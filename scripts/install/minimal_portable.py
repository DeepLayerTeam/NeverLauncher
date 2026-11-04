#!/usr/bin/env python3
"""Authenticated, streaming transfer for the existing offline minimal backup.

An encrypted archive is portable across Linux hosts. AES-256-GCM authenticates
all archive bytes; scrypt derives the key from an independently transported
passphrase file. Never publish a decrypted or partially restored installation.
Requires Python cryptography >= 41 on both hosts.
"""

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import tarfile
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import minimal_backup as core

MAGIC = b"NEVER-MINIMAL-PORTABLE-1\n"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE
BLOCK = 1024 * 1024
MAX_ENTRIES = 200_000


def passphrase(path):
    p = core.safe_absolute(path)
    st = core.check_path(p)
    core.require(st.st_mode & 0o077 == 0, "passphrase file must be mode 0600")
    core.require(st.st_size <= 4096, "passphrase file too large")
    with p.open("rb") as handle:
        secret = handle.read(4097)
    # Удалите ровно один обычный завершающий перевод строки; секреты CLI и окружения не раскрываются.
    if secret.endswith(b"\r\n"):
        secret = secret[:-2]
    elif secret.endswith(b"\n"):
        secret = secret[:-1]
    core.require(24 <= len(secret) <= 4096, "passphrase must contain >=24 bytes")
    return secret


def derive(secret, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(secret)


class EncryptedWriter:
    def __init__(self, stream, cipher):
        self.stream = stream
        self.cipher = cipher

    def write(self, data):
        self.stream.write(self.cipher.update(data))
        return len(data)

    def flush(self):
        self.stream.flush()


@contextmanager
def private_temp(parent, prefix):
    core.private_directory(parent)
    tmp = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    os.chmod(tmp, 0o700)
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp)


def _members(bundle, manifest):
    yield bundle, "snapshot"
    yield bundle / "manifest.json", "snapshot/manifest.json"
    yield bundle / "payload", "snapshot/payload"
    for relative in manifest["directories"]:
        if relative != ".":
            yield bundle / "payload" / relative, "snapshot/payload/" + relative
    for record in manifest["files"]:
        yield bundle / "payload" / record["path"], "snapshot/payload/" + record["path"]


def export(bundle, output, secret_file):
    source = core.safe_absolute(bundle)
    core.require(not core.safe_absolute(secret_file).is_relative_to(source),
                 "passphrase must not be stored in the exported snapshot")
    manifest = core.verify(source)
    secret = passphrase(secret_file)
    output = core.safe_absolute(output)
    core.private_directory(output.parent)
    core.require(not output.exists() and not output.is_symlink(), "portable output exists")
    core.require(not output.is_relative_to(source), "output must be outside snapshot")
    salt, nonce = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(NONCE_SIZE)
    header = MAGIC + salt + nonce
    encryptor = Cipher(algorithms.AES(derive(secret, salt)), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)
    fd, staging = tempfile.mkstemp(prefix=".portable-incomplete-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(header)
            with tarfile.open(fileobj=EncryptedWriter(stream, encryptor), mode="w|") as archive:
                for path, name in _members(source, manifest):
                    info = archive.gettarinfo(str(path), arcname=name)
                    core.require(info.isdir() or info.isfile(), "non-file in snapshot")
                    core.check_path(path, directory=info.isdir())
                    # Не допускайте утечки имён владельцев и временных меток при расшифровке архивов.
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    if info.isfile():
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
                    else:
                        archive.addfile(info)
            stream.write(encryptor.finalize())
            stream.write(encryptor.tag)
            stream.flush()
            os.fsync(stream.fileno())
        # Создание ссылки атомарно и с NOREPLACE, включая гонку злоумышленника за имя.
        os.link(staging, output, follow_symlinks=False)
        core.fsync_dir(output.parent)
        return output
    finally:
        Path(staging).unlink(missing_ok=True)


def _decrypt_to(archive_path, target, secret):
    source = core.safe_absolute(archive_path)
    st = core.check_path(source, owner=False)
    core.require(st.st_size > HEADER_SIZE + TAG_SIZE, "truncated portable archive")
    with source.open("rb") as stream:
        header = stream.read(HEADER_SIZE)
        core.require(header.startswith(MAGIC), "unsupported portable format")
        salt = header[len(MAGIC):len(MAGIC) + SALT_SIZE]
        nonce = header[-NONCE_SIZE:]
        stream.seek(st.st_size - TAG_SIZE)
        tag = stream.read(TAG_SIZE)
        stream.seek(HEADER_SIZE)
        decryptor = Cipher(algorithms.AES(derive(secret, salt)), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        remaining = st.st_size - HEADER_SIZE - TAG_SIZE
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as plaintext:
            while remaining:
                data = stream.read(min(BLOCK, remaining))
                core.require(bool(data), "truncated portable archive")
                remaining -= len(data)
                plaintext.write(decryptor.update(data))
            try:
                plaintext.write(decryptor.finalize())
            except InvalidTag as exc:
                raise core.BackupError("portable archive authentication failed") from exc
            plaintext.flush()
            os.fsync(plaintext.fileno())
        core.require(source.stat().st_size == st.st_size, "portable file changed during read")


def _extract_authenticated(tar_path, destination):
    """Never call tarfile.extractall on attacker-controlled content."""
    seen = set()
    with tarfile.open(tar_path, mode="r:") as archive:
        for member in archive:
            core.require(len(seen) < MAX_ENTRIES, "too many archive entries")
            rel = core.validate_relative(member.name)
            parts = rel.parts
            core.require(parts[0] == "snapshot", "unexpected archive root")
            core.require(member.isdir() or member.isfile(), "unsafe archive entry type")
            core.require(member.name not in seen, "duplicate archive member")
            seen.add(member.name)
            core.require(
                member.name in ("snapshot", "snapshot/manifest.json", "snapshot/payload")
                or (len(parts) >= 3 and parts[1] == "payload"),
                "unexpected archive member",
            )
            target = destination / member.name
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(target, 0o700)
            else:
                core.require(member.size >= 0 and member.size <= tar_path.stat().st_size,
                             "invalid archive member size")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        reader = archive.extractfile(member)
                        core.require(reader is not None, "missing archive member data")
                        remaining = member.size
                        while remaining:
                            part = reader.read(min(BLOCK, remaining))
                            core.require(bool(part), "truncated archive member")
                            stream.write(part)
                            remaining -= len(part)
                        stream.flush()
                        os.fsync(stream.fileno())
                except BaseException:
                    target.unlink(missing_ok=True)
                    raise
    core.require("snapshot/manifest.json" in seen, "missing archive manifest")
    return destination / "snapshot"


def import_and_verify(input_file, secret_file, *, target_root=None):
    secret = passphrase(secret_file)
    source = core.safe_absolute(input_file)
    core.require(source.exists(), "portable archive missing")
    if target_root is not None:
        target = core.safe_absolute(target_root)
        core.require(not target.exists() and not target.is_symlink(), "restore destination exists")
        parent = target.parent
    else:
        parent = source.parent
    with private_temp(parent, ".minimal-portable-verify-") as stage:
        plain = stage / "authenticated.tar"
        _decrypt_to(source, plain, secret)
        bundle = _extract_authenticated(plain, stage)
        manifest = core.verify(bundle)
        if target_root is None:
            return {"files": len(manifest["files"]), "status": "verified"}
        result = core.restore(bundle, target)
        return {"root": str(result), "files": len(manifest["files"]), "status": "restored"}


def backup_portable(root, output, secret_file):
    root = core.safe_absolute(root)
    core.read_install(root)
    core.require(not core.safe_absolute(secret_file).is_relative_to(root),
                 "recovery passphrase must be kept outside backed-up installation")
    passphrase(secret_file)  # preflight before making any plaintext snapshot
    output = core.safe_absolute(output)
    core.private_directory(output.parent)
    core.require(not output.exists() and not output.is_symlink(),
                 "portable output exists")
    core.require(not output.is_relative_to(root) or output.parent == root / "backups",
                 "portable output inside live root must be in backups/")
    # Снимок остаётся закрытым; отключение питания может оставить временную копию в
    # backups/. Она не считается полной до независимой проверки пакета.
    destination = root / "backups" / (".minimal-portable-source-" + secrets.token_hex(12))
    try:
        core.backup(root, destination)
        return export(destination, output, secret_file)
    finally:
        if destination.exists():
            shutil.rmtree(destination)


def main(argv=None):
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for operation in ("backup-portable", "export-portable", "verify-portable", "restore-portable"):
        cmd = sub.add_parser(operation)
        cmd.add_argument("--passphrase-file", required=True, type=Path)
        if operation == "backup-portable":
            cmd.add_argument("--root", required=True, type=Path)
            cmd.add_argument("--output", required=True, type=Path)
        elif operation == "export-portable":
            cmd.add_argument("--bundle", required=True, type=Path)
            cmd.add_argument("--output", required=True, type=Path)
        else:
            cmd.add_argument("--input", required=True, type=Path)
            if operation == "restore-portable":
                cmd.add_argument("--target-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "backup-portable":
            result = {"output": str(backup_portable(args.root, args.output, args.passphrase_file))}
        elif args.command == "export-portable":
            result = {"output": str(export(args.bundle, args.output, args.passphrase_file))}
        else:
            result = import_and_verify(args.input, args.passphrase_file,
                                       target_root=args.target_root if args.command == "restore-portable" else None)
        print(json.dumps({"operation": args.command, **result, "status": "ok"}))
        return 0
    except (core.BackupError, OSError, tarfile.TarError, ValueError) as exc:
        print(f"minimal portable backup failed closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
