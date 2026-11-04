#!/usr/bin/env python3
"""Explicit OFFLINE FileAuthSystem Database.json maintenance.

Requires Gravit/other writers STOPPED. NeverLauncher live federation remains
read-only; this utility edits the authoritative file with an operator-pinned
SHA256, an exclusive local lock and a durable preimage backup. Sessions.json,
roles, keys and imported session credentials are never touched. Linux/POSIX.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

MAX_BYTES = 16 << 20
UUID = re.compile(r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
USERNAME = re.compile(r"^[A-Za-z0-9_]{3,16}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")


class WritebackError(Exception):
    pass


def no_duplicate_pairs(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise WritebackError("duplicate JSON key")
        obj[k] = v
    return obj


def read_regular(path, max_bytes=MAX_BYTES, private=True):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or (private and meta.st_mode & 0o077):
        raise WritebackError("source must be a private regular file without symlinks")
    if meta.st_size > max_bytes:
        raise WritebackError("file exceeds size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (meta.st_dev, meta.st_ino):
            raise WritebackError("source changed during open")
        with os.fdopen(fd, "rb", closefd=False) as reader:
            data = reader.read(max_bytes + 1)
        after = path.lstat()
        if len(data) > max_bytes or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise WritebackError("source changed during read")
        return data
    finally:
        os.close(fd)


def parse_database(data):
    try:
        root = json.loads(data, object_pairs_hook=no_duplicate_pairs)
    except (UnicodeError, ValueError) as e:
        raise WritebackError("invalid FileAuth JSON") from e
    if not isinstance(root, dict) or len(root) > 20000 or not root:
        raise WritebackError("FileAuth UUID database is empty or too large")
    usernames = set()
    for uuid, entry in root.items():
        if not isinstance(uuid, str) or not UUID.fullmatch(uuid) or not isinstance(entry, dict):
            raise WritebackError("invalid FileAuth identity")
        username = entry.get("username")
        if not isinstance(username, str) or not USERNAME.fullmatch(username) or username.lower() in usernames:
            raise WritebackError("invalid or duplicate username")
        usernames.add(username.lower())
        if not isinstance(entry.get("uuid", uuid), str) or entry.get("uuid", uuid).lower() != uuid or not isinstance(entry.get("password"), str):
            raise WritebackError("invalid FileAuth UUID/password mapping")
    return root


def change(data, *, operation, user_uuid, username="", secret=b"", allow_legacy=False, password_format=""):
    accounts = parse_database(data)
    if user_uuid not in accounts:
        raise WritebackError("UUID not found: no implicit user creation")
    account = accounts[user_uuid]
    if operation == "rename":
        if not USERNAME.fullmatch(username):
            raise WritebackError("invalid new Minecraft username")
        if any(a["username"].lower() == username.lower() for k, a in accounts.items() if k != user_uuid):
            raise WritebackError("username already exists")
        account["username"] = username
    elif operation == "disable":
        del accounts[user_uuid]
        if not accounts:
            raise WritebackError("refusing to remove last account")
    elif operation == "set-password":
        # Строгий явно включённый устаревший хеш только для совместимости во избежание незаметного изменения формата,
        # которое могло бы заблокировать всех пользователей вышестоящего сервера Gravit.
        if not allow_legacy or password_format != "sha256-hex":
            raise WritebackError("SHA-256 legacy write requires --password-format sha256-hex and --allow-weak-legacy-hash")
        if not 1 <= len(secret) <= 4096 or not DIGEST.fullmatch(account["password"].lower()):
            raise WritebackError("source is not SHA256-hex or password is invalid")
        account["password"] = hashlib.sha256(secret).hexdigest()
    else:
        raise WritebackError("unsupported offline FileAuth operation")
    encoded = (json.dumps(accounts, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_BYTES:
        raise WritebackError("updated FileAuth database exceeds limit")
    if accounts:
        parse_database(encoded)
    return encoded


def fsync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def writeback(*, source, backup, expected_sha256, operation, user_uuid,
              username="", password_file=None, stopped_writers=False, allow_legacy=False, password_format=""):
    source, backup = Path(source), Path(backup)
    if not stopped_writers:
        raise WritebackError("stop Gravit and other writers, then specify --writers-stopped")
    if source.name != "Database.json" or not source.is_absolute():
        raise WritebackError("source must be an absolute Database.json path")
    if not DIGEST.fullmatch(expected_sha256):
        raise WritebackError("expected source SHA-256 is mandatory")
    if backup.parent.resolve() != source.parent.resolve() or backup == source or backup.exists() or backup.is_symlink():
        raise WritebackError("backup must be a new file in Database.json directory")
    if not UUID.fullmatch(user_uuid):
        raise WritebackError("invalid UUID")
    secret = b""
    if operation == "set-password":
        if password_file is None:
            raise WritebackError("private password file is required")
        secret = read_regular(Path(password_file), max_bytes=4096)
    elif password_file is not None:
        raise WritebackError("password file not accepted for this operation")
    # flock сериализует согласованные вызовы обслуживания. Внешние процессы Gravit
    # процессы не соблюдают эту блокировку, поэтому требуется явное предусловие оператора.
    lock_path = source.with_name(".FileAuthSystem.writeback.lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(lock_fd, "a+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode) or os.fstat(lock.fileno()).st_nlink != 1:
            raise WritebackError("unsafe lock file")
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        before = read_regular(source)
        digest = hashlib.sha256(before).hexdigest()
        if digest != expected_sha256:
            raise WritebackError("source SHA-256 changed since approval")
        after = change(before, operation=operation, user_uuid=user_uuid, username=username,
                       secret=secret, allow_legacy=allow_legacy, password_format=password_format)
        if before == after:
            raise WritebackError("no content change")
        name = None
        try:
            fd, name = tempfile.mkstemp(dir=source.parent, prefix=".fileauth-")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as dest:
                dest.write(after)
                dest.flush()
                os.fsync(dest.fileno())
            if hashlib.sha256(read_regular(source)).hexdigest() != digest:
                raise WritebackError("source changed before commit")
            # Жёсткая ссылка на исходные байты остаётся целой после атомарной замены и
            # создаётся без перезаписи существующей резервной копии другого оператора.
            os.link(source, backup, follow_symlinks=False)
            fsync_directory(source.parent)
            os.replace(name, source)
            name = None
            fsync_directory(source.parent)
        finally:
            if name:
                os.unlink(name)
        new_digest = hashlib.sha256(read_regular(source)).hexdigest()
        if new_digest != hashlib.sha256(after).hexdigest():
            raise WritebackError("writeback postcondition mismatch; recover from backup")
        return {"operation": operation, "userUuid": user_uuid, "sourceSha256": digest,
                "updatedSha256": new_digest, "backup": str(backup)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--uuid", required=True)
    parser.add_argument("--operation", choices=["rename", "disable", "set-password"], required=True)
    parser.add_argument("--username", default="")
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--writers-stopped", action="store_true")
    parser.add_argument("--allow-weak-legacy-hash", action="store_true")
    parser.add_argument("--password-format", choices=["sha256-hex"], default="")
    args = parser.parse_args()
    try:
        receipt = writeback(source=args.source, backup=args.backup, expected_sha256=args.expected_sha256,
                            operation=args.operation, user_uuid=args.uuid, username=args.username,
                            password_file=args.password_file, stopped_writers=args.writers_stopped,
                            allow_legacy=args.allow_weak_legacy_hash, password_format=args.password_format)
    except (WritebackError, OSError) as exc:
        parser.exit(2, f"FileAuth writeback rejected: {exc}\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
