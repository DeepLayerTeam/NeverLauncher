#!/usr/bin/env python3
"""Restore verified cold Minecraft world/user files, never live DBs.

Only works after operational_rollback_04912.py fence, with both game writer
services masked/inactive and HAProxy auth/game ingress closed. The replaced
folder is retained for manual recovery. Does not reconcile plugin databases.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile

import operational_rollback_04912 as rb
import production_cutover_04911 as co

FORMAT = "never/gravit-file-backup/v1"
MAX_ENTRIES = 150000
MAX_TOTAL_BYTES = 1 << 40


def ensure_dir(path: Path):
    co.require(path.is_absolute() and path.is_dir() and not path.is_symlink(), "real absolute directory required")


def entries(root: Path):
    """Enumerate without following links; no device files or hard-linked files."""
    ensure_dir(root)
    results = []
    total = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs:
            p = Path(base) / name
            co.require(stat.S_ISDIR(p.lstat().st_mode), "symlink or special directory in backup")
        for name in files:
            p = Path(base) / name
            st = p.lstat()
            co.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "backup contains linked/special file")
            co.require(st.st_size <= MAX_TOTAL_BYTES and total + st.st_size <= MAX_TOTAL_BYTES,
                       "file backup exceeds limit")
            total += st.st_size
            co.require(len(results) < MAX_ENTRIES, "file backup has too many files")
            rel = p.relative_to(root).as_posix()
            co.require(len(rel) < 1024 and all(x not in ("", ".", "..") for x in PurePosixPath(rel).parts),
                       "invalid backup file path")
            sha = hashlib.sha256()
            fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as source:
                co.require(os.fstat(source.fileno()).st_ino == st.st_ino, "backup file raced")
                while chunk := source.read(1 << 20):
                    sha.update(chunk)
                end = os.fstat(source.fileno())
                co.require(end.st_size == st.st_size and end.st_mtime_ns == st.st_mtime_ns,
                           "backup writer changed file during scan")
            results.append({"path":rel, "size":st.st_size, "sha256":sha.hexdigest()})
    return results


def write_manifest(root: Path, output: Path, run_id: str):
    co.require(bool(co.ROUTE.fullmatch(run_id)), "Требуется корректный идентификатор запуска")
    co.require(output.is_absolute() and not output.exists(), "new absolute manifest path required")
    manifest = {"format":FORMAT, "runId":run_id, "files":entries(root)}
    co.require(manifest["files"], "empty backup not accepted")
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as dest:
        dest.write(raw)
        dest.flush()
        os.fsync(dest.fileno())
    return manifest


def validate_manifest(manifest: dict, run_id: str):
    co.require(manifest.get("format") == FORMAT and manifest.get("runId") == run_id, "backup does not match run")
    files = manifest.get("files")
    co.require(isinstance(files, list) and 0 < len(files) <= MAX_ENTRIES, "invalid backup file count")
    names = []
    amount = 0
    for item in files:
        co.require(isinstance(item, dict) and set(item) == {"path", "size", "sha256"}, "invalid backup entry")
        name = item["path"]
        co.require(isinstance(name, str) and name != "" and len(name) < 1024 and
                   not name.startswith("/") and "\\" not in name and
                   all(part not in ("", ".", "..") for part in name.split("/")), "unsafe backup path")
        co.require(isinstance(item["size"], int) and not isinstance(item["size"], bool)
                   and 0 <= item["size"] <= MAX_TOTAL_BYTES and
                   isinstance(item["sha256"], str) and bool(co.HEX.fullmatch(item["sha256"])), "invalid backup digest")
        amount += item["size"]
        co.require(amount <= MAX_TOTAL_BYTES, "backup size limit exceeded")
        names.append(name)
    co.require(names == sorted(set(names)), "backup entries duplicate or out of order")
    return files


def safe_path(path: Path):
    co.require(path.is_absolute() and not path.is_symlink(), "real absolute target required")
    current = path.parent
    while current != current.parent:
        co.require(not current.is_symlink(), "symlink in restore parent path")
        current = current.parent


def get_state(cfgfile, rbfile, directory):
    cutraw = co.strict_file(cfgfile)
    cut = json.loads(cutraw)
    co.validate(cut, directory)
    cut["_hash"] = co.digest(cutraw)
    rraw = co.strict_file(rbfile)
    cfg = json.loads(rraw)
    rb.validate(cfg, cut)
    state = rb.state_load(directory, co.digest(rraw), cut["_hash"])
    co.require(state["phase"] in ("fenced", "planned", "committed_fenced"), "rollback not in a safe fenced phase")
    rb.assert_proxy(co.Proxy(cut["proxySocket"]), cut, state)
    rb.check_writers(cfg)
    return cfg, state


def restore(source: Path, target: Path, manifest: dict, directory: Path, run_id: str):
    files = validate_manifest(manifest, run_id)
    ensure_dir(source)
    safe_path(target)
    co.require(target.is_dir() and not target.is_symlink(), "existing restore target must be real directory")
    owner = target.stat()
    co.require(os.geteuid() == 0 or owner.st_uid == os.geteuid(),
               "operator must own target directory or run as root to preserve game-service ownership")
    co.require(source.resolve() != target.resolve() and not source.resolve().is_relative_to(target.resolve())
               and not target.resolve().is_relative_to(source.resolve()), "backup and destination overlap")
    old = target.with_name(target.name + ".before-" + run_id)
    co.require(not old.exists() and not old.is_symlink(), "retained old directory already exists")
    journal = directory / "file-restore-state.json"
    co.require(not journal.exists(), "Попытка восстановления файлов уже предпринималась; проверьте журнал")
    staged = Path(tempfile.mkdtemp(prefix=".never-restoring-", dir=target.parent))
    state = {"format":FORMAT,"runId":run_id,"phase":"staging","target":str(target),
             "retained":str(old),"stage":str(staged),"manifestSha256":co.digest(json.dumps(manifest,sort_keys=True).encode())}
    # Durable journal before any mutation of the destination.
    def record(phase):
        state["phase"] = phase
        raw = (json.dumps(state, sort_keys=True) + "\n").encode()
        tmp = journal.with_name(journal.name + ".next")
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, journal)
        dfd = os.open(directory, os.O_RDONLY | getattr(os,"O_DIRECTORY",0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
    record("staging")
    try:
        co.require(entries(source) == files, "original backup tree differs from sealed manifest")
        for item in files:
            rel = item["path"]
            original = source / rel
            dest = staged / rel
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            src_fd = os.open(original, os.O_RDONLY | getattr(os,"O_NOFOLLOW",0))
            sha = hashlib.sha256()
            with os.fdopen(src_fd,"rb") as f:
                st = os.fstat(f.fileno())
                co.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == item["size"],
                           "backup file changed or linked")
                out_fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os,"O_NOFOLLOW",0), 0o600)
                with os.fdopen(out_fd,"wb") as out:
                    while part := f.read(1<<20):
                        sha.update(part); out.write(part)
                    out.flush(); os.fsync(out.fileno())
                final = os.fstat(f.fileno())
                co.require(final.st_size == st.st_size and final.st_mtime_ns == st.st_mtime_ns,
                           "source backup file changed during restore")
            co.require(sha.hexdigest() == item["sha256"], "SHA-256 содержимого резервной копии не совпадает")
        co.require(entries(staged) == files, "staged restore differs from sealed manifest")
        # A root-operated restore must not leave the world unreadable by the
        # dedicated game service user. Preserve original target ownership and
        # use non-executable backup file modes; never copy setuid/sticky bits.
        directories = [staged]
        for base, dirs, names in os.walk(staged, followlinks=False):
            for d in dirs:
                directories.append(Path(base) / d)
            for name in names:
                p = Path(base) / name
                source_mode = (source / p.relative_to(staged)).lstat().st_mode & 0o666
                os.chown(p, owner.st_uid, owner.st_gid)
                os.chmod(p, source_mode | 0o600)
                fd = os.open(p, os.O_RDONLY | getattr(os,"O_NOFOLLOW",0))
                try: os.fsync(fd)
                finally: os.close(fd)
        for p in reversed(directories):
            os.chown(p, owner.st_uid, owner.st_gid)
            # The game account must traverse its own world directory.
            mode = (owner.st_mode & 0o777) | 0o700
            os.chmod(p, mode)
            fd = os.open(p, os.O_RDONLY | getattr(os,"O_DIRECTORY",0))
            try: os.fsync(fd)
            finally: os.close(fd)
        record("verified")
        os.replace(target, old)
        dfd = os.open(target.parent, os.O_RDONLY | getattr(os,"O_DIRECTORY",0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
        record("old_moved")
        os.replace(staged, target)
        dfd = os.open(target.parent, os.O_RDONLY | getattr(os,"O_DIRECTORY",0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
        record("installed")
        co.require(entries(target) == files, "После восстановления контрольная сумма данных не совпадает: оставьте входящий трафик закрытым")
        record("verified_installed")
    except BaseException:
        # A crash in the rename window is recoverable using the retained old folder.
        if not target.exists() and old.is_dir() and not old.is_symlink():
            os.replace(old, target)
            record("restored_previous_after_failure")
        raise


def recover(target: Path, manifest: dict, directory: Path, run_id: str):
    """Reconcile durable rename journal after kill/power loss; never overwrite data."""
    files = validate_manifest(manifest, run_id)
    journal = directory / "file-restore-state.json"
    state = co.document(journal, 16384)
    old = target.with_name(target.name + ".before-" + run_id)
    co.require(state.get("format") == FORMAT and state.get("runId") == run_id
               and state.get("target") == str(target) and state.get("retained") == str(old)
               and state.get("manifestSha256") == co.digest(json.dumps(manifest,sort_keys=True).encode()),
               "file restore journal mismatch")
    safe_path(target)
    safe_path(old)
    stage = Path(state.get("stage", ""))
    co.require(stage.is_absolute() and stage.parent == target.parent and
               stage.name.startswith(".never-restoring-"), "unsafe staged restore path")
    phase = state.get("phase")
    # A .next file left by a killed process is not authoritative; the old
    # atomically replaced journal is the last durable state. Reject links.
    nextfile = journal.with_name(journal.name + ".next")
    if nextfile.exists() or nextfile.is_symlink():
        st = nextfile.lstat()
        co.require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0,
                   "unsafe leftover journal file")
        nextfile.unlink()
    if target.is_dir() and old.is_dir():
        co.require(entries(target) == files, "Установленные файлы не соответствуют резервной копии; требуется ручное восстановление")
        state["phase"] = "verified_installed"
    elif not target.exists() and old.is_dir():
        os.replace(old, target)
        dfd = os.open(target.parent, os.O_RDONLY | getattr(os,"O_DIRECTORY",0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
        state["phase"] = "restored_previous_after_failure"
    elif target.is_dir() and not old.exists() and phase in ("staging", "verified"):
        state["phase"] = "aborted_before_install"
    elif phase in ("verified_installed", "restored_previous_after_failure", "aborted_before_install"):
        return state["phase"]
    else:
        raise co.Blocked("Журнал восстановления и целевое состояние не совпадают: требуется ручное восстановление")
    raw = (json.dumps(state,sort_keys=True) + "\n").encode()
    fd = os.open(nextfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os,"O_NOFOLLOW",0), 0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    os.replace(nextfile,journal)
    dfd = os.open(directory, os.O_RDONLY | getattr(os,"O_DIRECTORY",0))
    try: os.fsync(dfd)
    finally: os.close(dfd)
    return state["phase"]


def main(argv=None):
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("seal", "restore", "recover"))
    p.add_argument("--source", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--target")
    p.add_argument("--cutover-config")
    p.add_argument("--rollback-config")
    p.add_argument("--journal-dir")
    args = p.parse_args(argv)
    try:
        source, mf = Path(args.source), Path(args.manifest)
        if args.command == "seal":
            write_manifest(source, mf, args.run)
        else:
            co.require(args.target and args.cutover_config and args.rollback_config and args.journal_dir,
                       "restore requires target and both cutover/rollback configs and journal")
            directory = Path(args.journal_dir)
            co.require(directory.is_dir() and not directory.is_symlink() and directory.stat().st_mode & 0o077 == 0,
                       "private journal directory required")
            fd = os.open(directory / ".cutover.lock", os.O_CREAT | os.O_RDWR | getattr(os,"O_NOFOLLOW",0), 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                cfg, state = get_state(Path(args.cutover_config), Path(args.rollback_config), directory)
                co.require(cfg["runId"] == args.run, "restore run mismatch")
                if args.command == "restore":
                    restore(source, Path(args.target), co.document(mf, 16 << 20), directory, args.run)
                else:
                    print("Восстановление после сбоя: " + recover(Path(args.target), co.document(mf, 16 << 20), directory, args.run))
            finally:
                os.close(fd)
        return 0
    except (co.Blocked, OSError, ValueError, KeyError, TypeError) as exc:
        print("BLOCKED: " + str(exc),file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
