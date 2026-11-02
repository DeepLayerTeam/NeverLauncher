#!/usr/bin/env python3
"""NeverLauncher 0.47.5: fail-closed, resumable offline SQLite Core migration.

This does not translate the independent SQLite HTTP/Coordinator state. Such an
installation is explicitly ineligible for Backend cutover until that conversion
is implemented and tested. Never infer PostgreSQL readiness from a staging row.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

STAGES = ("preflight", "backup", "freeze", "frozen_backup", "import", "copy_files", "verify", "cutover", "health_check")
MAX_OUTPUT = 256 * 1024


class CutoverError(RuntimeError):
    pass


def record(stage: str, status: str, **fields):
    return dict(at=datetime.now(timezone.utc).isoformat(), stage=stage, status=status, **fields)


def refuse_symlink(path: Path):
    if path.is_symlink():
        raise CutoverError(f"symlink not allowed: {path}")


def private_file(path: Path):
    refuse_symlink(path)
    try:
        st = path.stat()
    except FileNotFoundError as exc:
        raise CutoverError(f"required private file missing: {path}") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise CutoverError(f"private regular file (0600) required: {path}")
    return st


def fsync_dir(directory: Path):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_secure(path: Path, payload: bytes):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    refuse_symlink(path)
    fd, temp = tempfile.mkstemp(prefix=".cutover-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def enough_space(path: Path, required_bytes: int, reason: str):
    """Fail before destructive work, reserving 20% + 64 MiB for WAL/metadata.

    A full filesystem can cause an SQLite online backup or filesystem copy to
    fail half-way through. This is a *preflight*, not a substitute for checking
    and fsyncing the actual result. Check the filesystem containing the target.
    """
    if required_bytes < 0:
        raise CutoverError("invalid storage size estimate")
    where = path
    while not where.exists():
        where = where.parent
    stats = os.statvfs(where)
    available = stats.f_bavail * stats.f_frsize
    reserve = max(64 * 1024 * 1024, (required_bytes + 4) // 5)
    if available < required_bytes + reserve:
        raise CutoverError(f"insufficient disk space for {reason}: need {required_bytes + reserve} bytes, have {available}")


def sqlite_size_on_disk(path: Path) -> int:
    private_file(path)
    total = path.stat().st_size
    for suffix in ("-wal", "-shm"):
        sibling = Path(str(path) + suffix)
        if sibling.exists():
            refuse_symlink(sibling)
            st = sibling.stat()
            if not stat.S_ISREG(st.st_mode):
                raise CutoverError("unsafe SQLite sidecar")
            total += st.st_size
    return total


def storage_fingerprint(root: Path) -> tuple[str, int, int]:
    """Hash every local blob and its relative name; reject symlink/device input.

    Called before and after copying, including during resume. Merely comparing
    file counts does not detect same-size/same-count source mutations.
    """
    refuse_symlink(root)
    if not root.is_dir():
        raise CutoverError("source local storage root must exist")
    digest = hashlib.sha256()
    count = total = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs):
            part = Path(folder) / name
            mode = part.lstat().st_mode
            if not stat.S_ISDIR(mode):
                raise CutoverError("non-directory or symlink inside source storage")
        dirs.sort()
        for name in sorted(files):
            part = Path(folder) / name
            before = part.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise CutoverError("unsafe source storage blob (link or special file)")
            relative = part.relative_to(root).as_posix().encode("utf-8")
            fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (before.st_ino, before.st_dev) != (opened.st_ino, opened.st_dev):
                    raise CutoverError("source storage path replaced before reading")
                content_sha = hashlib.sha256()
                for buf in iter(lambda: stream.read(1024 * 1024), b""):
                    content_sha.update(buf)
                after_open = os.fstat(stream.fileno())
            after = part.lstat()
            if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns) or (opened.st_size, opened.st_mtime_ns) != (after_open.st_size, after_open.st_mtime_ns):
                raise CutoverError("source file changed during fingerprint")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(before.st_size.to_bytes(8, "big"))
            digest.update(content_sha.digest())
            total += before.st_size
            count += 1
    return digest.hexdigest(), count, total


def check_stage_chain(state: dict):
    """Only a prefix of durable stage receipts may be replayed after a crash."""
    completed = state.get("completed")
    if not isinstance(completed, list) or completed != list(STAGES[:len(completed)]):
        raise CutoverError("corrupt or out-of-order migration stage journal")
    receipts = state.get("receipts", {})
    if not isinstance(receipts, dict):
        raise CutoverError("corrupt migration receipts")
    if any(stage not in completed for stage in receipts):
        raise CutoverError("receipt for uncommitted migration stage")
    if state.get("importOutcomeUnknown") and "import" in completed:
        raise CutoverError("contradictory import completion receipt")
    if state.get("writeBoundaryCrossed") and "verify" not in completed:
        raise CutoverError("unsafe write-boundary journal without verification; automatic rollback forbidden")
    if "cutover" in completed and not state.get("writeBoundaryCrossed"):
        raise CutoverError("cutover recorded without write boundary; automatic rollback forbidden")


def sha256_file(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for buf in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(buf)
    return h.hexdigest()


def run_cmd(args, *, env=None):
    try:
        p = subprocess.run(args, env=env, capture_output=True, timeout=3600, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CutoverError(f"subprocess failed: {args[0]}: {type(exc).__name__}") from exc
    if p.returncode:
        # stderr may contain command flags, paths and secrets. No unsafe echo.
        raise CutoverError(f"{Path(args[0]).name} {args[1] if len(args)>1 else ''} failed (exit {p.returncode}); see private operator service logs")
    if len(p.stdout) > MAX_OUTPUT:
        raise CutoverError("unreasonable CLI response size")
    try:
        return json.loads(p.stdout)
    except (ValueError, UnicodeError) as exc:
        raise CutoverError(f"invalid JSON response from {args[0]}") from exc


def parse_env(path: Path):
    """Small strict systemd EnvironmentFile subset, not shell interpolation."""
    private_file(path)
    items = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=.*", line):
            raise CutoverError("unsupported env syntax; refusing to rewrite service configuration")
        if line.startswith("export "):
            raise CutoverError("systemd EnvironmentFile cannot contain export")
        key, value = line.split("=", 1)
        if key in items:
            raise CutoverError(f"duplicate environment key {key}")
        if "\x00" in value or "\r" in value:
            raise CutoverError("unsafe environment value")
        items[key] = value
    return items


def change_env(path: Path, target_dsn: str, driver: str, storage_path: str):
    """Preserves comments and existing unrelated settings; no shell execution."""
    private_file(path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    changes = {
        "LAUNCHER_DATABASE_DSN": target_dsn,
        "LAUNCHER_REPOSITORY_DRIVER": driver,
        "LAUNCHER_SQL_DRIVER": "pgx",
        "LAUNCHER_DATABASE_AUTO_MIGRATE": "false",
        "LAUNCHER_STORAGE_DRIVER": "local",
        "LAUNCHER_STORAGE_LOCAL_PATH": storage_path,
    }
    if any(c in target_dsn + storage_path for c in ("\n", "\r", "\x00", "\"")):
        raise CutoverError("unsafe configuration characters")
    seen = set()
    new = []
    for line in lines:
        if line.lstrip().startswith("#") or "=" not in line:
            new.append(line)
            continue
        name, _ = line.split("=", 1)
        if name in changes:
            if name in seen:
                raise CutoverError("duplicate environment key")
            new.append(f"{name}={changes[name]}\n")
            seen.add(name)
        else:
            new.append(line)
    for name, value in changes.items():
        if name not in seen:
            new.append(f"{name}={value}\n")
    write_secure(path, "".join(new).encode("utf-8"))


def validate_sqlite_backup(path: Path):
    if not path.is_file():
        raise CutoverError("SQLite backup missing")
    private_file(path)
    uri = path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as db:
        check = db.execute("PRAGMA integrity_check").fetchall()
        if check != [("ok",)]:
            raise CutoverError("SQLite backup integrity_check failed")
        fk = db.execute("PRAGMA foreign_key_check").fetchone()
        if fk:
            raise CutoverError("SQLite backup foreign-key violation")


def verify_http_snapshot(path: Path):
    """Validate the committed HTTP snapshot, not just SQLite page integrity."""
    private_file(path)
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        exists = db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='http_repository_state_0372'").fetchone()[0]
        if exists != 1:
            raise CutoverError("HTTP Repository snapshot table missing")
        rows = db.execute("SELECT singleton,state_version,sequence,sha256,document FROM http_repository_state_0372").fetchall()
        if len(rows) != 1:
            raise CutoverError("HTTP Repository snapshot singleton invalid")
        singleton, version, sequence, digest, document = rows[0]
        if singleton != 1 or version != 1 or sequence < 1 or not isinstance(document, bytes):
            raise CutoverError("HTTP Repository snapshot metadata invalid")
        if hashlib.sha256(document).hexdigest() != digest:
            raise CutoverError("HTTP Repository snapshot SHA-256 mismatch")
        def reject_duplicate(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise CutoverError("duplicate HTTP snapshot JSON key")
                out[key] = value
            return out
        try:
            data = json.loads(document, object_pairs_hook=reject_duplicate)
        except (UnicodeError, ValueError) as exc:
            raise CutoverError("corrupt HTTP Repository JSON") from exc
        if not isinstance(data, dict) or not data:
            raise CutoverError("invalid HTTP Repository JSON state")


def sqlite_backup(source_name: str, dest: Path):
    source = Path(source_name)
    private_file(source)
    if dest.exists():
        raise CutoverError("refusing to overwrite independent SQLite backup")
    uri = source.resolve().as_uri() + "?mode=ro"
    # SQLite online backup API captures a single transactionally consistent
    # database, including committed WAL pages. Never copy just its .db file.
    with closing(sqlite3.connect(uri, uri=True, timeout=20)) as src:
        if src.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise CutoverError("source SQLite integrity check failed")
        fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(str(dest))) as target:
                src.backup(target)
            validate_sqlite_backup(dest)
            with dest.open("rb") as stream:
                os.fsync(stream.fileno())
            fsync_dir(dest.parent)
        except Exception:
            dest.unlink(missing_ok=True)
            raise


class Operator:
    def __init__(self, args):
        self.a = args
        # Do not resolve away a symlink before refuse_symlink checks it.
        self.work = Path(os.path.abspath(args.work_dir))
        self.state_path = self.work / "state.json"
        self.journal_path = self.work / "stages.jsonl"
        self.backup = self.work / "core-frozen.db"
        self.early_backup = self.work / "core-preflight.db"
        self.original_env = self.work / "backend-before.env"
        self.http_backup = self.work / "http-frozen.db"
        self.coordinator_backup = self.work / "coordinator-frozen.db"
        self.env = os.environ.copy()
        self.env[args.dsn_env] = os.environ.get(args.dsn_env, "")
        self.state = {"format": "neverlauncher-cutover-0475-v1", "completed": [], "blocked": False, "writeBoundaryCrossed": False}

    def init_workdir(self):
        refuse_symlink(self.work)
        if not self.work.exists():
            self.work.mkdir(mode=0o700, parents=True)
        if self.work.stat().st_mode & 0o077:
            raise CutoverError("work directory must be private (0700)")
        if self.state_path.exists():
            private_file(self.state_path)
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise CutoverError("invalid persisted cutover journal")
            if data.get("format") != self.state["format"]:
                raise CutoverError("unknown journal format")
            check_stage_chain(data)
            self.state = data
        else:
            write_secure(self.state_path, json.dumps(self.state, sort_keys=True).encode())

    def log(self, stage, status, **fields):
        # Never log DSN, env file contents, encryption keys or user credentials.
        value = json.dumps(record(stage, status, **fields), separators=(",", ":")) + "\n"
        with self.journal_path.open("ab") as stream:
            os.chmod(self.journal_path, 0o600)
            stream.write(value.encode())
            stream.flush()
            os.fsync(stream.fileno())

    def save(self):
        write_secure(self.state_path, json.dumps(self.state, indent=2, sort_keys=True).encode())

    def stage(self, name, fn):
        check_stage_chain(self.state)
        if name in self.state["completed"]:
            return
        if name != STAGES[len(self.state["completed"])]:
            raise CutoverError("migration stages must run in order")
        self.log(name, "started")
        try:
            result = fn() or {}
        except Exception as exc:
            self.state["blocked"] = True
            self.state["failedStage"] = name
            self.save()
            self.log(name, "failed", reason=type(exc).__name__)
            raise
        self.state["completed"].append(name)
        if name == "import":
            # Only clear ambiguity after the completed stage is durably
            # journaled. A kill immediately after PostgreSQL COMMIT is unsafe
            # to retry without inspecting the existing receipt.
            self.state["importOutcomeUnknown"] = False
        self.state["blocked"] = False
        self.state.pop("failedStage", None)
        if result:
            self.state.setdefault("receipts", {})[name] = result
        self.save()
        self.log(name, "completed")

    def service(self, cmd, unit):
        # Unit names never flow through a shell; no remote systemd support.
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", unit):
            raise CutoverError("invalid systemd service unit")
        p = subprocess.run(["systemctl", cmd, unit], capture_output=True, timeout=90, check=False)
        return p.returncode, p.stdout.strip()

    def inactive(self):
        for unit in self.a.units:
            code, state = self.service("is-active", unit)
            if code == 0 or state not in (b"inactive", b"failed"):
                raise CutoverError(f"writer unit not reliably stopped: {unit}")

    def preflight(self):
        if not self.a.units or len(set(self.a.units)) != len(self.a.units):
            raise CutoverError("at least one explicit systemd service and no duplicate units required")
        if not self.env[self.a.dsn_env]:
            raise CutoverError("target PostgreSQL DSN must be supplied via an environment variable")
        private_file(Path(self.a.source_env))
        cfg = parse_env(Path(self.a.source_env))
        if cfg.get("LAUNCHER_REPOSITORY_DRIVER", "").lower() != "sqlite":
            raise CutoverError("source backend must use SQLite; never alter an existing PostgreSQL deployment")
        if cfg.get("LAUNCHER_DATABASE_DSN", "") != self.a.http_db:
            raise CutoverError("--http-db must exactly match current SQLite Backend DSN")
        for source in (self.a.core_db, self.a.http_db):
            private_file(Path(source))
        # Independent preflight + frozen copies of Core, one frozen HTTP and
        # one optional Coordinator copy; include WAL and guard headroom.
        required = 2 * sqlite_size_on_disk(Path(self.a.core_db)) + sqlite_size_on_disk(Path(self.a.http_db))
        if self.a.coordinator_db:
            required += sqlite_size_on_disk(Path(self.a.coordinator_db))
        enough_space(self.work, required, "SQLite backups")
        if self.a.coordinator_db:
            private_file(Path(self.a.coordinator_db))
        if cfg.get("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", "") and cfg["LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH"] != self.a.coordinator_db:
            raise CutoverError("Coordinator path must be explicitly supplied and match the source configuration")
        sources = [self.a.core_db, self.a.http_db]
        if self.a.coordinator_db:
            sources.append(self.a.coordinator_db)
        if len({Path(v).resolve() for v in sources}) != len(sources):
            raise CutoverError("SQLite Core, HTTP and Coordinator must be separate databases")
        # THIS IS A HARD INCOMPATIBILITY in 0.47.4. It must not be bypassed
        # even when an HTTP snapshot appears empty: private auth, coordinator,
        # signing, install and runtime metadata have no canonical PG mapping.
        self.state["cutoverSupported"] = False
        self.save()
        return {"corePresent": True, "httpMigrationSupported": False}

    def do_backup(self):
        private_file(Path(self.a.source_env))
        if self.original_env.exists():
            private_file(self.original_env)
            if sha256_file(self.original_env) != sha256_file(Path(self.a.source_env)):
                raise CutoverError("previous original environment backup differs")
        else:
            write_secure(self.original_env, Path(self.a.source_env).read_bytes())
        self.state["sourceEnvSHA256"] = sha256_file(Path(self.a.source_env))
        self.save()
        result = run_cmd([self.a.launcher_sqlite, "pre-upgrade", "--db", self.a.core_db, "--backup", str(self.early_backup)], env=self.env)
        if not result.get("verifiedRestore"):
            raise CutoverError("preflight backup restore was not independently verified")
        return {"backupSha256": result["manifest"]["sha256"]}

    def freeze(self):
        for unit in self.a.units:
            code, _ = self.service("stop", unit)
            if code:
                raise CutoverError(f"cannot stop writer service {unit}")
        self.inactive()
        return {"stoppedServices": len(self.a.units)}

    def frozen_backup(self):
        self.inactive()
        if self.backup.exists() or self.http_backup.exists() or self.coordinator_backup.exists():
            # An interrupted physical backup must never be reused as complete.
            # Preserve evidence; require manual resolution rather than overwrite.
            raise CutoverError("incomplete frozen backup files exist; inspect before retry")
        if sha256_file(Path(self.a.source_env)) != self.state.get("sourceEnvSHA256"):
            raise CutoverError("service configuration changed since preflight")
        # HTTP and Coordinator are not silently dropped. Back up and verify
        # their complete SQLite state even though there is no live PG mapping.
        sqlite_backup(self.a.http_db, self.http_backup)
        verify_http_snapshot(self.http_backup)
        if self.a.coordinator_db:
            sqlite_backup(self.a.coordinator_db, self.coordinator_backup)
        result = run_cmd([self.a.launcher_sqlite, "pre-upgrade", "--db", self.a.core_db, "--backup", str(self.backup)], env=self.env)
        if not result.get("verifiedRestore"):
            raise CutoverError("frozen backup failed independent restore")
        self.state["sourceSHA256"] = result["manifest"]["sha256"]
        self.save()
        return {"backupSha256": self.state["sourceSHA256"], "httpBackupSHA256": sha256_file(self.http_backup), "coordinatorBackupSHA256": sha256_file(self.coordinator_backup) if self.a.coordinator_db else None}

    def importing(self):
        self.inactive()
        if sha256_file(Path(self.a.source_env)) != self.state.get("sourceEnvSHA256"):
            raise CutoverError("source configuration changed while frozen")
        # IMPORTANT: if a process died after commit but before this stage was
        # journaled, the commit outcome is unknown. Never blindly retry.
        self.state["importOutcomeUnknown"] = True
        self.save()
        report = run_cmd([self.a.launcher_sqlite, "sqlite-to-postgres-live", "--backup", str(self.backup), "--ack-live-import", "--timeout", "45m", *self.mfa_args()], env=self.env)
        if not report.get("verified") or report.get("sourceSha256") != self.state["sourceSHA256"]:
            raise CutoverError("live import receipt invalid")
        return {"sourceSHA256": self.state["sourceSHA256"], "verified": True}

    def mfa_args(self):
        if self.a.mfa_key_file and self.a.pg_secret_env:
            return ["--sqlite-mfa-key-file", self.a.mfa_key_file, "--postgres-secret-env", self.a.pg_secret_env]
        if self.a.mfa_key_file or self.a.pg_secret_env:
            raise CutoverError("both MFA keys are required")
        return []

    def files(self):
        self.inactive()
        if not self.a.storage_source or not self.a.storage_target:
            raise CutoverError("distinct local source/target storage roots required")
        src = Path(self.a.storage_source)
        dst = Path(self.a.storage_target)
        if not src.is_absolute() or not dst.is_absolute():
            raise CutoverError("source and target storage roots must be absolute")
        src_path, dst_path = src.resolve(), dst.resolve()
        if (src_path == dst_path or src_path.is_relative_to(dst_path)
                or dst_path.is_relative_to(src_path)):
            raise CutoverError("source and PostgreSQL storage must be disjoint trees")
        if self.work.is_relative_to(src_path) or self.work.is_relative_to(dst_path):
            raise CutoverError("private migration journal must not be inside storage")
        refuse_symlink(dst)
        before, count, size = storage_fingerprint(src)
        enough_space(dst, size, "verified local blob copy")
        report = run_cmd([self.a.launcher_sqlite, "sqlite-to-postgres-files", "--source-root", self.a.storage_source, "--target-root", self.a.storage_target, "--ack-offline"], env=self.env)
        if not report.get("verified") or report.get("sourceSha256") != self.state["sourceSHA256"]:
            raise CutoverError("file-copy receipt invalid")
        after, after_count, after_size = storage_fingerprint(src)
        if (after, after_count, after_size) != (before, count, size):
            raise CutoverError("source blobs changed during PostgreSQL copy")
        if int(report.get("checked", -1)) < 0 or not report.get("catalogSha256"):
            raise CutoverError("file-copy result missing verified catalog digest")
        return {"verified": True, "objects": report["checked"], "sourceStorageSHA256": after, "sourceStorageObjects": count, "catalogSha256": report["catalogSha256"]}

    def verify(self):
        self.inactive()
        if self.state.get("importOutcomeUnknown"):
            raise CutoverError("ambiguous import commit: inspect PostgreSQL and reconcile before any retry")
        manifest = run_cmd([self.a.launcher_sqlite, "backup-verify", "--backup", str(self.backup)], env=self.env)
        if manifest.get("manifest", {}).get("sha256") != self.state.get("sourceSHA256"):
            raise CutoverError("frozen SQLite backup has changed")
        report = run_cmd([self.a.launcher_sqlite, "sqlite-to-postgres-cutover-check", "--source-sha256", self.state["sourceSHA256"], "--project", self.a.project, "--owner-email", self.a.owner_email], env=self.env)
        if not all(report.get(k) for k in ("liveVerified", "filesVerified", "repositoryVerified")):
            raise CutoverError("PostgreSQL Repository verification incomplete")
        return {"verified": True, "readyForBackendCutover": report.get("readyForBackendCutover", False), "ownerId": report["ownerId"]}

    def cutover(self):
        self.inactive()
        verdict = self.state.get("receipts", {}).get("verify", {})
        if not verdict.get("readyForBackendCutover") or not self.state.get("cutoverSupported"):
            raise CutoverError("unsafe cutover blocked: HTTP/Coordinator state not migrated; Core receipt is not approval")
        # The recovery barrier MUST reach durable storage before env rewrite.
        # A crash between config replacement and flag persistence otherwise
        # permits an unsafe SQLite rollback after PG may have accepted writes.
        self.state["writeBoundaryCrossed"] = True
        self.save()
        self.log("cutover", "write_boundary_armed")
        change_env(Path(self.a.source_env), self.env[self.a.dsn_env], "postgres", self.a.storage_target)
        for unit in self.a.units:
            code, _ = self.service("start", unit)
            if code:
                raise CutoverError("PostgreSQL writer failed to start: check write outcome before rollback")
        return {"backendStarted": True}

    def health_check(self):
        # Cannot undo new PostgreSQL writes. If the backend has started, any
        # unsuccessful health check stops here for manual reconciliation.
        import urllib.request
        request = urllib.request.Request(self.a.health_url, method="GET")
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise CutoverError("Backend health status is not 200")
        # /ready proves only process liveness. Production acceptance requires
        # an actual owner login and project operation; never mark the complete
        # pipeline successful based solely on an HTTP 200.
        raise CutoverError("Backend responded but owner login/project operation was not verified; keep PostgreSQL writers stopped")

    def run(self):
        self.init_workdir()
        lock_path = self.work / "operator.lock"
        try:
            with lock_path.open("a+b") as lock:
                os.chmod(lock_path, 0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise CutoverError("operator is already running") from exc
                check_stage_chain(self.state)
                if self.state.get("rolledBack"):
                    raise CutoverError("previous operation rolled back; use a fresh work directory")
                if self.state.get("importOutcomeUnknown"):
                    raise CutoverError("previous import outcome unknown: manually reconcile PostgreSQL before continuing")
                pipeline = [self.preflight, self.do_backup, self.freeze, self.frozen_backup, self.importing, self.files, self.verify, self.cutover, self.health_check]
                for stage, function in zip(STAGES, pipeline):
                    self.stage(stage, function)
                return self.state
        except Exception:
            # If any PostgreSQL writer could have started, STOP all declared
            # units but never claim that stopping makes stale-DB rollback safe.
            if self.state.get("writeBoundaryCrossed"):
                for unit in self.a.units:
                    try:
                        self.service("stop", unit)
                    except Exception:
                        pass
                self.log("post_cutover_fault", "writes_unknown_rollback_blocked")
            # The lock above has been released before restarting SQLite.
            # PostgreSQL is still isolated until the write boundary is crossed.
            if ("backup" in self.state.get("completed", []) and
                    not self.state.get("writeBoundaryCrossed") and
                    not self.state.get("rolledBack")):
                try:
                    self.rollback()
                except Exception as rollback_error:
                    self.log("automatic_rollback", "failed", reason=type(rollback_error).__name__)
            raise

    def rollback(self):
        self.init_workdir()
        with (self.work / "operator.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.state.get("writeBoundaryCrossed"):
                raise CutoverError("writes may have reached PostgreSQL; automatic rollback forbidden")
            if self.state.get("importOutcomeUnknown"):
                # SQLRepository import may be committed, but the old source
                # remains authoritative until cutover. Never delete PG data or
                # retry import as part of SQLite recovery.
                self.log("rollback", "isolated_postgres_commit_unknown")
            # An abrupt termination after systemctl stop but before the phase
            # receipt is still safely recoverable if all units are inactive.
            if "backup" not in self.state["completed"]:
                raise CutoverError("no verified preflight backup to restore")
            self.inactive()
            private_file(self.original_env)
            # We have never modified the source databases. Validate the frozen
            # independent backup before restoring the original service config.
            if "frozen_backup" in self.state["completed"]:
                # A completed backup receipt must always pass independent
                # verification. On an interrupted backup stage, incomplete
                # files are forensic evidence, NOT an input to source recovery.
                validate_sqlite_backup(self.http_backup)
                if self.a.coordinator_db:
                    validate_sqlite_backup(self.coordinator_backup)
                result = run_cmd([self.a.launcher_sqlite, "backup-verify", "--backup", str(self.backup)], env=self.env)
                if result.get("manifest", {}).get("sha256") != self.state.get("sourceSHA256"):
                    raise CutoverError("source backup damaged; rollback blocked")
            elif any(path.exists() for path in (self.backup, self.http_backup, self.coordinator_backup)):
                self.log("rollback", "partial_frozen_backups_ignored_source_only")
            # Verify all old sources are still readable; never overwrite a
            # source DB merely because the independently copied backup exists.
            for source in [self.a.core_db, self.a.http_db, *([self.a.coordinator_db] if self.a.coordinator_db else [])]:
                private_file(Path(source))
                validate_sqlite_backup(Path(source))
            write_secure(Path(self.a.source_env), self.original_env.read_bytes())
            for unit in self.a.units:
                code, _ = self.service("start", unit)
                if code:
                    for stopped in self.a.units:
                        try:
                            self.service("stop", stopped)
                        except Exception:
                            pass
                    raise CutoverError("SQLite service restart failed; services stopped for investigation")
            self.state["rolledBack"] = True
            self.save()
            self.log("rollback", "completed")
            return {"restoredOriginalEnvironment": True, "sourceDatabaseUntouched": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "status", "rollback"))
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--launcher-sqlite", default="launcher-sqlite")
    parser.add_argument("--source-env", default="")
    parser.add_argument("--core-db", default="")
    parser.add_argument("--http-db", default="")
    parser.add_argument("--coordinator-db", default="")
    parser.add_argument("--storage-source", default="")
    parser.add_argument("--storage-target", default="")
    parser.add_argument("--writer-unit", dest="units", action="append", default=[])
    parser.add_argument("--project", default="")
    parser.add_argument("--owner-email", default="")
    parser.add_argument("--dsn-env", default="LAUNCHER_POSTGRES_DSN")
    parser.add_argument("--mfa-key-file", default="")
    parser.add_argument("--pg-secret-env", default="")
    parser.add_argument("--health-url", default="http://127.0.0.1:8080/ready")
    args = parser.parse_args(argv)
    try:
        operator = Operator(args)
        if args.action == "status":
            operator.init_workdir()
            print(json.dumps(operator.state, sort_keys=True))
            return 0
        required = ("source_env", "core_db", "http_db", "storage_source", "storage_target", "project", "owner_email")
        if any(not getattr(args, field) for field in required):
            raise CutoverError("required source paths, local storage, project and owner-email")
        if args.action == "rollback":
            result = operator.rollback()
        else:
            result = operator.run()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (CutoverError, OSError, ValueError, KeyError) as exc:
        print(f"cutover rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
