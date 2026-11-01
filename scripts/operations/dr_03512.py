#!/usr/bin/env python3
"""Docker Compose Standard/Network-HA full-state cold backup, restore and DR checks.

Standard backup freezes all application writers, verifies PostgreSQL has no other
client sessions, dumps PostgreSQL and captures storage, factory, backups and the
SQLite coordinator as one maintenance-window snapshot. Restores only to an empty
project and verifies volume readback and database restore. External secrets/TLS
files are NOT exported: recover them from an approved separate secret manager.
"""

from __future__ import annotations

import argparse
import io
import stat
from datetime import datetime, timezone
import hashlib
import sqlite3
import json
import os
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy/production/docker-compose.yml"
COMPOSE_FILES = [COMPOSE]
COMPOSE_PROFILES: list[str] = []
VOLUMES = (
    "launcher_storage",
    "launcher_backups",
    "launcher_factory",
    "launcher_coordinator",
    "launcher_redis",
)
STANDARD_VOLUMES = VOLUMES[:-1]
# Redis AOF is deliberately never promoted to the new cluster: it contains
# transient leases and presence that MUST NOT survive a disaster restore.
WORLD_NAME = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
WORLD_BACKUP_ID = re.compile(r"^[0-9a-f]{32}$")


def required_volumes() -> tuple[str, ...]:
    return STANDARD_VOLUMES


CHUNK = 1024 * 1024
PROJECT_PATTERN = re.compile(r"^nl-dr-[a-z0-9][a-z0-9-]{0,35}$")
VALID_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")


class DrillError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def run(
    args: list[str], *, stdin=None, stdout=None, timeout=600, env=None
) -> subprocess.CompletedProcess:
    # Do not print commands: Compose env and pg_dump invocations may contain secrets.
    result = subprocess.run(
        args,
        stdin=stdin,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
        check=False,
    )
    if result.returncode:
        # Keep diagnostic bounded; never echo credentials/DSNs from tool output.
        raise DrillError(f"{args[0]} command failed (exit {result.returncode})")
    return result


def compose(
    project: str, env_file: Path, *args: str, stdout=None, stdin=None, timeout=600
):
    return run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "--env-file",
            str(env_file),
            *[
                entry
                for profile in COMPOSE_PROFILES
                for entry in ("--profile", profile)
            ],
            *[entry for path in COMPOSE_FILES for entry in ("-f", str(path))],
            *args,
        ],
        stdin=stdin,
        stdout=stdout,
        timeout=timeout,
    )


def compose_states(project: str, env_file: Path) -> dict[str, str]:
    """Read actual Docker Compose container states; do not guess from exit codes."""
    result = compose(project, env_file, "ps", "--all", "--format", "json", timeout=45)
    raw = result.stdout.decode("utf-8", errors="strict").strip()
    if not raw:
        return {}
    try:
        decoded = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
    except (ValueError, UnicodeError) as exc:
        raise DrillError("cannot parse Docker Compose service states") from exc
    if isinstance(decoded, dict):
        decoded = [decoded]
    if not isinstance(decoded, list):
        raise DrillError("invalid Docker Compose service states")
    states = {}
    for item in decoded:
        if not isinstance(item, dict) or not isinstance(item.get("Service"), str):
            raise DrillError("invalid Docker Compose service entry")
        name, state = item["Service"], str(item.get("State", "")).lower()
        if name in states or not state:
            raise DrillError("duplicate/unknown Compose state")
        states[name] = state
    return states


def assert_quiescent(project: str, env_file: Path) -> str:
    states = compose_states(project, env_file)
    if states.get("postgres") != "running":
        raise DrillError("PostgreSQL must be running to create a logical snapshot")
    for name in ("api", "admin", "nginx", "redis"):
        if name == "redis" and "network-ha" not in COMPOSE_PROFILES:
            continue
        if states.get(name) in ("running", "restarting", "paused"):
            raise DrillError(f"writes not fenced: service {name} is active")
    # Standard PostgreSQL is private to this Compose project. Fail if an
    # unexpected client stays connected; external writers must also be fenced
    # at the deployment boundary for the ENTIRE maintenance window.
    query = (
        "SELECT (SELECT count(*) FROM pg_stat_activity "
        "WHERE datname=current_database() "
        "AND backend_type='client backend' AND pid<>pg_backend_pid()) "
        "|| '|' || pg_current_wal_insert_lsn()::text"
    )
    command = (
        'exec psql -X -A -t -v ON_ERROR_STOP=1 '
        '-U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "' + query + '"'
    )
    result = compose(project, env_file, "exec", "-T", "postgres", "sh", "-ec", command, timeout=60)
    observation = result.stdout.decode("ascii", errors="replace").strip()
    match = re.fullmatch(r"(\d+)\|([0-9A-F]+/[0-9A-F]+)", observation)
    if not match:
        raise DrillError("invalid PostgreSQL session/WAL observation")
    if int(match.group(1)) != 0:
        raise DrillError("PostgreSQL has additional active client sessions; backup blocked")
    return match.group(2)


def verify_coordinator(archive_path: Path) -> None:
    """Validate WAL-aware recovered SQLite coordinator, not merely tar checksums."""
    if "network-ha" in COMPOSE_PROFILES:
        return
    safe_tar(archive_path)
    parts = {"state.db", "state.db-wal", "state.db-shm"}
    with tempfile.TemporaryDirectory(prefix="launcher-coordinate-verify-") as tmp:
        base = Path(tmp)
        seen = set()
        with tarfile.open(archive_path, "r:gz") as archive:
            for entry in archive:
                relative = PurePosixPath(entry.name)
                if not entry.isfile() or len(relative.parts) != 1 or relative.name not in parts:
                    continue
                if relative.name in seen:
                    raise DrillError("duplicate SQLite coordinator file")
                seen.add(relative.name)
                input_stream = archive.extractfile(entry)
                if input_stream is None:
                    raise DrillError("unreadable SQLite coordinator")
                with input_stream, (base / relative.name).open("xb") as out:
                    shutil.copyfileobj(input_stream, out, length=CHUNK)
        if "state.db" not in seen:
            raise DrillError("Standard snapshot is missing the SQLite coordinator database")
        try:
            connection = sqlite3.connect(
                "file:" + quote(str(base / "state.db")) + "?mode=ro", uri=True, timeout=10
            )
            try:
                if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise DrillError("SQLite coordinator integrity check failed")
                if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise DrillError("SQLite coordinator FK check failed")
                version = connection.execute(
                    "SELECT value FROM coord_meta WHERE key='version'"
                ).fetchone()
                if version != (1,):
                    raise DrillError("SQLite coordinator has incompatible schema")
            finally:
                connection.close()
        except sqlite3.DatabaseError as exc:
            raise DrillError("invalid SQLite coordinator database") from exc


def volume_name(project: str, logical: str) -> str:
    if logical not in VOLUMES:
        raise DrillError("unknown volume")
    if not VALID_PROJECT.fullmatch(project):
        raise DrillError("invalid Compose project name")
    return project + "_" + logical


def authorize_project(
    project: str,
    confirmation: str,
    *,
    production: bool = False,
    approved: bool = False,
    chaos_mode: bool = False,
) -> None:
    if not VALID_PROJECT.fullmatch(project):
        raise DrillError("invalid Compose project name")
    if confirmation != project:
        raise DrillError(
            "refusing destructive operation: --confirm must exactly match --project"
        )
    if PROJECT_PATTERN.fullmatch(project):
        return
    if chaos_mode or not (production and approved):
        raise DrillError(
            "production project requires explicit production mode and maintenance approval"
        )


def ensure_isolated(project: str, confirmation: str) -> None:
    authorize_project(project, confirmation, chaos_mode=True)


def docker_volume_exists(volume: str) -> bool:
    result = subprocess.run(
        ["docker", "volume", "inspect", volume],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    return result.returncode == 0


def safe_tar(path: Path) -> tuple[int, int]:
    total, count = 0, 0
    seen: set[str] = set()
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            # A DR archive may never plant symlinks, devices, hardlinks, or escape paths.
            name = PurePosixPath(entry.name)
            if (
                entry.name.startswith("/")
                or "\\" in entry.name
                or ".." in name.parts
                or "\x00" in entry.name
            ):
                raise DrillError("unsafe archive member path")
            if not (entry.isfile() or entry.isdir()):
                raise DrillError("unsafe archive member type")
            canonical = str(name)
            if canonical in seen and canonical != ".":
                raise DrillError("duplicate archive path")
            seen.add(canonical)
            if entry.isfile():
                count += 1
                total += entry.size
    return count, total


def stream_to_file(cmd: list[str], destination: Path, timeout: int = 1800) -> None:
    # Large archives/dumps stream directly to disk; no full in-memory buffering.
    with destination.open("xb") as out:
        run(cmd, stdout=out, timeout=timeout)
    if not destination.is_file() or destination.stat().st_size == 0:
        raise DrillError("empty snapshot output")


def docker_tar_backup(volume: str, output: Path) -> None:
    stream_to_file(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            f"type=volume,src={volume},dst=/source,readonly",
            "alpine:3.20",
            "tar",
            "-czf",
            "-",
            "-C",
            "/source",
            ".",
        ],
        output,
    )
    safe_tar(output)


def tar_digests(path: Path) -> dict[str, dict]:
    """Stream every restored volume file and compare actual bytes, not tar headers."""
    safe_tar(path)
    result = {}
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            if entry.isfile():
                digest = hashlib.sha256()
                contents = archive.extractfile(entry)
                if contents is None:
                    raise DrillError("invalid tar file entry")
                with contents:
                    for chunk in iter(lambda: contents.read(CHUNK), b""):
                        digest.update(chunk)
                result[str(PurePosixPath(entry.name))] = {
                    "sha256": digest.hexdigest(),
                    "size": entry.size,
                }
    return result


def docker_tar_restore(volume: str, archive: Path) -> None:
    safe_tar(archive)
    # Only ever extract into a new, empty, isolated volume.
    cmd = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--mount",
        f"type=volume,src={volume},dst=/target",
        "alpine:3.20",
        "tar",
        "-xzf",
        "-",
        "-C",
        "/target",
    ]
    with archive.open("rb") as source:
        run(cmd, stdin=source, timeout=1800)
    with tempfile.TemporaryDirectory(prefix="launcher-volume-check-") as work:
        actual = Path(work) / "readback.tar.gz"
        docker_tar_backup(volume, actual)
        if tar_digests(archive) != tar_digests(actual):
            raise DrillError("restored Docker volume data mismatch")


def compose_pg_dump(project: str, env_file: Path, dst: Path) -> None:
    prefix = [
        "docker",
        "compose",
        "-p",
        project,
        "--env-file",
        str(env_file),
        *[entry for profile in COMPOSE_PROFILES for entry in ("--profile", profile)],
        *[entry for path in COMPOSE_FILES for entry in ("-f", str(path))],
    ]
    stream_to_file(
        prefix
        + [
            "exec",
            "-T",
            "postgres",
            "sh",
            "-ec",
            'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-acl',
        ],
        dst,
    )


def compose_pg_restore(project: str, env_file: Path, dump: Path) -> None:
    # --single-transaction makes failed database restores atomic within PG.
    with dump.open("rb") as source:
        compose(
            project,
            env_file,
            "exec",
            "-T",
            "postgres",
            "sh",
            "-ec",
            'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --single-transaction --exit-on-error --no-owner --no-acl',
            stdin=source,
            timeout=1800,
        )


def pg_validate(dump: Path) -> None:
    # Validate archive structure using the matching PostgreSQL client in Alpine.
    with dump.open("rb") as f:
        run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "postgres:16-alpine",
                "sh",
                "-ec",
                "cat > /tmp/backup.dump && pg_restore --list /tmp/backup.dump >/dev/null",
            ],
            stdin=f,
            timeout=1800,
        )


def aws(*args: str, timeout: int = 1800) -> str:
    result = run(["aws", *args], timeout=timeout)
    return result.stdout.decode("utf-8", errors="replace")


def s3_options(endpoint: str | None) -> list[str]:
    if endpoint and not (
        endpoint.startswith("https://")
        or endpoint.startswith("http://127.0.0.1:")
        or endpoint.startswith("http://localhost:")
    ):
        raise DrillError("S3 endpoint must be HTTPS or local loopback")
    return ["--endpoint-url", endpoint] if endpoint else []


def s3_download(bucket: str, root: Path, endpoint: str | None) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", bucket):
        raise DrillError("invalid S3 bucket")
    root.mkdir(parents=True, exist_ok=False)
    aws(
        *s3_options(endpoint),
        "s3",
        "sync",
        "s3://" + bucket,
        str(root),
        "--only-show-errors",
    )
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise DrillError("S3 snapshot contains unsafe filesystem entry")


def s3_list_first(bucket: str, endpoint: str | None) -> bool:
    value = aws(
        *s3_options(endpoint),
        "s3api",
        "list-objects-v2",
        "--bucket",
        bucket,
        "--max-keys",
        "1",
        "--query",
        "KeyCount",
        "--output",
        "text",
    ).strip()
    if value not in ("0", "1"):
        raise DrillError("unexpected S3 inventory response")
    return value == "1"


def s3_upload_fresh(
    bucket: str, root: Path, endpoint: str | None, expected: dict
) -> None:
    if s3_list_first(bucket, endpoint):
        raise DrillError("S3 restore bucket is not empty")
    aws(
        *s3_options(endpoint),
        "s3",
        "sync",
        str(root),
        "s3://" + bucket,
        "--only-show-errors",
    )
    # The restore is not called verified until every uploaded byte is read back.
    with tempfile.TemporaryDirectory(prefix="launcher-s3-verify-") as temp:
        second = Path(temp) / "objects"
        s3_download(bucket, second, endpoint)
        files = {
            p.relative_to(second).as_posix(): {
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            }
            for p in second.rglob("*")
            if p.is_file()
        }
        if files != expected:
            raise DrillError("S3 readback differs from verified source snapshot")



def parse_world_args(values: list[str]) -> dict[str, Path]:
    result = {}
    for entry in values:
        name, separator, path = entry.partition("=")
        if not separator or not WORLD_NAME.fullmatch(name) or name in result or not path:
            raise DrillError("world option must be unique NAME=/absolute/path")
        location = Path(path)
        if not location.is_absolute() or location.is_symlink():
            raise DrillError("world path must be an absolute real path")
        result[name] = Path(os.path.abspath(location))
    return result


def safe_world_backup(folder: Path) -> dict:
    """Independently verify the actual Go world-backup/v1 payload byte by byte."""
    if not folder.is_dir() or folder.is_symlink() or not WORLD_BACKUP_ID.fullmatch(folder.name):
        raise DrillError("world backup must be an ID directory, without symlinks")
    manifest = folder / "manifest.json"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 32 * 1024 * 1024:
        raise DrillError("missing or unsafe world manifest")
    try:
        data = json.loads(manifest.read_text(encoding="utf8"))
    except (ValueError, UnicodeError) as exc:
        raise DrillError("invalid world backup manifest") from exc
    if (not isinstance(data, dict) or data.get("schema") != "launcher-world-backup/v1"
            or data.get("id") != folder.name or data.get("consistency") != "confirmed-stopped"
            or not isinstance(data.get("entries"), list) or not data["entries"]):
        raise DrillError("unsupported/incomplete world backup")
    expected = {}
    if len(data["entries"]) > 1000000:
        raise DrillError("world manifest exceeds supported entries")
    for item in data["entries"]:
        if not isinstance(item, dict):
            raise DrillError("invalid world entry")
        name = item.get("path")
        if (not isinstance(name, str) or not name or name.startswith("/") or "\\" in name
                or "\x00" in name or any(part in ("", ".", "..") for part in name.split("/"))
                or name in expected or item.get("type") not in ("dir", "file")):
            raise DrillError("invalid or duplicate world path")
        if item["type"] == "file" and (not isinstance(item.get("size"), int) or item["size"] < 0
                or not isinstance(item.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", item["sha256"])):
            raise DrillError("invalid world file digest")
        mode = item.get("mode")
        if not isinstance(mode, int) or mode < 0 or mode > 0o777:
            raise DrillError("invalid world file mode")
        if "/" in name:
            parent = name.rsplit("/", 1)[0]
            if parent not in expected or expected[parent]["type"] != "dir":
                raise DrillError("world manifest lacks directory ancestor or is unsorted")
        expected[name] = item
    root = folder / "payload"
    if root.is_symlink() or not root.is_dir():
        raise DrillError("world payload missing")
    actual = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        entry = expected.get(relative)
        mode = path.lstat().st_mode
        if entry is None or stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise DrillError("unsafe or unexpected world backup file")
        if (entry["type"] == "dir") != stat.S_ISDIR(mode):
            raise DrillError("world file type mismatch")
        if entry["type"] == "file" and (path.stat().st_size != entry["size"] or sha256_file(path) != entry["sha256"]):
            raise DrillError("world backup checksum mismatch")
        actual[relative] = True
    if set(actual) != set(expected):
        raise DrillError("missing world backup files")
    if not isinstance(data.get("worlds"), list) or not data["worlds"] or any(
        not isinstance(w, str) or w not in expected or expected[w]["type"] != "dir"
        for w in data["worlds"]
    ):
        raise DrillError("world backup selection is missing")
    if data.get("totalBytes") != sum(v["size"] for v in expected.values() if v["type"] == "file"):
        raise DrillError("world backup totalBytes mismatch")
    return data


def archive_world_backups(stage: Path, sources: dict[str, Path]) -> list[dict]:
    if not sources:
        raise DrillError("network-ha backup needs stopped world snapshots (--world-backup)")
    receipts = []
    for name, source in sorted(sources.items()):
        manifest = safe_world_backup(source)
        target = stage / "worlds" / name / source.name
        target.parent.mkdir(parents=True, mode=0o700)
        shutil.copytree(source, target, symlinks=False)
        again = safe_world_backup(target)
        if again != manifest or safe_world_backup(source) != manifest:
            raise DrillError("world backup changed during copying")
        receipts.append({"name": name, "backupId": source.name, "fileCount": len(manifest["entries"]),
                         "totalBytes": manifest["totalBytes"], "manifestSha256": sha256_file(target / "manifest.json")})
    return receipts


def validate_world_receipts(folder: Path, receipts: object) -> None:
    if not isinstance(receipts, list) or not receipts:
        raise DrillError("network-ha world inventory is empty")
    seen = set()
    for r in receipts:
        if (not isinstance(r, dict) or not WORLD_NAME.fullmatch(str(r.get("name", "")))
                or not WORLD_BACKUP_ID.fullmatch(str(r.get("backupId", ""))) or r["name"] in seen):
            raise DrillError("invalid world receipt")
        seen.add(r["name"])
        source = folder / "worlds" / r["name"] / r["backupId"]
        manifest = safe_world_backup(source)
        if (r.get("fileCount") != len(manifest["entries"]) or r.get("totalBytes") != manifest["totalBytes"]
                or r.get("manifestSha256") != sha256_file(source / "manifest.json")):
            raise DrillError("world receipt mismatch")
    worlds = folder / "worlds"
    if worlds.is_symlink() or not worlds.is_dir():
        raise DrillError("world inventory root is unsafe")
    for name in worlds.iterdir():
        if name.is_symlink() or not name.is_dir() or name.name not in seen:
            raise DrillError("unexpected world inventory")
        expected_id = next(r["backupId"] for r in receipts if r["name"] == name.name)
        if sorted(p.name for p in name.iterdir()) != [expected_id]:
            raise DrillError("unexpected world backup content")


def validate_world_destinations(worlds: list[dict], destinations: dict[str, Path], folder: Path) -> None:
    if set(destinations) != {r["name"] for r in worlds}:
        raise DrillError("each captured world needs exactly one --world-destination")
    targets = list(destinations.values())
    for name, path in destinations.items():
        if path.exists() or path.is_symlink():
            raise DrillError(f"world destination for {name} exists; fresh destination required")
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise DrillError("world destination parent must already exist")
        for parent in [path.parent, *path.parent.parents]:
            if parent.is_symlink():
                raise DrillError("symlinked world destination ancestor")
        if folder == path or folder in path.parents or path in folder.parents:
            raise DrillError("world destination overlaps the snapshot")
    for i, left in enumerate(targets):
        for right in targets[i+1:]:
            if left == right or left in right.parents or right in left.parents:
                raise DrillError("overlapping world destinations")


def restore_world_backup(source: Path, destination: Path) -> None:
    manifest = safe_world_backup(source)
    staging = Path(tempfile.mkdtemp(prefix=".world-restore-", dir=destination.parent))
    try:
        for item in manifest["entries"]:
            rel = item["path"]
            target = staging / rel
            if item["type"] == "dir":
                target.mkdir(mode=0o700)
            else:
                with (source / "payload" / rel).open("rb") as stream, target.open("xb") as out:
                    digest = hashlib.sha256()
                    while chunk := stream.read(CHUNK):
                        out.write(chunk)
                        digest.update(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                if digest.hexdigest() != item["sha256"] or target.stat().st_size != item["size"]:
                    raise DrillError("world changed during restore")
                target.chmod(item["mode"])
        for item in reversed(manifest["entries"]):
            if item["type"] == "dir":
                (staging / item["path"]).chmod(item["mode"])
        safe_world_restored(staging, manifest)
        if destination.exists() or destination.is_symlink():
            raise DrillError("world destination appeared before publication")
        staging.rename(destination)
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def safe_world_restored(folder: Path, manifest: dict) -> None:
    # Actual restored bytes, not merely the transport archive digest.
    for item in manifest["entries"]:
        path = folder / item["path"]
        if item["type"] == "file" and (not path.is_file() or path.is_symlink()
                or path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]):
            raise DrillError("restored world file mismatch")
        if item["type"] == "dir" and (not path.is_dir() or path.is_symlink()):
            raise DrillError("restored world directory mismatch")


def ensure_empty_redis_volume(project: str) -> None:
    name = volume_name(project, "launcher_redis")
    if not docker_volume_exists(name):
        raise DrillError("Compose did not create fresh Redis volume")
    run(["docker", "run", "--rm", "--network", "none", "--mount",
         f"type=volume,src={name},dst=/data,readonly", "alpine:3.20",
         "sh", "-ec", 'test -z "$(ls -A /data)"'], timeout=60)


FENCE_SQL_0454 = """BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '120s';
SELECT pg_advisory_xact_lock(4504, 1);
-- Dispatched side effects can never be replayed after a disaster.
UPDATE server_bridge_control_commands_v3
 SET status='indeterminate', updated_at=now(), completed_at=now(), lease_until=NULL,
 error='disaster recovery: old lease untrusted; inspect external effect'
 WHERE status='leased';
UPDATE server_bridge_control_commands_v3
 SET status='expired', updated_at=now(), completed_at=now(), lease_until=NULL,
 error='disaster recovery: pending command discarded' WHERE status='pending';
UPDATE server_bridge_join_tickets_v2
 SET status='invalidated', invalidated_at=now() WHERE status='active';
UPDATE server_bridge_handoffs_v2
 SET status='invalidated', invalidated_at=now() WHERE status='active';
UPDATE server_bridge_player_transfers_v3
 SET status='invalidated' WHERE status='issued';
UPDATE server_bridge_player_sessions_v3
 SET status='invalidated', recheck_required=false, invalidated_at=now(),
 invalidated_reason='disaster recovery: prior runtime not trusted', updated_at=now()
 WHERE status='active';
UPDATE server_bridge_runtime_instances_v3 SET ended_at=now() WHERE ended_at IS NULL;
-- A restored credential cannot admit an old running JVM. Force explicit
-- rotation/re-enrollment; never automatically resume signed host commands.
UPDATE server_bridge_nodes_v2 SET
 status='credential-rotation-required', last_heartbeat_at=NULL,
 runtime_previous_id=runtime_id, runtime_id='', runtime_epoch=runtime_epoch+1,
 routing_accepting=false, routing_state='maintenance', routing_health='unknown'
 WHERE status='active';
-- Fence all other durable work. Never silently replay a side effect whose
-- acknowledgement might have been lost on the destroyed source cluster.
UPDATE durable_jobs SET status='failed', lease_owner='', lease_token='', lease_fence=lease_fence+1,
 lease_expires_at=NULL, completed_at=now(), updated_at=now(),
 last_error='disaster recovery: in-flight effect requires reconciliation' WHERE status='running';
UPDATE event_outbox SET status='dead', lease_owner='', lease_token='', lease_fence=lease_fence+1,
 lease_expires_at=NULL, updated_at=now(),
 last_error='disaster recovery: in-flight delivery requires reconciliation' WHERE status='running';
UPDATE durable_scope_leases SET fencing_token=fencing_token+1,
 owner='disaster-recovery-fenced', lease_token='disaster-recovery-fenced',
 expires_at='-infinity', updated_at=now();
UPDATE extension_event_deliveries SET status='dead', lease_until=NULL, lease_token='',
 last_error='disaster recovery: in-flight extension effect', updated_at=now()
 WHERE status='processing';
DELETE FROM extension_update_leases;
UPDATE extension_update_transactions SET status='failed', lease_owner='', finished_at=now(),
 failure='disaster recovery: reconcile partial extension update' WHERE status='running';
UPDATE migration_runs_0331 SET status='paused', fence=fence+1, lease_owner=NULL, lease_until=NULL,
 last_error='disaster recovery: migration must be reconciled', updated_at=now()
 WHERE status='running' OR lease_owner IS NOT NULL;
COMMIT;
SELECT (SELECT count(*) FROM server_bridge_control_commands_v3 WHERE status IN ('leased','pending')) || '|' ||
 (SELECT count(*) FROM server_bridge_nodes_v2 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_join_tickets_v2 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_player_sessions_v3 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_handoffs_v2 WHERE status='active') || '|' ||
 (SELECT count(*) FROM server_bridge_player_transfers_v3 WHERE status='issued') || '|' ||
 (SELECT count(*) FROM durable_jobs WHERE status='running') || '|' ||
 (SELECT count(*) FROM event_outbox WHERE status='running') || '|' ||
 (SELECT count(*) FROM extension_event_deliveries WHERE status='processing') || '|' ||
 (SELECT count(*) FROM migration_runs_0331 WHERE lease_owner IS NOT NULL);
"""


def fence_restored_serverbridge(project: str, env_file: Path) -> None:
    result = compose(project, env_file, "exec", "-T", "postgres", "sh", "-ec",
                     'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql -X -A -t -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                     stdin=io.BytesIO(FENCE_SQL_0454.encode("utf-8")), timeout=180)
    if not result.stdout.decode("utf-8", errors="replace").strip().endswith("0|0|0|0|0|0|0|0|0|0"):
        raise DrillError("restored ServerBridge fence readback did not pass")


def snapshot(
    project: str,
    env_file: Path,
    dest: Path,
    confirm: str,
    s3_bucket: str | None = None,
    s3_endpoint: str | None = None,
    production: bool = False,
    approved: bool = False,
    world_backups: dict[str, Path] | None = None,
) -> dict:
    authorize_project(project, confirm, production=production, approved=approved)
    if "network-ha" in COMPOSE_PROFILES and not world_backups:
        raise DrillError("network-ha requires verified world backups")
    if dest.exists():
        raise DrillError("snapshot destination already exists; will not overwrite")
    if not env_file.is_file() or env_file.is_symlink():
        raise DrillError("Compose environment file missing or symlinked")
    started = time.monotonic()
    dest.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".dr-stage-", dir=dest.parent))
    stopped = []
    try:
        # Preserve initially stopped services; a backup must not silently start
        # a service that its operator deliberately left disabled.
        states = compose_states(project, env_file)
        if states.get("postgres") != "running":
            raise DrillError("PostgreSQL is not running")
        for svc in (
            ("nginx", "admin", "api", "redis")
            if "network-ha" in COMPOSE_PROFILES
            else ("nginx", "admin", "api")
        ):
            if states.get(svc) == "running":
                compose(project, env_file, "stop", "-t", "30", svc)
                stopped.append(svc)
            elif states.get(svc) in ("paused", "restarting"):
                raise DrillError(f"cannot freeze unhealthy service: {svc}")
        pg_lsn_before = assert_quiescent(project, env_file)
        compose_pg_dump(project, env_file, stage / "database.dump")
        pg_validate(stage / "database.dump")
        for item in required_volumes():
            name = volume_name(project, item)
            if not docker_volume_exists(name):
                raise DrillError(f"missing volume: {item}")
            docker_tar_backup(name, stage / (item + ".tar.gz"))
            if item == "launcher_coordinator":
                verify_coordinator(stage / (item + ".tar.gz"))
        worlds = archive_world_backups(stage, world_backups or {}) if "network-ha" in COMPOSE_PROFILES else []
        s3_files = {}
        if s3_bucket:
            s3_root = stage / "s3-objects"
            s3_download(s3_bucket, s3_root, s3_endpoint)
            s3_files = {
                p.relative_to(s3_root).as_posix(): {
                    "sha256": sha256_file(p),
                    "size": p.stat().st_size,
                }
                for p in s3_root.rglob("*")
                if p.is_file()
            }
            if "network-ha" in COMPOSE_PROFILES:
                # Re-read every remote byte, not merely S3 LIST metadata: a
                # concurrent object writer must not silently produce a split
                # PostgreSQL/blob recovery image.
                with tempfile.TemporaryDirectory(dir=stage, prefix=".s3-recheck-") as checkdir:
                    second_root = Path(checkdir) / "objects"
                    s3_download(s3_bucket, second_root, s3_endpoint)
                    second_files = {
                        p.relative_to(second_root).as_posix(): {
                            "sha256": sha256_file(p), "size": p.stat().st_size
                        }
                        for p in second_root.rglob("*") if p.is_file()
                    }
                    if second_files != s3_files:
                        raise DrillError("S3 objects changed during Network-HA backup")
        # Recheck after copying blobs to detect any foreign PostgreSQL clients
        # observed during the maintenance window, rather than only before dump.
        pg_lsn_after = assert_quiescent(project, env_file)
        if pg_lsn_before != pg_lsn_after:
            raise DrillError("PostgreSQL WAL advanced during cold snapshot; retry after fencing ALL writers")
        files = {
            p.name: {"sha256": sha256_file(p), "size": p.stat().st_size}
            for p in stage.iterdir()
            if p.is_file()
        }
        result = {
            "schema": 3 if "network-ha" in COMPOSE_PROFILES else 2,
            "mode": "network-ha" if "network-ha" in COMPOSE_PROFILES else "standard",
            "worlds": worlds,
            "ephemeralRedis": "network-ha" in COMPOSE_PROFILES,
            "version": (ROOT / "VERSION").read_text().strip(),
            "sourceProject": project,
            "createdUtc": datetime.now(timezone.utc).isoformat(),
            "repository": "postgres-logical",
            "storage": "s3-objects" if s3_bucket else "local-volume",
            "s3SourceBucket": s3_bucket,
            "s3Files": s3_files,
            "volumes": list(required_volumes()),
            "redis": "fresh-ephemeral-not-restored"
            if "network-ha" in COMPOSE_PROFILES
            else "not-used",
            "files": files,
            "credentialPolicy": "signing keys, passwords, TLS and KMS material must be restored separately",
            "consistentWrites": "Compose writers stopped; PostgreSQL WAL unchanged and no extra client sessions across snapshot",
            "postgresWalLsn": pg_lsn_before,
            "serviceStateAtBackup": {key: states.get(key, "absent") for key in ("api", "admin", "nginx")},
            "coordinatorIntegrity": "sqlite integrity_check + coord_meta schema version" if "network-ha" not in COMPOSE_PROFILES else "not-used",
        }
        (stage / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
        verify_snapshot(stage)
        if dest.exists() or dest.is_symlink():
            raise DrillError("snapshot destination appeared during backup")
        stage.rename(dest)
        result["durationSeconds"] = round(time.monotonic() - started, 3)
        return result
    finally:
        # Never leave isolated services down after a failed backup.
        try:
            for svc in reversed(stopped):
                compose(project, env_file, "up", "-d", svc)
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def verify_snapshot(folder: Path) -> dict:
    if not folder.is_dir() or folder.is_symlink():
        raise DrillError("snapshot must be a real directory")
    manifest_file = folder / "manifest.json"
    if manifest_file.is_symlink() or not manifest_file.is_file() or manifest_file.stat().st_size > 16 * 1024 * 1024:
        raise DrillError("unsafe or oversized snapshot manifest")
    data = json.loads(manifest_file.read_text())
    if data.get("schema") not in (1, 2, 3) or data.get("storage") not in (
        "local-volume",
        "s3-objects",
    ):
        raise DrillError("unsupported snapshot schema/storage")
    volumes = data.get("volumes", [])
    if data.get("schema") == 3:
        if (data.get("mode") != "network-ha" or data.get("storage") != "s3-objects"
                or data.get("ephemeralRedis") is not True or volumes != list(STANDARD_VOLUMES)):
            raise DrillError("network-ha restore must omit historic Redis leases")
        validate_world_receipts(folder, data.get("worlds"))
    elif volumes not in (list(STANDARD_VOLUMES), list(VOLUMES)):
        raise DrillError("invalid volume inventory")
    expected = {"database.dump", *(v + ".tar.gz" for v in volumes)}
    if set(data.get("files", {})) != expected:
        raise DrillError("snapshot files mismatch")
    if data["storage"] == "s3-objects":
        s3_root = folder / "s3-objects"
        if not s3_root.is_dir() or s3_root.is_symlink():
            raise DrillError("S3 object snapshot missing")
        actual = {}
        for obj in s3_root.rglob("*"):
            if obj.is_symlink() or (not obj.is_file() and not obj.is_dir()):
                raise DrillError("unsafe S3 object")
            if obj.is_file():
                actual[obj.relative_to(s3_root).as_posix()] = {
                    "size": obj.stat().st_size,
                    "sha256": sha256_file(obj),
                }
        if actual != data.get("s3Files"):
            raise DrillError("S3 object snapshot checksum mismatch")
    for filename, meta in data["files"].items():
        path = folder / filename
        if not path.is_file() or path.is_symlink():
            raise DrillError("snapshot missing file")
        if path.stat().st_size != meta["size"] or sha256_file(path) != meta["sha256"]:
            raise DrillError("snapshot SHA-256 verification failed")
        if filename.endswith(".tar.gz"):
            safe_tar(path)
    if data.get("schema") == 2 and data["storage"] == "local-volume":
        verify_coordinator(folder / "launcher_coordinator.tar.gz")
    return data


def validate_ready_url(url: str) -> None:
    parsed = urlsplit(url)
    if (parsed.path != "/ready" or parsed.query or parsed.fragment
            or parsed.username or parsed.password or not parsed.hostname
            or parsed.scheme not in ("https", "http")):
        raise DrillError("readiness URL must be an HTTPS /ready or loopback HTTP /ready")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise DrillError("insecure non-loopback readiness endpoint refused")


def target_release(env_file: Path) -> str | None:
    """Get release used for restore without shell-expanding an untrusted env file."""
    result = None
    for line in env_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() == "LAUNCHER_IMAGE_TAG":
            if result is not None:
                raise DrillError("duplicate LAUNCHER_IMAGE_TAG")
            result = value.strip().strip("\"").strip("'")
    return result


def check_restored_backend(project: str, env_file: Path, *, version: str | None, storage: str, timeout: int = 120) -> dict:
    """Read the actual RESTORED API container, not a possibly stale public DNS route."""
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        try:
            result = compose(
                project, env_file, "exec", "-T", "api", "wget", "-qO-",
                "http://127.0.0.1:8080/ready", timeout=10,
            )
            payload = json.loads(result.stdout)
            if (isinstance(payload, dict) and payload.get("status") == "ready"
                    and payload.get("repository") == "postgres"
                    and payload.get("storage") == storage
                    and (version is None or payload.get("version") == version)):
                return payload
        except (DrillError, ValueError, UnicodeError, OSError):
            pass
        time.sleep(1)
    raise DrillError("restored API container did not become ready with required version/storage")


def restore_fresh(
    project: str,
    env_file: Path,
    folder: Path,
    confirm: str,
    ready_url: str | None = None,
    target_s3_bucket: str | None = None,
    s3_endpoint: str | None = None,
    production: bool = False,
    approved: bool = False,
    world_destinations: dict[str, Path] | None = None,
) -> dict:
    authorize_project(project, confirm, production=production, approved=approved)
    manifest = verify_snapshot(folder)
    if "network-ha" in COMPOSE_PROFILES:
        if manifest.get("schema") != 3:
            raise DrillError("legacy Redis-bearing Network-HA snapshots cannot be restored safely")
        validate_world_destinations(manifest["worlds"], world_destinations or {}, folder)
    elif manifest.get("schema") == 3:
        raise DrillError("network-ha snapshot requires --network-ha")
    # The same project NAME is normal on a replacement host. Never infer that
    # same-name means same existing volumes; only verified empty targets qualify.
    if not env_file.is_file() or env_file.is_symlink():
        raise DrillError("Compose environment file missing or symlinked")
    if not ready_url:
        raise DrillError("restore-fresh requires an actual application readiness endpoint")
    validate_ready_url(ready_url)
    if manifest.get("schema") == 2 and target_release(env_file) != manifest.get("version"):
        raise DrillError("target image version differs from backup; restore exact version first")
    if manifest["volumes"] != list(required_volumes()):
        raise DrillError("restore mode does not match snapshot volume topology")
    if manifest["storage"] == "s3-objects":
        if not target_s3_bucket or target_s3_bucket == manifest["s3SourceBucket"]:
            raise DrillError("restore requires a distinct --target-s3-bucket")
        if s3_list_first(target_s3_bucket, s3_endpoint):
            raise DrillError("S3 target bucket is not empty")
    for item in (VOLUMES if "network-ha" in COMPOSE_PROFILES else manifest["volumes"]):
        if docker_volume_exists(volume_name(project, item)):
            raise DrillError(
                "target already has state: fresh project required; refusing to overwrite"
            )
    # Verify PostgreSQL dump before mutation; refuse pre-existing target containers
    # even if their volumes were manually renamed or removed.
    pg_validate(folder / "database.dump")
    if compose_states(project, env_file):
        raise DrillError("target already has Compose containers; use a fresh host/project")
    started = time.monotonic()
    # A failed restore does not boot the API with partial data.
    compose(project, env_file, "create")
    for item in manifest["volumes"]:
        name = volume_name(project, item)
        if not docker_volume_exists(name):
            raise DrillError("compose did not create required volume")
        docker_tar_restore(name, folder / (item + ".tar.gz"))
    if "network-ha" in COMPOSE_PROFILES:
        ensure_empty_redis_volume(project)
    compose(project, env_file, "up", "-d", "postgres")
    for attempt in range(45):
        try:
            compose(
                project,
                env_file,
                "exec",
                "-T",
                "postgres",
                "sh",
                "-ec",
                'exec pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                timeout=10,
            )
            break
        except DrillError:
            time.sleep(1)
    else:
        raise DrillError("PostgreSQL did not become healthy")
    try:
        compose_pg_restore(project, env_file, folder / "database.dump")
    except Exception:
        # Leave API stopped; manual inspection mandatory.
        raise
    if "network-ha" in COMPOSE_PROFILES:
        # No API/worker/game process can run before the recovered DB is fenced.
        fence_restored_serverbridge(project, env_file)
        for receipt in manifest["worlds"]:
            name = receipt["name"]
            source = folder / "worlds" / name / receipt["backupId"]
            restore_world_backup(source, (world_destinations or {})[name])
    if manifest["storage"] == "s3-objects":
        s3_upload_fresh(
            target_s3_bucket, folder / "s3-objects", s3_endpoint, manifest["s3Files"]
        )
    for svc in (
        ("redis", "api", "admin", "nginx")
        if "network-ha" in COMPOSE_PROFILES
        else ("api", "admin", "nginx")
    ):
        compose(project, env_file, "up", "-d", svc)
    outcome = {
        "status": "restored-and-started",
        "source": manifest["sourceProject"],
        "target": project,
        "rtoSeconds": round(time.monotonic() - started, 3),
        "dataChecks": "snapshot SHA-256, archive member safety, pg_restore transaction",
        "credentials": "provided externally via target environment",
        "applicationVerified": False,
        "serverbridgeFenced": "network-ha" in COMPOSE_PROFILES,
        "redisRestored": False if "network-ha" in COMPOSE_PROFILES else None,
        "restoredWorlds": sorted((world_destinations or {}).keys()),
    }
    try:
        check_restored_backend(
            project, env_file,
            version=manifest.get("version") if manifest.get("schema") == 2 else None,
            storage="local" if manifest["storage"] == "local-volume" else "s3",
        )
        await_readiness(
            ready_url, expected=True, limit=120,
            expected_version=manifest.get("version") if manifest.get("schema") == 2 else None,
            expected_storage="local" if manifest["storage"] == "local-volume" else "s3",
        )
    except Exception:
        # Do not leave an unverified installation reachable from the outside.
        # The partial target is left for forensic recovery, never auto-reused.
        for svc in ("nginx", "admin", "api"):
            try:
                compose(project, env_file, "stop", "-t", "10", svc)
            except Exception:
                pass
        raise
    outcome["applicationVerified"] = True
    return outcome


def ready(url: str, *, expected_version: str | None = None, expected_storage: str | None = None) -> bool:
    validate_ready_url(url)
    try:
        with urlopen(url, timeout=4) as response:
            if response.status != 200:
                return False
            value = json.load(response)
            return (isinstance(value, dict) and value.get("status") == "ready"
                    and (expected_version is None or value.get("version") == expected_version)
                    and (expected_storage is None or value.get("storage") == expected_storage)
                    and (expected_storage is None or value.get("repository") == "postgres"))
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return False


def await_readiness(url: str, expected: bool, limit=90, **checks) -> float:
    start = time.monotonic()
    while time.monotonic() - start <= limit:
        if ready(url, **checks) == expected:
            return round(time.monotonic() - start, 3)
        time.sleep(1)
    raise DrillError(f"/ready did not reach expected state after {limit}s")


def chaos(
    project: str, env_file: Path, url: str, confirm: str, network_ha: bool
) -> dict:
    ensure_isolated(project, confirm)
    if not (
        url.startswith("http://127.0.0.1:") or url.startswith("http://localhost:")
    ) or not url.endswith("/ready"):
        raise DrillError("chaos readiness URL must be loopback /ready")
    await_readiness(url, expected=True, limit=30)
    outcomes = []
    for svc in ("postgres", "redis") if network_ha else ("postgres",):
        down_start = time.monotonic()
        try:
            compose(project, env_file, "stop", "-t", "5", svc)
            # Loss of DB must fail closed; Redis is mandatory in network-ha.
            down_sec = await_readiness(url, expected=False, limit=35)
        finally:
            compose(project, env_file, "up", "-d", svc)
        up_sec = await_readiness(url, expected=True, limit=120)
        outcomes.append(
            {
                "service": svc,
                "failClosedSeconds": down_sec,
                "recoverySeconds": up_sec,
                "totalSeconds": round(time.monotonic() - down_start, 3),
            }
        )
    try:
        compose(project, env_file, "kill", "api")
        compose(project, env_file, "stop", "-t", "1", "api")
        await_readiness(url, expected=False, limit=25)
    finally:
        compose(project, env_file, "up", "-d", "api")
    outcomes.append(
        {
            "service": "api",
            "recoverySeconds": await_readiness(url, expected=True, limit=120),
        }
    )
    return {
        "status": "measured",
        "project": project,
        "mode": "network-ha" if network_ha else "standard",
        "events": outcomes,
        "haDisclaimer": "single-node recovery and readiness; does not establish backend HA",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["backup", "verify", "restore-fresh", "chaos"]
    )
    parser.add_argument("--project", help="isolated docker compose project, nl-dr-*")
    parser.add_argument("--confirm", help="exact project name required for mutation")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--ready-url")
    parser.add_argument("--network-ha", action="store_true")
    parser.add_argument("--s3-source-bucket")
    parser.add_argument("--target-s3-bucket")
    parser.add_argument("--s3-endpoint")
    parser.add_argument("--world-backup", action="append", default=[],
                        metavar="NAME=/absolute/path/backup-id",
                        help="previously stopped, verified Go CLI world backup on operator's mounted filesystem")
    parser.add_argument("--world-destination", action="append", default=[],
                        metavar="NAME=/absolute/fresh/server-root",
                        help="fresh host-mounted destination; never auto-starts the game JVM")
    parser.add_argument(
        "--production-source",
        action="store_true",
        help="allow backup on explicitly approved maintenance-window source",
    )
    parser.add_argument(
        "--production-target",
        action="store_true",
        help="allow restore to explicitly approved fresh target; does not overwrite",
    )
    parser.add_argument(
        "--maintenance-approved",
        action="store_true",
        help="explicit operator acknowledgement: all writers fenced, downtime approved",
    )
    args = parser.parse_args()
    if args.network_ha:
        COMPOSE_FILES.append(ROOT / "deploy/production/docker-compose.network-ha.yml")
        COMPOSE_PROFILES.append("network-ha")
    try:
        world_backups = parse_world_args(args.world_backup)
        world_destinations = parse_world_args(args.world_destination)
        if args.network_ha and args.action == "backup" and world_destinations:
            raise DrillError("world destinations are only valid for restore-fresh")
        if args.network_ha and args.action == "restore-fresh" and world_backups:
            raise DrillError("world backups are only valid for backup")
        if not args.network_ha and (world_backups or world_destinations):
            raise DrillError("world recovery requires --network-ha")
        if args.network_ha and args.action == "backup" and not args.s3_source_bucket:
            raise DrillError("network-ha backup requires --s3-source-bucket")
        if args.action == "restore-fresh" and not args.ready_url:
            raise DrillError("restore-fresh requires --ready-url to verify the actual backend")
        if args.action == "verify":
            verified = verify_snapshot(args.snapshot)
            pg_validate(args.snapshot / "database.dump")
            report = {"status": "verified", "postgresArchiveChecked": True, "manifest": verified}
        else:
            if not args.project or not args.env_file:
                raise DrillError("project and env-file required")
            if args.action == "backup":
                report = snapshot(
                    args.project,
                    args.env_file,
                    args.snapshot,
                    args.confirm or "",
                    args.s3_source_bucket,
                    args.s3_endpoint,
                    args.production_source,
                    args.maintenance_approved,
                    world_backups,
                )
            elif args.action == "restore-fresh":
                report = restore_fresh(
                    args.project,
                    args.env_file,
                    args.snapshot,
                    args.confirm or "",
                    args.ready_url,
                    args.target_s3_bucket,
                    args.s3_endpoint,
                    args.production_target,
                    args.maintenance_approved,
                    world_destinations,
                )
            else:
                if not args.ready_url:
                    raise DrillError("--ready-url required")
                report = chaos(
                    args.project,
                    args.env_file,
                    args.ready_url,
                    args.confirm or "",
                    args.network_ha,
                )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except (
        DrillError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
        KeyError,
    ) as exc:
        print(
            json.dumps({"status": "failed", "reason": str(exc)[:160]}), file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
