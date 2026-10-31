"""Trusted-host-only diagnostic retention. Export raw runner stdout.

Diagnostics are not certification: the attestor signs separately verified
runtime artifacts; this spool only retains redacted operational logs.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re

_SECRET = [
    re.compile(
        r'(?i)(["\'](?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|secret|api[_-]?key|session[_-]?id|account[_-]?id|player[_-]?name|username|uuid|xuid)["\']\s*:\s*["\'])[^"\']+'
    ),
    re.compile(r'(?i)(\b(?:authorization\s*:\s*bearer|bearer)\s+)[^\s,;"\'<>]+'),
    re.compile(
        r'(?i)(\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|api[_-]?key|session[_-]?id|credentials|authorization|account[_-]?id|player[_-]?name|username|uuid|xuid)\b\s*[=:]\s*["\']?)[^\s,;"\'&<>]+'
    ),
    re.compile(
        r'(?i)(--(?:accessToken|clientToken|refreshToken|password|username|uuid|session|authorization)\s+)[^\s,;"\'<>]+'
    ),
    re.compile(
        r'(?i)(-D[^\s=]*(?:token|password|secret|key|session)[^\s=]*=)[^\s,;"\'<>]+'
    ),
    re.compile(
        r'(?i)([?&](?:access_token|refresh_token|token|code|password|secret|session)=)[^\s&"\'<>]+'
    ),
]
_IDENT = [
    re.compile(
        r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
    ),
    re.compile(r"(?i)\b[0-9a-f]{32}\b"),
    re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"),
]


def redact(text: str) -> str:
    for pattern in _SECRET:
        text = pattern.sub(lambda match: match.group(1) + "[REDACTED]", text)
    for pattern in _IDENT:
        text = pattern.sub("[IDENTIFIER]", text)
    return text


def prune(folder: Path, now: datetime):
    """Expire only files created by this service, follow symlinks."""
    for path in folder.iterdir():
        if path.is_symlink() or not re.fullmatch(
            r"[a-f0-9]{48}\.(?:log|json)", path.name
        ):
            continue
        try:
            if path.is_file() and datetime.fromtimestamp(
                path.stat().st_mtime, timezone.utc
            ) < now - timedelta(days=31):
                path.unlink()
            elif path.suffix == ".json":
                metadata = json.loads(path.read_text(encoding="utf-8"))
                if (
                    datetime.fromisoformat(metadata["expiresAt"].replace("Z", "+00:00"))
                    <= now
                ):
                    path.unlink()
                    sibling = path.with_suffix(".log")
                    if sibling.is_file() and not sibling.is_symlink():
                        sibling.unlink()
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            pass


def retain(
    worker_log: Path, directory: Path, run_id: str, ttl_hours: int = 168
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{48}", run_id):
        raise ValueError("invalid diagnostic run id")
    if not 1 <= ttl_hours <= 720:
        raise ValueError("diagnostic ttl must be 1..720 hours")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError("diagnostic directory must be host-owner-only")
    now = datetime.now(timezone.utc)
    prune(directory, now)
    # Bound total retained log size to 2 MiB. Read past this limit.
    with worker_log.open("rb") as raw:
        content = raw.read(2 * 1024 * 1024)
    sanitized = redact(content.decode("utf-8", "replace")).encode("utf-8")
    # Write with O_EXCL+O_NOFOLLOW to avoid replacing existing evidence/logs.
    destination = directory / (run_id + ".log")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(sanitized)
    digest = hashlib.sha256(sanitized).hexdigest()
    meta = {
        "runId": run_id,
        "sha256": digest,
        "size": len(sanitized),
        "createdAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + timedelta(hours=ttl_hours))
        .isoformat()
        .replace("+00:00", "Z"),
    }
    metadata = directory / (run_id + ".json")
    fd = os.open(metadata, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(meta, output, sort_keys=True)
    return meta
