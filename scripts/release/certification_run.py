#!/usr/bin/env python3
"""Run-scoped provenance for executed RC and GA checks.

For 0.36.2+ a passed JSON receipt from a previous run, even at the same
commit, cannot certify the current attempt. This is *not* an operator
signature or a substitute for the independent exact-byte GA approval.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import os
import re
import subprocess
from pathlib import Path
from typing import Mapping

SCHEMA = "launcher.certification-run.v1"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MAX_AGE = timedelta(hours=6)


class CertificationBlocked(ValueError):
    pass


def required(version: str) -> bool:
    from release_policy import parsed

    number, _ = parsed(version)
    return number >= (0, 36, 2)


def _positive(value: str, name: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise CertificationBlocked(
            f"missing or invalid {name}; current CI execution is required"
        )
    return int(value)


def _timestamp(value: str) -> datetime:
    try:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError("not a UTC timestamp")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("missing timezone")
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise CertificationBlocked("invalid certification execution timestamp") from exc


def identity(
    version: str,
    commit: str,
    env: Mapping[str, str] | None = None,
    *,
    root: Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Stamp only a freshly executed test runner after successful execution."""
    if not required(version):
        return {}
    env = os.environ if env is None else env
    commit = commit.lower()
    if not COMMIT.fullmatch(commit) or env.get("GITHUB_SHA", "").lower() != commit:
        raise CertificationBlocked(
            "current GitHub source commit does not match certification"
        )
    if root is not None:
        head = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if head.returncode or head.stdout.strip().lower() != commit:
            raise CertificationBlocked("checkout HEAD differs from current CI commit")
        version_in_checkout = (root / "VERSION").read_text(encoding="utf-8").strip()
        if version_in_checkout != version:
            raise CertificationBlocked("checkout VERSION differs from certification")
    repository = env.get("GITHUB_REPOSITORY", "")
    if not REPO.fullmatch(repository):
        raise CertificationBlocked("current GitHub repository identity required")
    run_id = _positive(env.get("GITHUB_RUN_ID", ""), "GITHUB_RUN_ID")
    attempt = _positive(env.get("GITHUB_RUN_ATTEMPT", ""), "GITHUB_RUN_ATTEMPT")
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {
        "schema": SCHEMA,
        "version": version,
        "commit": commit,
        "repository": repository,
        "runId": str(run_id),
        "runAttempt": attempt,
        "generatedAt": moment.isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def verify(
    doc: dict,
    version: str,
    commit: str,
    env: Mapping[str, str] | None = None,
    *,
    now: datetime | None = None,
) -> None:
    if not required(version):
        return
    expected = identity(version, commit, env, now=now)
    received = doc.get("certificationRun")
    if not isinstance(received, dict) or set(received) != set(expected):
        raise CertificationBlocked(
            "missing or malformed current-run certification identity"
        )
    for field in expected:
        if field != "generatedAt" and received[field] != expected[field]:
            raise CertificationBlocked(
                f"certification belongs to a different run: {field}"
            )
    stamp = _timestamp(received["generatedAt"])
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if not timedelta(0) <= current - stamp <= MAX_AGE:
        raise CertificationBlocked(
            "historical, future-dated or expired certification is not fresh"
        )
