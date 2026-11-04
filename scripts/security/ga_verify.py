#!/usr/bin/env python3
"""Fail-closed GA signoff for exact-source, independently signed live evidence.

This *verifies* reports; it cannot manufacture hardware/OS evidence. The signing
private key is held by the release security approver, never by build/test jobs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import certify_03114 as prior

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = b"Launcher-0.32.0-security-evidence-v1\n"
SCHEMA = "launcher/security-certification/0320"
TIERS = {
    "offline",
    "backend-security",
    "linux-live",
    "windows-live",
    "macos-live",
    "hardware-live",
    "compatibility-live",
}
# The first four tiers must contain actual named Go test results. Human/live
# signoffs must contain individually identified successful procedures, not a
# single unqualified PASS string.
REQUIRED = {
    "offline": {
        "./internal/linuxsandbox",
        "./internal/attestverify",
        "./internal/extensionpolicy",
        "./internal/extensionbroker",
        "./internal/extensionhost",
        "./internal/trustbaseline",
        "./internal/macossandbox",
    },
    "backend-security": {"./internal/httpapi"},
    "linux-live": {"./internal/linuxsandbox"},
    "windows-live": {"./internal/windowssandbox"},
}
EXPECTED_TESTS = {
    "offline": {
        **prior.OFFLINE,
        "./internal/linuxsandbox": list(prior.OFFLINE["./internal/linuxsandbox"])
        + ["TestGACgroupKillMandatory0320", "TestGAConcurrentIPCListenerShutdown0320"],
    },
    "backend-security": prior.BACKEND_SECURITY,
    "linux-live": prior.LINUX_LIVE,
    "windows-live": {
        **prior.WINDOWS_LIVE,
        "./internal/windowssandbox": list(
            prior.WINDOWS_LIVE["./internal/windowssandbox"]
        )
        + ["TestGAInheritedHandlesWhitelisted0320"],
    },
}
MANUAL = {
    "macos-live": {
        "macos-signed-helper",
        "macos-unsupported-isolation-rejected",
        "macos-no-trusted-fallback",
    },
    "hardware-live": {
        "windows-physical-tpm-certify",
        "linux-physical-tpm-certify",
        "tpm-wrong-key-replay-epoch",
        "tpm-root-revocation",
        "physical-pcr-quote-policy",
        "guard-session-join-rejection",
        "guard-attach-injection-boundaries",
    },
    "compatibility-live": {
        "ordinary-overlay",
        "accessibility",
        "antivirus-edr",
        "developer-debugger",
    },
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def unique_json(raw: bytes) -> dict:
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"duplicate JSON key: {k}")
            d[k] = v
        return d

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("evidence must be object")
    return value


def verify_evidence(
    path: Path, key: Ed25519PublicKey, *, commit: str, source_sha: str, now: dt.datetime
) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError(f"evidence not ordinary/small: {path}")
    sig_path = Path(str(path) + ".sig")
    if sig_path.is_symlink() or not sig_path.is_file() or sig_path.stat().st_size > 512:
        raise ValueError(f"missing detached signature: {path}")
    raw = path.read_bytes()
    try:
        signature = bytes.fromhex(sig_path.read_text("ascii").strip())
        if len(signature) != 64:
            raise ValueError("invalid signature size")
        key.verify(signature, DOMAIN + raw)
    except (InvalidSignature, ValueError) as e:
        raise ValueError(f"invalid evidence signature: {path}") from e
    doc = unique_json(raw)
    tier = doc.get("tier")
    if tier not in TIERS:
        raise ValueError(f"unexpected tier: {tier}")
    if doc.get("schema") != SCHEMA:
        raise ValueError(f"{tier}: invalid evidence schema")
    if doc.get("status") != "PASS" or doc.get("sourceSha256") != source_sha:
        raise ValueError(f"{tier}: status or source fingerprint mismatch")
    if doc.get("commit") != commit or doc.get("productVersion") != "0.32.0":
        raise ValueError(f"{tier}: not bound to exact release commit/version")
    try:
        when = dt.datetime.fromisoformat(doc["generatedAt"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"{tier}: invalid timestamp") from e
    if when.tzinfo is None or not dt.timedelta(0) <= now - when <= dt.timedelta(days=7):
        raise ValueError(f"{tier}: stale or future evidence")
    host = doc.get("host")
    if (
        not isinstance(host, dict)
        or not host.get("system")
        or not host.get("architecture")
    ):
        raise ValueError(f"{tier}: missing host identity")
    if (
        tier == "linux-live"
        and host["system"] != "Linux"
        or tier == "windows-live"
        and host["system"] != "Windows"
        or tier == "macos-live"
        and host["system"] != "Darwin"
    ):
        raise ValueError(f"{tier}: evidence from wrong OS")
    results = doc.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError(f"{tier}: no test evidence")
    if tier in REQUIRED:
        seen = set()
        for result in results:
            if (
                not isinstance(result, dict)
                or result.get("status") != "PASS"
                or result.get("exitCode") != 0
            ):
                raise ValueError(f"{tier}: failed or skipped executable package")
            package = result.get("package")
            if package in seen or package not in REQUIRED[tier]:
                raise ValueError(f"{tier}: duplicate/unknown test package {package}")
            seen.add(package)
            required = result.get("required")
            if (
                not isinstance(required, dict)
                or set(required) != set(EXPECTED_TESTS[tier][package])
                or any(v != "PASS" for v in required.values())
            ):
                raise ValueError(f"{tier}: missing passing named tests")
        if seen != REQUIRED[tier]:
            raise ValueError(
                f"{tier}: missing mandatory packages {REQUIRED[tier] - seen}"
            )
    else:
        checks = {}
        for result in results:
            if not isinstance(result, dict):
                raise ValueError(f"{tier}: malformed live check")
            name = result.get("name")
            if name in checks or name not in MANUAL[tier]:
                raise ValueError(f"{tier}: duplicate/unknown live check {name}")
            if (
                result.get("status") != "PASS"
                or result.get("simulated") is not False
                or result.get("actualExecution") is not True
            ):
                raise ValueError(f"{tier}: unverified or simulated check {name}")
            if not isinstance(result.get("evidenceSha256"), str) or not HEX64.fullmatch(
                result["evidenceSha256"]
            ):
                raise ValueError(f"{tier}: missing external audit-log hash for {name}")
            checks[name] = result
        if set(checks) != MANUAL[tier]:
            raise ValueError(
                f"{tier}: missing live scenarios: {MANUAL[tier] - set(checks)}"
            )
    return {"tier": tier, "sha256": hashlib.sha256(raw).hexdigest(), "status": "PASS"}


def verify_all(
    paths: list[Path],
    key_hex: str,
    commit: str,
    source_sha: str,
    now: dt.datetime | None = None,
) -> dict:
    if (
        not HEX64.fullmatch(key_hex)
        or not HEX40.fullmatch(commit)
        or not HEX64.fullmatch(source_sha)
    ):
        raise ValueError(
            "32-byte trusted Ed25519 key, exact 40-digit git SHA and source fingerprint required"
        )
    if len(paths) != len(TIERS):
        raise ValueError("seven independent signed tiers required")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    now = now or dt.datetime.now(dt.timezone.utc)
    results = [
        verify_evidence(p, key, commit=commit, source_sha=source_sha, now=now)
        for p in paths
    ]
    tiers = [r["tier"] for r in results]
    if set(tiers) != TIERS or len(set(tiers)) != len(tiers):
        raise ValueError("missing or duplicated mandatory tiers")
    return {
        "schema": "launcher.ga.device-guard-isolation.v1",
        "version": "0.32.0",
        "commit": commit,
        "sourceSha256": source_sha,
        "status": "PASS",
        "tiers": sorted(results, key=lambda r: r["tier"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", nargs="+", type=Path, required=True)
    parser.add_argument("--trusted-public-key", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_all(
            args.evidence, args.trusted_public_key, args.commit, args.source_sha256
        )
    except (OSError, ValueError, InvalidSignature, UnicodeError) as e:
        result = {
            "schema": "launcher.ga.device-guard-isolation.v1",
            "status": "BLOCKED",
            "reason": str(e),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(f"Launcher 0.32.0 security GA: {result['status']}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
