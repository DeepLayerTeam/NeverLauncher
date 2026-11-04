#!/usr/bin/env python3
"""Fail-closed verifier for independently signed Launcher 0.26.0 GA evidence.

This tool NEVER generates or signs release attestations. Passing unit tests,
self-reported JSON or a successful simulated login do not certify a release.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

VERSION = "0.26.0"
SCHEMA = "launcher.textures.ga.v1"
DOMAIN = b"Launcher-Textures-GA-0.26.0-v1\n"
TARGETS = {
    f"{os}-{arch}"
    for os in ("linux", "windows", "darwin")
    for arch in ("amd64", "arm64")
}
REQUIRED_REPORTS = {
    "gameplay": (
        "clientStarted",
        "remoteObserverSawSkin",
        "classic",
        "slim",
        "cape",
        "cacheInvalidation",
    ),
    "official": (
        "microsoftOwned",
        "officialProfileVerified",
        "localIdentityIsolated",
        "skinUploadReset",
        "ownedCapeOnly",
    ),
    "backend": (
        "postgresql17",
        "realS3",
        "snapshotRestored",
        "gcRace",
        "gravitMigration",
        "signedTextures",
        "ssrfBlocked",
        "foreignUUIDBlocked",
    ),
    "desktop": (
        "nativeAppStarted",
        "skin2D",
        "skin3D",
        "cape3D",
        "progressCancel",
        "permissionFailures",
    ),
    "installer": (
        "builtFromSource",
        "osSignatureVerified",
        "cleanMachineInstall",
        "rollbackTested",
    ),
}
LOADER_SET = {"vanilla", "fabric", "neoforge"}
SHA = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")


class GateError(ValueError):
    pass


def strict_json(data: bytes) -> dict:
    def no_duplicate(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise GateError(f"duplicate JSON key: {k}")
            out[k] = v
        return out

    value = json.loads(data, object_pairs_hook=no_duplicate)
    if type(value) is not dict:
        raise GateError("report is not an object")
    return value


def read_file(
    base: Path,
    name: str,
    *,
    limit: int,
    expected: str | None = None,
    retain: bool = True,
) -> bytes:
    if (
        not name
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or Path(name).name != name
    ):
        raise GateError("unsafe evidence filename")
    if base.is_symlink():
        raise GateError("symlinked evidence directory")
    path = base / name
    if path.is_symlink() or not path.is_file():
        raise GateError(f"missing or unsafe evidence file: {path}")
    if path.stat().st_size > limit:
        raise GateError(f"oversized evidence file: {path}")
    hasher = hashlib.sha256()
    output = bytearray()
    size = 0
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            size += len(block)
            if size > limit:
                raise GateError(f"oversized evidence file: {path}")
            hasher.update(block)
            if retain:
                output.extend(block)
    if expected is not None and (
        not SHA.fullmatch(expected) or hasher.hexdigest() != expected
    ):
        raise GateError(f"evidence SHA-256 mismatch: {path}")
    return bytes(output)


def check_report(report: dict, name: str, target: str, commit: str) -> None:
    if (
        report.get("schemaVersion") != f"launcher.textures.ga.{name}.v1"
        or report.get("productVersion") != VERSION
        or report.get("commit") != commit
        or report.get("target") != target
        or report.get("status") != "passed"
        or report.get("actualExecution") is not True
        or report.get("simulated") is not False
        or report.get("mocked") is not False
    ):
        raise GateError(f"{target}/{name}: not a matching real execution report")
    for check in REQUIRED_REPORTS[name]:
        if report.get(check) is not True:
            raise GateError(f"{target}/{name}: {check} was not verified")
    if name == "gameplay":
        loaders = report.get("loaders")
        if not isinstance(loaders, list) or not LOADER_SET.issubset(
            set(str(v) for v in loaders)
        ):
            raise GateError(
                f"{target}/gameplay: required real Minecraft loaders missing"
            )
    if name == "installer" and not report.get("trustedOSSigner"):
        raise GateError(f"{target}/installer: trusted OS signing identity missing")


def verify_target(
    folder: Path, target: str, key: Ed25519PublicKey, commit: str
) -> dict:
    raw = read_file(folder, "attestation.json", limit=1024 * 1024)
    signature_hex = (
        read_file(folder, "attestation.sig", limit=256).decode("ascii").strip()
    )
    if not re.fullmatch(r"[0-9a-f]{128}", signature_hex):
        raise GateError(f"{target}: invalid Ed25519 signature encoding")
    try:
        key.verify(bytes.fromhex(signature_hex), DOMAIN + raw)
    except InvalidSignature as exc:
        raise GateError(f"{target}: untrusted or altered signed attestation") from exc
    data = strict_json(raw)
    if (
        data.get("schemaVersion") != SCHEMA
        or data.get("productVersion") != VERSION
        or data.get("commit") != commit
        or data.get("target") != target
        or data.get("status") != "passed"
        or data.get("actualExecution") is not True
        or data.get("sourceTreeClean") is not True
    ):
        raise GateError(f"{target}: release identity/status mismatch")
    try:
        recorded = datetime.fromisoformat(data["recordedAt"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError) as exc:
        raise GateError(f"{target}: missing recordedAt timestamp") from exc
    age = (
        (datetime.now(timezone.utc) - recorded).total_seconds()
        if recorded.tzinfo
        else -1
    )
    if age < -300 or age > 60 * 60 * 24 * 90:
        raise GateError(f"{target}: stale or future evidence")
    reports = data.get("reports")
    if not isinstance(reports, dict) or set(reports) != set(REQUIRED_REPORTS):
        raise GateError(f"{target}: missing mandatory evidence report")
    for name, info in reports.items():
        if not isinstance(info, dict) or set(info) != {"file", "sha256"}:
            raise GateError(f"{target}/{name}: invalid report descriptor")
        report = strict_json(
            read_file(
                folder, info["file"], expected=info["sha256"], limit=2 * 1024 * 1024
            )
        )
        check_report(report, name, target, commit)
    # An actual release installer must be present, digest-bound to the signed
    # attestation, and carry separately verified native OS signature evidence.
    installer = data.get("releaseArtifact")
    if not isinstance(installer, dict) or set(installer) != {"file", "sha256"}:
        raise GateError(f"{target}: release installer missing")
    read_file(
        folder,
        installer["file"],
        expected=installer["sha256"],
        limit=4 * 1024 * 1024 * 1024,
        retain=False,
    )
    return {
        "target": target,
        "installerSha256": installer["sha256"],
        "reports": sorted(reports),
    }


def verify(evidence: Path, commit: str, trusted_public_key: str) -> dict:
    if not COMMIT.fullmatch(commit):
        raise GateError("expected Git commit must be 40 lowercase hex digits")
    if not re.fullmatch("[a-f0-9]{64}", trusted_public_key):
        raise GateError("trusted independent Ed25519 public key must be 32-byte hex")
    if evidence.is_symlink() or not evidence.is_dir():
        raise GateError("missing/unsafe evidence directory")
    found = {p.name for p in evidence.iterdir()}
    if found != TARGETS:
        raise GateError(
            f"GA requires exactly six independent targets; missing={sorted(TARGETS - found)} extra={sorted(found - TARGETS)}"
        )
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key))
    checked = [
        verify_target(evidence / target, target, key, commit)
        for target in sorted(TARGETS)
    ]
    return {
        "schemaVersion": "launcher.textures.ga.verdict.v1",
        "status": "passed",
        "productVersion": VERSION,
        "commit": commit,
        "targets": checked,
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description="Verify external signed real-world texture GA evidence"
    )
    p.add_argument("--evidence", required=True, type=Path)
    p.add_argument("--commit", required=True)
    p.add_argument("--trusted-public-key", required=True)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    try:
        result = verify(args.evidence, args.commit, args.trusted_public_key)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print("Accepted independent signed GA evidence for all six platforms")
        return 0
    except (GateError, ValueError, OSError, json.JSONDecodeError, UnicodeError) as exc:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(
                {
                    "schemaVersion": "launcher.textures.ga.verdict.v1",
                    "status": "incomplete",
                    "productVersion": VERSION,
                    "reason": str(exc),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"0.26.0 GA NOT CERTIFIED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
