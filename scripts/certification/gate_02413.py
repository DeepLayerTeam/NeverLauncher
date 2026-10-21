#!/usr/bin/env python3
"""Fail-closed certification report for 0.24.13. Never synthesizes test evidence.

Actual Minecraft client launch and the exact six-target platform matrix are
mandatory for certification. Missing or failed checks remain INCOMPLETE/FAILED.
This JSON does not replace separately signed clean-machine GA attestations.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys

REQUIRED_TARGETS = frozenset(f"{os}-{arch}" for os in ("windows", "linux", "macos")
                             for arch in ("x86_64", "aarch64"))
REQUIRED_CHECKS = ("signed-install", "preset-isolation", "ownership", "wrong-key", "signature-tamper")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def read_report(path: Path) -> tuple[dict, str]:
    blob = path.read_bytes()
    if len(blob) > 1024 * 1024:
        raise ValueError("oversized evidence report")
    doc = json.loads(blob)
    if not isinstance(doc, dict):
        raise ValueError("invalid evidence document")
    return doc, hashlib.sha256(blob).hexdigest()


def aggregate(paths: list[Path], *, expected_commit: str) -> dict:
    if not _SHA.fullmatch(expected_commit):
        raise ValueError("a full, exact 40-character Git commit is required")
    result = {"schemaVersion": "1.0", "version": "0.24.13", "commit": expected_commit,
              "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "status": "incomplete",
              "platforms": {}, "unmetGates": []}
    unmet = result["unmetGates"]
    for path in paths:
        report, digest = read_report(path)
        target = report.get("target")
        if target not in REQUIRED_TARGETS or target in result["platforms"]:
            raise ValueError(f"duplicate or unsupported target: {target}")
        if report.get("schemaVersion") != "1.0" or report.get("version") != "0.24.13":
            raise ValueError(f"unexpected certification schema/version for {target}")
        if report.get("commit") != expected_commit or report.get("gitTreeClean") is not True:
            unmet.append(f"{target}: not clean source for expected commit")
        native = report.get("nativeComponents") or {}
        tests = native.get("tests") or []
        if (native.get("status") != "passed" or native.get("target") != target or
            native.get("signedManifestVersion") != "3.0" or native.get("catalogSchema") != "5.0" or
            not set(REQUIRED_CHECKS).issubset(tests) or not isinstance(native.get("httpRequests"), int) or
            native["httpRequests"] < 1):
            unmet.append(f"{target}: native signed components certification missing/failed")
        # Linux/macOS and Windows guard modes are not interchangeable.
        required = ("rustUnitTests", "goModelTests", "faultInjection", "neverGuard", "serverBridgePolicy")
        for check in required:
            if (report.get("checks") or {}).get(check) != "passed":
                unmet.append(f"{target}: {check} missing/failed")
        minecraft = report.get("minecraft") or {}
        if (minecraft.get("status") != "passed" or minecraft.get("target") != target or
            minecraft.get("actualClient") is not True or minecraft.get("loader") not in
            ("vanilla", "fabric", "quilt", "forge", "neoforge") or
            not isinstance(minecraft.get("evidenceSha256"), str) or
            not re.fullmatch(r"[a-f0-9]{64}", minecraft["evidenceSha256"])):
            unmet.append(f"{target}: actual Minecraft client launch evidence missing/failed")
        result["platforms"][target] = {"sourceArtifactSha256": digest,
                                       "componentStatus": native.get("status"),
                                       "minecraftStatus": minecraft.get("status")}
    for target in sorted(REQUIRED_TARGETS - result["platforms"].keys()):
        unmet.append(f"{target}: platform evidence not supplied")
    result["status"] = "passed" if not unmet else "incomplete"
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("reports", nargs="*", type=Path)
    args = ap.parse_args()
    try:
        report = aggregate(args.reports, expected_commit=args.commit)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        report = {"status": "failed", "error": str(exc), "unmetGates": ["invalid certification evidence"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"0.24.13 certification: {report['status']}; unmet={len(report['unmetGates'])}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
