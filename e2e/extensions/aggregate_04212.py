#!/usr/bin/env python3
"""Reject incomplete, mislabeled or stale platform evidence for extension E2E."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

TARGETS = (
    "linux-x64",
    "linux-arm64",
    "windows-x64",
    "windows-arm64",
    "macos-x64",
    "macos-arm64",
)
CASES = ("java-host", "java-runtime", "java-lifecycle", "gravit-port")


def validate(folder, source_commit, version, run_id, run_attempt):
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", source_commit):
        raise ValueError("invalid source commit")
    if not version or not run_id or not run_attempt:
        raise ValueError("version, CI run ID and attempt are mandatory")
    folder = Path(folder)
    present = {p.stem for p in folder.glob("*.json")}
    # The final certificate is downloaded into this same directory by Actions.
    # Never treat it as a seventh platform; reject every other unexpected JSON.
    present.discard("extension-acceptance-certificate")
    if present != set(TARGETS):
        raise ValueError(
            f"platform evidence missing or unexpected: {sorted(set(TARGETS) - present)} / {sorted(present - set(TARGETS))}"
        )
    result = {}
    for name in TARGETS:
        report = json.loads((folder / f"{name}.json").read_text())
        if (
            report.get("target") != name
            or report.get("version") != version
            or report.get("status") != "pass"
            or report.get("sourceCommit") != source_commit
            or report.get("runId") != run_id
            or report.get("runAttempt") != run_attempt
        ):
            raise ValueError(
                f"{name}: invalid status, version, source commit or CI run identity"
            )
        if tuple(map(int, version.split("."))) >= (0, 43, 0):
            audit = report.get("gravitMatrixAudit", {})
            matrix_sha = hashlib.sha256(
                (
                    Path(__file__).resolve().parents[2]
                    / "compatibility/gravit/module-parity-04211.json"
                ).read_bytes()
            ).hexdigest()
            if (
                audit.get("status") != "source-verified-not-equivalent"
                or audit.get("modules") != 19
                or audit.get("sha256") != matrix_sha
            ):
                raise ValueError(f"{name}: Gravit 19-module executable audit missing")
        checks = report.get("checks")
        if not isinstance(checks, dict) or set(checks) != set(CASES):
            raise ValueError(f"{name}: incomplete executable tests")
        for case, check in checks.items():
            if check.get("runtime") != "pass" or not re.fullmatch(
                "[0-9a-f]{64}", check.get("jarSha256", "")
            ):
                raise ValueError(f"{name}/{case}: unverified JVM execution")
            if case in ("java-host", "gravit-port"):
                signature = check.get("signing", {})
                if (
                    not re.fullmatch("[0-9a-f]{64}", signature.get("sha256", ""))
                    or signature.get("wrongKeyDenied") is not True
                    or signature.get("tamperDenied") is not True
                ):
                    raise ValueError(
                        f"{name}/{case}: signed package negative tests absent"
                    )
        result[name] = {
            "status": "pass",
            "checks": len(checks),
            "evidenceSha256": hashlib.sha256(
                (folder / f"{name}.json").read_bytes()
            ).hexdigest(),
            "jars": {
                case: check["jarSha256"] for case, check in sorted(checks.items())
            },
        }
    return {
        "schemaVersion": "launcher.extensions.acceptance.v1",
        "version": version,
        "sourceCommit": source_commit,
        "runId": run_id,
        "runAttempt": run_attempt,
        "status": "pass",
        "platforms": result,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence-dir", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-attempt", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = validate(
            args.evidence_dir, args.commit, args.version, args.run_id, args.run_attempt
        )
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"extension E2E certification BLOCKED: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("PASS: six real JVM target results and signed-package negative checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
