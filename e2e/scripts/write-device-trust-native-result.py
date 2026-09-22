#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

TEST_MARKERS = {
    "deviceKeyUnitTests": ["storage_username_is_scoped_by_backend_and_user", "hardware_backend_classification_is_fail_closed"],
    "generationScopedHardwareLabels": ["hardware_generation_labels_are_scoped_and_rotate"],
    "replacementPayloadValidation": ["replacement_payload_is_canonical_and_user_scoped"],
    "refreshPayloadBinding": ["refresh_payload_binds_session_device_epoch_and_token_hash_without_token_disclosure"],
    "attestationPayloadValidation": ["attestation_payload_is_hardware_only_and_identity_bound"],
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Create machine-verifiable native Device Trust result")
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--os", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text = args.log.read_text(encoding="utf-8", errors="replace")
    checks = {"tauriCompile": "test result: ok." in text}
    for check, markers in TEST_MARKERS.items():
        checks[check] = all(marker in text for marker in markers)
    failed = [name for name, ok in checks.items() if not ok]
    payload = {
        "schemaVersion": "1.0",
        "productVersion": VERSION,
        "targetId": args.target_id,
        "kind": "native-tests",
        "os": args.os,
        "arch": args.arch,
        "runtimeArch": platform.machine().lower() or "unknown",
        "commit": args.commit,
        "runId": args.run_id,
        "status": "passed" if not failed else "failed",
        "exitCode": 0 if not failed else 1,
        "checks": checks,
        "evidence": {
            "files": [args.log.name],
            "sha256": {args.log.name: hashlib.sha256(args.log.read_bytes()).hexdigest()},
        },
        "limitations": ["headless-ci-does-not-prove-os-secure-storage-runtime"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if failed:
        raise SystemExit("native Device Trust evidence missing checks: " + ", ".join(failed))
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
