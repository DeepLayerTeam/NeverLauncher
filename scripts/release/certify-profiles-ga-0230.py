#!/usr/bin/env python3
"""Fail-closed profile/workspace GA certification against actual executables and PostgreSQL.

This is not a substitute for the cross-platform signed release bundle. A run
must exercise real Go tests (including a database), not rely on a generated
manifest or inspect source text for test names.
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

ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ("profile-v2-gravit-and-file-rules", "services/api", "./internal/model", (
        "TestProfileV2DeterministicSnapshots",
        "TestFileOwnershipRules0224",
        "TestFileOwnershipSigningCompatibility0224",
        "TestRuntimeConstraints0223RejectsUnsafeLaunch",
        "TestGravitImportReadyWorkspaceSettings02210",
        "TestGravitImportFailClosed02210",
        "TestGravitImportDeterministicAndNoSourceSecrets02210",
    )),
    ("workspace-and-channel-cas", "services/api", "./internal/repository", (
        "TestGAWorkspaceImmutabilityAndStateMachine0230",
        "TestGAWorkspaceParallelRevisionCAS0230",
        "TestGravitAtomicImportMemory02210",
        "TestGravitAtomicImportConcurrent02210",
        "TestChannelHeadCASPublishAndRead0228",
        "TestGAWorkspacePostgresCASAndAtomicImport0230",
    )),
    ("workspace-http-materialize", "services/api", "./internal/httpapi", (
        "TestBuildWorkspaceDirectoryStageAndMaterialize0226",
        "TestGAHTTPGravitPreviewCommitAndConflict0230",
        "TestDesktopProfileServers0229ScopeAndPublicResponse",
    )),
    ("client-update-and-repair", "cli", "./cmd/neverlauncher", (
        "TestManifestUpdaterPreservesUserData0224",
        "TestClientStateCASPreventsStaleUpdate0228",
        "TestTransactionalUpdaterPostVerifyFailureRollsBack0156",
        "TestTransactionalUpdaterCrashRecovery0156",
        "TestClientLifecycleInstallRepairCleanupRollback",
    )),
)


def validate_test_events(output: str, required: tuple[str, ...]) -> None:
    terminal: dict[str, str] = {}
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        test = event.get("Test")
        action = event.get("Action")
        if test in required and action in {"pass", "fail", "skip"}:
            terminal[test] = action
    not_passed = {name: terminal.get(name, "missing") for name in required if terminal.get(name) != "pass"}
    if not_passed:
        raise ValueError("mandatory tests missing, failed or skipped: " + json.dumps(not_passed, sort_keys=True))


def run_suite(name: str, directory: str, package: str, tests: tuple[str, ...]) -> dict:
    regex = "^(?:" + "|".join(re.escape(test) for test in tests) + ")$"
    cmd = ["go", "test", "-json", "-race", "-count=1", "-timeout=7m", package, "-run", regex]
    result = subprocess.run(cmd, cwd=ROOT / directory, capture_output=True, text=True, timeout=600)
    combined = result.stdout + "\n" + result.stderr
    if result.returncode:
        raise RuntimeError(f"{name}: exit {result.returncode}\n{combined[-6000:]}")
    validate_test_events(result.stdout, tests)
    return {"id": name, "status": "passed", "tests": list(tests), "command": cmd}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="dist/ga-certification/profiles-0230.json")
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    sha = os.environ.get("GITHUB_SHA", os.environ.get("NEVERLAUNCHER_SOURCE_COMMIT", ""))
    if version != "0.23.0" or not re.fullmatch(r"[a-fA-F0-9]{40}", sha):
        print("GA certification requires VERSION=0.23.0 and exact 40-digit source SHA", file=sys.stderr)
        return 2
    if not os.getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN"):
        print("GA certification requires NEVERLAUNCHER_TEST_POSTGRES_DSN (real PostgreSQL)", file=sys.stderr)
        return 2
    report = {"schemaVersion": "1", "productVersion": version, "commit": sha.lower(),
              "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
              "status": "failed", "suites": []}
    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    for name, directory, package, tests in CASES:
        try:
            print("[profiles-ga]", name, flush=True)
            report["suites"].append(run_suite(name, directory, package, tests))
        except (RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as exc:
            print(str(exc), file=sys.stderr)
            report["suites"].append({"id": name, "status": "failed", "error": str(exc)[-6000:]})
            break
    if len(report["suites"]) == len(CASES) and all(s["status"] == "passed" for s in report["suites"]):
        report["status"] = "passed"
    # Evidence ties to this commit; it is not a signing certificate and never
    # contains database passwords, signing material, or full command output.
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("[profiles-ga]", report["status"], output)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
