#!/usr/bin/env python3
"""Fail-closed 0.24.0 certification runner. Writes reproducible evidence, not promises.

local: run accessible tests and record missing gates as incomplete;
full: require exact git SHA, clean source, Rust/Go integration, real JVM,
Windows file-lock E2E, signed bootstrap and same-stand 0.23.0 benchmark.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RUST_REQUIRED = (
    "interrupted_transfer_persists_validator_and_sends_if_range_after_restart",
    "changed_etag_and_http_200_never_append_old_content",
    "malformed_content_range_must_fallback_to_fresh_get",
    "wrong_hash_discards_partial_and_preserves_previous_target",
    "bounded_parallel_downloads_isolate_failures_and_report_progress",
    "separate_repair_downloads_share_process_host_limit",
    "retries_503_then_truncated_body_by_range_without_repeating_prefix",
    "crash_after_first_file_of_two_recovers_complete_old_release",
    "insufficient_disk_budget_fails_before_live_mutation",
    "backup_corruption_blocks_destructive_recovery",
    "symlink_target_prevents_install_without_modifying_external_file",
    "inventory_detects_non_executable_corruption_and_added_files",
    "verified_local_distribution_restores_corrupted_runtime_without_network",
    "signed_game_rollback_must_use_new_authorized_generation_02311",
)
GO_CASES = {
    "prestarter": (
        "prestarter",
        "./...",
        (
            "TestOfflineFreshInstallAndVerifiedRecovery",
            "TestFailedNewReleaseKeepsOldActive",
            "TestDownloadRangeResumeAndBadRangeInvalidates",
            "TestMalformed206NeverJoinsOldBytes",
            "TestProcessLockSerializesSameRoot",
            "TestRollbackIfSignedProfileCannotBootstrap",
            "TestRecoveryRemovesUncommittedStaging",
            "TestDelegatedBootstrapCannotUseRevokedSigner02312",
            "TestRootSignedTrustRotationAndRevocation02312",
            "TestVerifyOnlyWindowAndFreeze02312",
            "TestInstallRepairUninstallKeepsGameData",
            "TestTamperedSignedBundleRejected",
            "TestRepairCorruptedInstalledPrestarterFromRetainedOffline",
        ),
    ),
    "component-updater": (
        "cli",
        "./cmd/launcher",
        (
            "TestSignedComponentSet02310",
            "TestCoordinatedPackageCommitAndFailure02310",
            "TestComponentSetInterruptedSwitchRecovery02310",
            "TestComponentGenerationRealUpdater02311",
            "TestCorruptedComponentGenerationFloor02311",
            "TestComponentDelegatedTrust02312",
            "TestTransactionalUpdaterCrashRecovery0156",
            "TestTransactionalUpdaterPostVerifyFailureRollsBack0156",
        ),
    ),
}


def tree_digest():
    h = hashlib.sha256()
    skip = {".git", "node_modules", "target", "dist", "__pycache__", ".venv"}
    for path in sorted(
        p
        for p in ROOT.rglob("*")
        if p.is_file() and not skip.intersection(p.relative_to(ROOT).parts)
    ):
        rel = path.relative_to(ROOT).as_posix().encode()
        h.update(len(rel).to_bytes(4, "big") + rel)
        digest = hashlib.sha256(path.read_bytes()).digest()
        h.update(digest)
    return h.hexdigest()


def source_identity():
    sha = None
    clean = False
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    )
    if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", result.stdout.strip()):
        sha = result.stdout.strip()
        clean = (
            subprocess.run(
                ["git", "diff", "--quiet", "HEAD", "--", "."], cwd=ROOT
            ).returncode
            == 0
        )
        # Untracked files mean the SHA cannot identify the tested source either.
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        clean = clean and not untracked.stdout.strip()
    injected = os.environ.get("GITHUB_SHA")
    if injected and injected != sha:
        raise ValueError("GITHUB_SHA disagrees with actual git HEAD")
    return sha, clean


def execute(name, cmd, *, cwd=ROOT, timeout=240):
    t = time.monotonic_ns()
    try:
        p = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        output = p.stdout
        rc = p.returncode
    except (OSError, subprocess.TimeoutExpired) as e:
        output, rc = str(e), -1
    return {
        "id": name,
        "status": "passed" if rc == 0 else "failed",
        "command": cmd,
        "exitCode": rc,
        "elapsedNs": time.monotonic_ns() - t,
        "outputSha256": hashlib.sha256(output.encode()).hexdigest(),
        "outputTail": output[-1800:],
    }


def go_suite(name, directory, package, cases):
    regex = "^(?:" + "|".join(re.escape(c) for c in cases) + ")$"
    cmd = ["go", "test", "-json", "-count=1", "-timeout=4m", package, "-run", regex]
    start = time.monotonic_ns()
    try:
        executed = subprocess.run(
            cmd,
            cwd=ROOT / directory,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=360,
        )
        output = executed.stdout + executed.stderr
        code = executed.returncode
    except (OSError, subprocess.TimeoutExpired) as e:
        output, code = str(e), -1
    observed = {}
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("Test") in cases and event.get("Action") in {
            "pass",
            "fail",
            "skip",
        }:
            observed[event["Test"]] = event["Action"]
    failures = [case for case in cases if observed.get(case) != "pass"]
    return {
        "id": name,
        "status": "passed" if code == 0 and not failures else "failed",
        "command": cmd,
        "exitCode": code,
        "elapsedNs": time.monotonic_ns() - start,
        "outputSha256": hashlib.sha256(output.encode()).hexdigest(),
        "outputTail": output[-1800:],
        "testOutcomes": observed,
        "missingOrFailed": failures,
    }


def rust_suite():
    manifest = ROOT / "runtime/runtime/Cargo.toml"
    listed = execute(
        "rust-list",
        ["cargo", "test", "--manifest-path", str(manifest), "--lib", "--", "--list"],
        timeout=600,
    )
    if listed["status"] != "passed":
        return listed
    # -q hides names; test list output is stored in compact outputTail only, so query it explicitly.
    listing = subprocess.run(
        ["cargo", "test", "--manifest-path", str(manifest), "--lib", "--", "--list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    missing = [
        name
        for name in RUST_REQUIRED
        if not re.search(r"::" + re.escape(name) + r": test\b", listing.stdout)
    ]
    if missing:
        listed["status"] = "failed"
        listed["missingTests"] = missing
        return listed
    return execute(
        "rust-runtime",
        [
            "cargo",
            "test",
            "--manifest-path",
            str(manifest),
            "--lib",
            "--",
            "--nocapture",
        ],
        timeout=1200,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["local", "full"], default="local")
    parser.add_argument(
        "--output", type=Path, default=Path("dist/certification-0240/evidence.json")
    )
    args = parser.parse_args()
    if (ROOT / "VERSION").read_text().strip() != "0.24.0":
        raise SystemExit("VERSION must equal 0.24.0")
    try:
        sha, clean = source_identity()
    except ValueError as e:
        raise SystemExit(str(e))
    evidence = {
        "schemaVersion": "1",
        "productVersion": "0.24.0",
        "commit": sha,
        "sourceTreeSha256": tree_digest(),
        "gitTreeClean": clean,
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": args.mode,
        "status": "incomplete",
        "suites": [],
        "unmetGates": [],
    }
    suites = evidence["suites"]
    suites.append(
        execute(
            "fault-http-server",
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(HERE),
                "-p",
                "test_fault_server.py",
                "-v",
            ],
            timeout=90,
        )
    )
    if shutil.which("go"):
        for name, (directory, package, tests) in GO_CASES.items():
            suites.append(go_suite(name, directory, package, tests))
    else:
        for name in GO_CASES:
            suites.append(
                {"id": name, "status": "missing", "reason": "go not installed"}
            )
    if shutil.which("cargo"):
        suites.append(rust_suite())
        cargo = [
            "cargo",
            "build",
            "--manifest-path",
            str(ROOT / "runtime/runtime/Cargo.toml"),
            "--bin",
            "runtime",
            "--example",
            "cert_sign_fixture",
        ]
        built = execute("build-runtime-e2e", cargo, timeout=1200)
        suites.append(built)
        if built["status"] == "passed":
            suffix = ".exe" if os.name == "nt" else ""
            out = args.output if args.output.is_absolute() else ROOT / args.output
            suites.append(
                execute(
                    "real-runtime-e2e",
                    [
                        sys.executable,
                        str(HERE / "runtime_e2e.py"),
                        "--runtime",
                        str(ROOT / f"runtime/runtime/target/debug/runtime{suffix}"),
                        "--signer",
                        str(
                            ROOT
                            / f"runtime/runtime/target/debug/examples/cert_sign_fixture{suffix}"
                        ),
                        "--output",
                        str(out.parent / "runtime-e2e.json"),
                    ],
                    timeout=600,
                )
            )
    else:
        for name in ("rust-runtime", "build-runtime-e2e", "real-runtime-e2e"):
            suites.append(
                {"id": name, "status": "missing", "reason": "cargo/rustc not installed"}
            )

    if platform.system() == "Windows" and shutil.which("go"):
        suites.append(
            go_suite(
                "windows-locked-executable-test",
                "cli",
                "./cmd/launcher",
                ("TestLockedWindowsExecutablePreservesOldRelease02313",),
            )
        )

    # Platform/hardware obligations are distinct from unit tests. Evidence must
    # point to an independently executed verified report for this SAME commit.
    attachments = {
        "real-java-clean-machine": "NEVERLAUNCHER_CERT_JAVA_EVIDENCE",
        "signed-installer-clean-machine": "NEVERLAUNCHER_CERT_BOOTSTRAP_EVIDENCE",
        "crash-power-loss": "NEVERLAUNCHER_CERT_POWERLOSS_EVIDENCE",
        "windows-locked-executable": "NEVERLAUNCHER_CERT_WINDOWS_LOCK_EVIDENCE",
    }
    for case, variable in attachments.items():
        value = os.environ.get(variable)
        if not value:
            suites.append(
                {"id": case, "status": "missing", "reason": f"{variable} not provided"}
            )
            continue
        path = Path(value).resolve()
        try:
            report = json.loads(path.read_text())
            if (
                report.get("status") != "passed"
                or report.get("commit") != sha
                or not sha
            ):
                raise ValueError("report not passed or commit mismatch")
            suites.append(
                {
                    "id": case,
                    "status": "passed",
                    "artifactSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        except (OSError, ValueError) as err:
            suites.append({"id": case, "status": "failed", "reason": str(err)})
    baseline = os.environ.get("NEVERLAUNCHER_BASELINE_0230_BIN")
    runtime_bin = ROOT / (
        "runtime/runtime/target/debug/runtime" + (".exe" if os.name == "nt" else "")
    )
    signer_bin = ROOT / (
        "runtime/runtime/target/debug/examples/cert_sign_fixture"
        + (".exe" if os.name == "nt" else "")
    )
    if baseline and runtime_bin.exists() and signer_bin.exists():
        out = args.output if args.output.is_absolute() else ROOT / args.output
        suites.append(
            execute(
                "same-stand-benchmark",
                [
                    sys.executable,
                    str(HERE / "benchmark.py"),
                    "--baseline",
                    str(Path(baseline).resolve()),
                    "--candidate",
                    str(runtime_bin),
                    "--signer",
                    str(signer_bin),
                    "--output",
                    str(out.parent / "benchmark.json"),
                ],
                timeout=1200,
            )
        )
    else:
        suites.append(
            {
                "id": "same-stand-benchmark",
                "status": "missing",
                "reason": "real 0.23.0 executable or built Rust artifacts unavailable",
            }
        )
    if not sha or not clean:
        evidence["unmetGates"].append(
            "exact clean git commit SHA is required; archive snapshot hash is not a git commit"
        )
    evidence["unmetGates"] += [s["id"] for s in suites if s["status"] != "passed"]
    if not evidence["unmetGates"]:
        evidence["status"] = "passed"
    elif any(s["status"] == "failed" for s in suites):
        evidence["status"] = "failed"
    out = args.output if args.output.is_absolute() else ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf8"
    )
    print(
        f"certification {evidence['status']} ({len(suites)} suites): {out}", flush=True
    )
    for s in suites:
        print(f"  {s['id']}: {s['status']}", flush=True)
    return (
        0
        if args.mode == "local" and evidence["status"] != "failed"
        else (0 if evidence["status"] == "passed" else 1)
    )


if __name__ == "__main__":
    raise SystemExit(main())
