#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 8):
    raise SystemExit(f"Release Verification v2 gate requires VERSION>=0.15.8, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")

v2 = read("cli/cmd/neverlauncher/release_verification_v2.go")
require(v2, [
    "RELEASE_TRUST_POLICY.json", "neverlauncher.release.v2", "TrustEpoch",
    "verifyReleaseTrustPolicy0158", "signReleaseBundleV20158", "verifyReleaseSignatureV20158",
    "verify-only", "revoked", "trust epoch rollback", "release rollback blocked",
    "NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE", "current trust policy", "root trust anchor",
], "Release Verification v2 core")

keyring = read("cli/cmd/neverlauncher/security_keyring.go")
require(keyring, ["TrustEpoch", "reg.TrustEpoch++", 'Status: "active"'], "key lifecycle registry")

release = read("cli/cmd/neverlauncher/release_commands.go")
require(release, [
    "releaseVerificationV2Required0158", "verifyReleaseBundleWithTrustState",
    "release-verification-v2-trust-lifecycle-anti-rollback", "--trust-state",
], "release integration")

build = read("scripts/release/build-release.sh")
require(build, [
    "NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE", "NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE",
    "NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE", '--trust-policy "${TRUST_POLICY}"',
], "production release script")

bundle_gate = read("scripts/smoke/release-required/release-bundle.sh")
require(bundle_gate, ["RELEASE_TRUST_POLICY.json", "TRUST_STATE", "--trust-state"], "release bundle gate")

tests = read("cli/cmd/neverlauncher/release_verification_v2_test.go")
require(tests, [
    "TestReleaseVerificationV2TrustLifecycleAndAntiRollback",
    "TestReleaseTrustPolicyRejectsTampering",
], "Release Verification v2 tests")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestReleaseVerificationV2|TestReleaseTrustPolicy", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Release Verification v2 + trust/key lifecycle gate: OK")
