#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def triple(v: str) -> tuple[int, int, int]:
    core = v.split("-", 1)[0].split("+", 1)[0]
    return tuple(int(x) for x in core.split(".")[:3])  # type: ignore[return-value]


def require(text: str, needles: list[str], label: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


if triple(VERSION) < (0, 15, 11):
    raise SystemExit(f"Production Release Candidate gate requires VERSION>=0.15.11, got {VERSION}")

impl = (ROOT / "cli/cmd/neverlauncher/production_release_candidate_01511.go").read_text(encoding="utf-8")
release = (ROOT / "cli/cmd/neverlauncher/release_commands.go").read_text(encoding="utf-8")
build = (ROOT / "scripts/release/build-release.sh").read_text(encoding="utf-8")
tests = (ROOT / "cli/cmd/neverlauncher/production_release_candidate_01511_test.go").read_text(encoding="utf-8")

require(impl, [
    "PRODUCTION_RELEASE_CANDIDATE.json",
    "production-release-candidate",
    "exact-source-commit-cohort",
    "productionReleaseCandidateCohortDigest01511",
    "verifyProductionReleaseCandidatePrerequisites01511",
    "verifyWindowsSigningEvidence0152",
    "verifyMacOSNotarizationEvidence0154",
    "verifyManagedJREDistribution0155",
    "verifyPublicProductionDeliveryMatrix0159",
    "PROVENANCE.json sourceCommit mismatch",
], "production candidate implementation")
require(release, [
    'case "candidate-verify":',
    "productionReleaseCandidateRequired01511",
    "writeProductionReleaseCandidate01511",
    "verifyProductionReleaseCandidate01511",
    "production-release-candidate-exact-source-cohort",
], "release integration")
require(build, [
    "PRODUCTION_RC_REQUIRED",
    "Production Release Candidate требует полный Compatibility + Device Trust + Guard CI certification cohort",
    "git -C \"${ROOT_DIR}\" diff --quiet HEAD --",
    "release candidate-verify",
    "PRODUCTION_RELEASE_CANDIDATE.json",
], "production build integration")
require(tests, [
    "TestProductionReleaseCandidate01511BindsExactCohort",
    "TestProductionReleaseCandidate01511RejectsInjectedFile",
    "TestSLSAProvenance01511CarriesExactSourceCommit",
    "TestNormalizeSourceCommit01511RejectsPlaceholders",
], "production candidate tests")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestProductionReleaseCandidate|TestSLSAProvenance01511|TestNormalizeSourceCommit01511", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)
print(f"NeverLauncher {VERSION} Production release candidate 0.15.11 gate: OK")
