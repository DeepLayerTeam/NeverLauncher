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


if triple(VERSION) < (0, 16, 0):
    raise SystemExit(f"Production Delivery Release gate requires VERSION>=0.16.0, got {VERSION}")
if "-" in VERSION or "+" in VERSION:
    raise SystemExit(f"Production Delivery Release requires GA SemVer, got {VERSION}")

impl = (ROOT / "cli/cmd/neverlauncher/production_delivery_release_0160.go").read_text(encoding="utf-8")
tests = (ROOT / "cli/cmd/neverlauncher/production_delivery_release_0160_test.go").read_text(encoding="utf-8")
release = (ROOT / "cli/cmd/neverlauncher/release_commands.go").read_text(encoding="utf-8")
build = (ROOT / "scripts/release/build-release.sh").read_text(encoding="utf-8")
bundle = (ROOT / "scripts/smoke/release-required/release-bundle.sh").read_text(encoding="utf-8")
public_delivery = (ROOT / "cli/cmd/neverlauncher/public_delivery_matrix.go").read_text(encoding="utf-8")
public_workflow = (ROOT / ".github/workflows/public-production-delivery.yml").read_text(encoding="utf-8")

require(impl, [
    "PRODUCTION_DELIVERY_RELEASE.json",
    "production-delivery-release",
    "stable-versioned-public-origin",
    "productionDeliveryReleaseBoundaryDigest0160",
    "versionedPublicBaseURL0160",
    "verifyProductionDeliveryRelease0160",
    "productionReleaseCandidateFile01511",
    "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json" if False else "publicProductionDeliveryMatrixFile0159",
    "PostPublishE2E",
], "Production Delivery Release implementation")
require(release, [
    'case "production-verify":',
    "writeProductionDeliveryRelease0160",
    "verifyProductionDeliveryRelease0160",
    "production-delivery-release-stable-six-target-ga",
    "productionDeliveryReleaseSha256",
    'manifest["channel"] = productionDeliveryReleaseChannel0160',
], "release integration")
require(build, [
    "PRODUCTION_DELIVERY_RELEASE_REQUIRED",
    "PRODUCTION_DELIVERY_RELEASE.json",
    "release production-verify",
    "immutable version segment",
], "production build integration")
require(bundle, ["PRODUCTION_DELIVERY_RELEASE.json", "release publish-check"], "release bundle gate")
require(public_delivery, ["production-delivery-release", "ProductionDeliveryReleaseVerified", "verifyProductionDeliveryRelease0160"], "public E2E integration")
require(public_workflow, ["PRODUCTION_DELIVERY_RELEASE.json", "release production-verify", "productionDeliveryReleaseVerified"], "post-publish GA verification")
require(tests, [
    "TestProductionDeliveryRelease0160BindsCandidateAndAnchors",
    "TestProductionDeliveryRelease0160RejectsUnversionedPublicOrigin",
    "TestProductionDeliveryRelease0160RejectsPrereleaseSemver",
], "Production Delivery Release tests")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestProductionDeliveryRelease0160", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)
print(f"NeverLauncher {VERSION} Production Delivery Release 0.16.0 gate: OK")
