#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 9):
    raise SystemExit(f"Public Production Delivery Matrix + E2E gate requires VERSION>=0.15.9, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")

core_go = read("cli/cmd/neverlauncher/public_delivery_matrix.go")
require(core_go, [
    "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json",
    "buildPublicProductionDeliveryMatrix0159",
    "validatePublicProductionDeliveryMatrix0159",
    "runPublicProductionDeliveryE2E0159",
    "windows", "linux", "macos", "x64", "arm64",
    "ManagedJRE", "downloadPublicAsset0159", "verifyReleaseBundleWithTrust",
    "public delivery base URL must use HTTPS", "redirect changed to untrusted host",
], "public production delivery core")

commands = read("cli/cmd/neverlauncher/delivery_manifest.go")
require(commands, [
    'case "public-matrix":', 'case "verify-public-matrix":', 'case "public-e2e":',
    '"--matrix-url"', '"--public-key"', '"--trust-policy"', '"--trust-state"',
], "delivery CLI")

release = read("cli/cmd/neverlauncher/release_commands.go")
require(release, [
    "publicProductionDeliveryRequired0159", "public-production-delivery-matrix-six-target-e2e",
    "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json", "writePublicProductionDeliveryMatrix0159",
], "release integration")

build = read("scripts/release/build-release.sh")
require(build, [
    "NEVERLAUNCHER_PUBLIC_RELEASE_BASE_URL",
    "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json",
    "neverruntime-windows-x64.exe", "neverruntime-windows-arm64.exe",
], "production build script")

workflow = read(".github/workflows/public-production-delivery.yml")
require(workflow, [
    "release:", "types: [published]", "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json",
    "delivery public-e2e", "NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE",
    "NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE", "PUBLIC_DELIVERY_E2E_REPORT.json",
], "post-publish E2E workflow")

tests = read("cli/cmd/neverlauncher/public_delivery_matrix_test.go")
require(tests, [
    "TestPublicProductionDeliveryMatrix0159CoversSixTargets",
    "TestPublicProductionDeliveryMatrix0159RejectsMissingRuntime",
    "TestFetchPublicMatrix0159LoopbackHTTP",
], "public delivery tests")

subprocess.run(
    ["go", "test", "./cmd/neverlauncher", "-run", "TestPublicProductionDeliveryMatrix0159|TestFetchPublicMatrix0159", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)

print(f"NeverLauncher {VERSION} Public Production Delivery Matrix + E2E gate: OK")
