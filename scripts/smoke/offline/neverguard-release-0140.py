#!/usr/bin/env python3
from pathlib import Path
import json

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 0):
    raise SystemExit("VERSION is older than 0.14.0")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(path: str, needles: list[str]) -> None:
    text = read(path)
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path}: missing {missing}")


for path, platform in [
    ("runtime/neverruntime/src/guard_ipc.rs", "windows-amd64"),
    ("runtime/neverruntime/src/linux_guard.rs", "linux-amd64"),
    ("runtime/neverruntime/src/macos_guard.rs", "macos-universal"),
]:
    require(path, ["product_version", "platform", 'env!("CARGO_PKG_VERSION")', platform, "validate_release_identity", '"status"'])

require("services/api/internal/httpapi/guard_attestation_0134.go", [
    'guardReleasePolicySchema0140      = "2.0"',
    "PlatformArtifacts",
    "allowsArtifactPair0140",
    "guardReleasePolicyV2Required0140",
    "NeverGuard 0.14+ requires schemaVersion=2.0",
    '"guardReleasePolicySchema"',
    '"guardProtocolVersion"',
    '"guardPlatform"',
    'signingMode != "authenticode"',
    'signingMode != "developer-id-notarized"',
    'Windows Authenticode policy contains artifact pair without requireAuthenticode',
    'NeverGuard current production release %s is missing %s artifact policy',
])
require("services/api/internal/httpapi/minecraft_serverbridge_integrity_0135.go", ["policy.allowsArtifactPair0140(device.Platform"])
require("services/api/internal/httpapi/minecraft_serverbridge_integrity_0135_test.go", ["TestMinecraftIntegrityV2RejectsCrossProductArtifactPair0140", "cross-product v2 artifact pair remained valid"])
require("services/api/internal/config/config.go", [
    'SchemaVersion string                  `json:"schemaVersion"`',
    'document.SchemaVersion != "2.0"',
    '"windows": "authenticode"',
    '"macos": "developer-id-notarized"',
])
require("services/api/internal/httpapi/guard_attestation_0134_test.go", [
    "TestGuardReleasePolicyV2ExactPlatformPair0140",
    "cross-product artifact pair must not be accepted",
    "TestGuardReleasePolicyLegacyRejectedFrom0140",
    "TestGuardReleasePolicyProductionSigningRequirements0140",
])

require("scripts/release/build-linux-desktop.sh", ['"schemaVersion":"2.0"', '"signingMode":"integrity-only"'])
require("scripts/release/build-windows-desktop.ps1", ['schemaVersion = "2.0"', 'signingMode = $(if ($AuthenticodeRequired) { "authenticode" } else { "unsigned-development" })'])
require("scripts/release/build-macos-desktop.sh", ['"schemaVersion":"2.0"', 'SIGNING_MODE="developer-id-notarized"'])
require("scripts/release/merge-guard-release-policy.py", [
    '"windows": ("authenticode", True)',
    '"linux": ("integrity-only", False)',
    '"macos": ("developer-id-notarized", False)',
    "Windows production pair must require Authenticode",
    'set(platforms) != {expected_platform}',
])

matrix = read("scripts/guard_ci/matrix.py")
for needle in ["neverGuardRelease0140", 'releasePolicySchema', 'releaseIdentityAuthenticated']:
    if needle not in matrix:
        raise SystemExit(f"Guard CI matrix missing {needle}")
targets = json.loads(read("guard-ci/targets.json"))
if targets.get("productVersion") != version:
    raise SystemExit("Guard CI target productVersion is not aligned with VERSION")
for target in targets.get("targets", []):
    if "neverGuardRelease0140" not in target.get("requiredChecks", []):
        raise SystemExit(f"{target.get('id')}: NeverGuard 0.14 release check is missing")

require("scripts/release/preflight.sh", ["neverguard-release-0140.py"])
require(".github/workflows/ci.yml", ["neverguard-release-0140.py"])
require("cli/cmd/neverlauncher/release_commands.go", ["neverguard-release-0140.py", '"neverguard-release"'])

print(f"NeverLauncher 0.14.0 NeverGuard Release gate: OK ({version})")
