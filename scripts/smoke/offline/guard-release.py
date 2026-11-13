#!/usr/bin/env python3
from pathlib import Path
import json

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 0):
    raise SystemExit("VERSION ниже 0.14.0")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(path: str, needles: list[str]) -> None:
    text = read(path)
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path}: отсутствует {missing}")


for path, platform in [
    ("runtime/runtime/src/guard_ipc.rs", "windows-amd64"),
    ("runtime/runtime/src/linux_guard.rs", "linux-amd64"),
    ("runtime/runtime/src/macos_guard.rs", "macos-universal"),
]:
    require(
        path,
        [
            "product_version",
            "platform",
            'env!("CARGO_PKG_VERSION")',
            platform,
            "validate_release_identity",
            '"status"',
        ],
    )

require(
    "services/api/internal/httpapi/guard_attestation.go",
    [
        'guardReleasePolicySchema0140      = "2.0"',
        "PlatformArtifacts",
        "allowsArtifactPair0140",
        "guardReleasePolicyV2Required0140",
        "Для Guard 0.14+ необходима политика выпуска schemaVersion=2.0",
        '"guardReleasePolicySchema"',
        '"guardProtocolVersion"',
        '"guardPlatform"',
        'signingMode != "authenticode"',
        'signingMode != "developer-id-notarized"',
        "содержит пару артефактов без requireAuthenticode",
        "Для текущего промышленного выпуска Guard %s отсутствует политика артефактов %s",
    ],
)
require(
    "services/api/internal/httpapi/minecraft_serverbridge_integrity.go",
    ["policy.allowsArtifactPair0140(device.Platform"],
)
require(
    "services/api/internal/httpapi/minecraft_serverbridge_integrity_test.go",
    [
        "TestMinecraftIntegrityV2RejectsCrossProductArtifactPair0140",
        "пара артефактов версии 2 от разных продуктов осталась действительной",
    ],
)
require(
    "services/api/internal/config/config.go",
    [
        'SchemaVersion string                  `json:"schemaVersion"`',
        'document.SchemaVersion != "2.0"',
        '"windows": "authenticode"',
        '"macos": "developer-id-notarized"',
    ],
)
require(
    "services/api/internal/httpapi/guard_attestation_test.go",
    [
        "TestGuardReleasePolicyV2ExactPlatformPair0140",
        "cross-product artifact pair must not be accepted",
        "TestGuardReleasePolicyLegacyRejectedFrom0140",
        "TestGuardReleasePolicyProductionSigningRequirements0140",
    ],
)

require(
    "scripts/release/build-linux-desktop.sh",
    ['"schemaVersion":"2.0"', '"signingMode":"integrity-only"'],
)
require(
    "scripts/release/build-windows-desktop.ps1",
    [
        'schemaVersion = "2.0"',
        'signingMode = $(if ($SignedProduction) { "authenticode" } else { "unsigned-development" })',
        "signtool verify",
    ],
)
require(
    "scripts/release/build-macos-desktop.sh",
    ['"schemaVersion":"2.0"', 'SIGNING_MODE="developer-id-notarized"'],
)
require(
    "scripts/release/merge-guard-release-policy.py",
    [
        '"windows": ("authenticode", True)',
        '"linux": ("integrity-only", False)',
        '"macos": ("developer-id-notarized", False)',
        "Windows production pair must require Authenticode",
        "set(platforms) != {expected_platform}",
    ],
)

matrix = read("scripts/guard_ci/matrix.py")
for needle in [
    "GuardRelease0140",
    "releasePolicySchema",
    "releaseIdentityAuthenticated",
]:
    if needle not in matrix:
        raise SystemExit(f"В матрице Guard CI отсутствует {needle}")
targets = json.loads(read("guard-ci/targets.json"))
if targets.get("productVersion") != version:
    raise SystemExit("productVersion цели Guard CI не совпадает с VERSION")
for target in targets.get("targets", []):
    if "GuardRelease0140" not in target.get("requiredChecks", []):
        raise SystemExit(f"{target.get('id')}: отсутствует проверка релиза Guard 0.14")

require("scripts/release/preflight.sh", ["guard-release.py"])
require(".github/workflows/ci.yml", ["guard-release.py"])
require(
    "cli/cmd/launcher/release_commands.go",
    ["guard-release.py", '"guard-release"'],
)

print(f"Launcher 0.14.0: проверка выпуска Guard: OK ({version})")
