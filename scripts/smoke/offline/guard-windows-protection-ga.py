#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, path: str, needles: list[str]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(
            f"[Launcher] Проверка GA защиты Windows 0.19.0: {path} отсутствует: {', '.join(missing)}"
        )


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"Некорректное значение VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 19, 0):
    raise SystemExit(f"Общедоступный выпуск защиты Windows: требуется версия не ниже 0.19.0, получено {version}")

impl = read("cli/cmd/launcher/windows_protection_ga.go")
require(
    impl,
    "cli/cmd/launcher/windows_protection_ga.go",
    [
        "windowsProtectionGAFile0190",
        '"WINDOWS_PROTECTION_GA_CERTIFICATE.json"',
        "windowsProtectionGAStatus0190",
        '"windows-protection-ga"',
        "windowsProtectionGAModel0190",
        '"user-mode"',
        "windowsProtectionGAEnforcement0190",
        '"fail-closed"',
        "func verifyWindowsUserModeOnlyPackages0190",
        'strings.HasSuffix(clean, ".sys")',
        "func windowsProtectionGABoundaryDigest0190",
        "func buildWindowsProtectionGADocument0190",
        "verifyWindowsProtectionRelease01812(dir, ver)",
        '"server-enforced-continuous-attestation-v2-join-ticket"',
        '"kernel-driver-free-production-package"',
        '"kernelDriverAbsent"',
        '"userModeProtectionBoundary"',
        "func verifyWindowsProtectionGA0190",
    ],
)

tests = read("cli/cmd/launcher/windows_protection_ga_test.go")
require(
    tests,
    "cli/cmd/launcher/windows_protection_ga_test.go",
    [
        "TestWindowsProtectionGARequired0190",
        "TestWindowsProtectionGABoundaryBindsRCAndArtifacts0190",
        "TestWindowsProtectionGACapabilities0190",
    ],
)

runtime = read("runtime/runtime/src/windows_protection.rs")
require(
    runtime,
    "runtime/runtime/src/windows_protection.rs",
    [
        "is_remote_attestation_eligible",
        "matches!(self, Self::Aggressive)",
    ],
)

attestation = read("services/api/internal/httpapi/guard_attestation_v2_.go")
bridge = read("services/api/internal/httpapi/server_bridge.go")
require(
    attestation,
    "services/api/internal/httpapi/guard_attestation_v2_.go",
    [
        "guardAttestationV2Schema01810",
        "guardContinuousEvidenceSchema01810",
        "guardContinuousJoinPurpose01810",
        "ContinuousGuardHealthy",
        "consumeGuardContinuousJoinTicket01810",
    ],
)
require(
    bridge,
    "services/api/internal/httpapi/server_bridge.go",
    [
        "ContinuousGuardTicket",
        "consumeGuardContinuousJoinTicket01810",
        "validateContinuousGuardTicketForMinecraftSession01810",
    ],
)

release = read("cli/cmd/launcher/release_commands.go")
require(
    release,
    "cli/cmd/launcher/release_commands.go",
    [
        'case "windows-protection-ga-verify":',
        "writeWindowsProtectionGA0190(out, ver)",
        "verifyWindowsProtectionGA0190(out, ver)",
        '"windows-protection-ga-fail-closed-user-mode-boundary"',
        '"windowsProtectionGACertified"',
        '"windowsProtectionGACertificateSha256"',
    ],
)

candidate = read("cli/cmd/launcher/production_release_candidate.go")
delivery = read("cli/cmd/launcher/production_delivery_release.go")
require(
    candidate,
    "cli/cmd/launcher/production_release_candidate.go",
    [
        '"windows-protection-ga-fail-closed-user-mode-boundary"',
        "verifyWindowsProtectionGA0190(dir, ver)",
    ],
)
require(
    delivery,
    "cli/cmd/launcher/production_delivery_release.go",
    [
        '"windows-protection-ga-fail-closed-user-mode-boundary"',
        "windowsProtectionGAFile0190",
    ],
)

build = read("scripts/release/build-release.sh")
require(
    build,
    "scripts/release/build-release.sh",
    [
        "WINDOWS_PROTECTION_GA_REQUIRED",
        "WINDOWS_PROTECTION_GA_CERTIFICATE.json",
        'release windows-protection-ga-verify "${OUT_DIR}"',
    ],
)

workflow = read(".github/workflows/production-release-candidate.yml")
require(
    workflow,
    ".github/workflows/production-release-candidate.yml",
    [
        "WINDOWS_PROTECTION_GA_CERTIFICATE.json",
        "windowsProtectionGACertified",
        "windows-protection-ga",
    ],
)

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
for text, path in [
    (ci, ".github/workflows/ci.yml"),
    (preflight, "scripts/release/preflight.sh"),
]:
    if "guard-windows-protection-ga.py" not in text:
        raise SystemExit(
            f"[Launcher] Проверка защиты Windows GA 0.19.0: обязательная проверка не подключена в {path}"
        )
if "TestWindowsProtectionGA" not in ci:
    raise SystemExit(
        "[Launcher] Проверка GA защиты Windows 0.19.0: Go-тесты GA не подключены к CI"
    )

for marker in ["todo!", "unimplemented!", "placeholder", "stub"]:
    if marker in impl.lower():
        raise SystemExit(
            f"[Launcher] Проверка защиты Windows GA 0.19.0: заглушка {marker!r} в реализации"
        )

print(f"[Launcher] Выпуск защиты Guard для Windows (GA) 0.19.0: проверка готовности к эксплуатации: OK ({version})")
