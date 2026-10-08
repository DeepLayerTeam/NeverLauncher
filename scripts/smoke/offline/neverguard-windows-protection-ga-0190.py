#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, path: str, needles: list[str]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"[NeverLauncher] Windows Защита GA 0.19.0 контроль: {path} отсутствующий: {', '.join(missing)}")


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"недопустимый VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 19, 0):
    raise SystemExit(f"Windows Защита GA контроль требует >=0.19.0, получил {version}")

impl = read("cli/cmd/neverlauncher/windows_protection_ga_0190.go")
require(impl, "cli/cmd/neverlauncher/windows_protection_ga_0190.go", [
    'windowsProtectionGAFile0190',
    '"WINDOWS_PROTECTION_GA_CERTIFICATE.json"',
    'windowsProtectionGAStatus0190',
    '"windows-protection-ga"',
    'windowsProtectionGAModel0190',
    '"user-mode"',
    'windowsProtectionGAEnforcement0190',
    '"fail-closed"',
    'func verifyWindowsUserModeOnlyPackages0190',
    'strings.HasSuffix(clean, ".sys")',
    'func windowsProtectionGABoundaryDigest0190',
    'func buildWindowsProtectionGADocument0190',
    'verifyWindowsProtectionRelease01812(dir, ver)',
    '"server-enforced-continuous-attestation-v2-join-ticket"',
    '"kernel-driver-free-production-package"',
    '"kernelDriverAbsent"',
    '"userModeProtectionBoundary"',
    'func verifyWindowsProtectionGA0190',
])

tests = read("cli/cmd/neverlauncher/windows_protection_ga_0190_test.go")
require(tests, "cli/cmd/neverlauncher/windows_protection_ga_0190_test.go", [
    "TestWindowsProtectionGARequired0190",
    "TestWindowsProtectionGABoundaryBindsRCAndArtifacts0190",
    "TestWindowsProtectionGACapabilities0190",
])

runtime = read("runtime/neverruntime/src/windows_protection.rs")
require(runtime, "runtime/neverruntime/src/windows_protection.rs", [
    "is_remote_attestation_eligible",
    "matches!(self, Self::Aggressive)",
])

attestation = read("services/api/internal/httpapi/guard_attestation_v2_01810.go")
bridge = read("services/api/internal/httpapi/server_bridge.go")
require(attestation, "services/api/internal/httpapi/guard_attestation_v2_01810.go", [
    'guardAttestationV2Schema01810',
    'guardContinuousEvidenceSchema01810',
    'guardContinuousJoinPurpose01810',
    'ContinuousGuardHealthy',
    'consumeGuardContinuousJoinTicket01810',
])
require(bridge, "services/api/internal/httpapi/server_bridge.go", [
    'ContinuousGuardTicket',
    'consumeGuardContinuousJoinTicket01810',
    'validateContinuousGuardTicketForMinecraftSession01810',
])

release = read("cli/cmd/neverlauncher/release_commands.go")
require(release, "cli/cmd/neverlauncher/release_commands.go", [
    'case "windows-protection-ga-verify":',
    'writeWindowsProtectionGA0190(out, ver)',
    'verifyWindowsProtectionGA0190(out, ver)',
    '"windows-protection-ga-fail-closed-user-mode-boundary"',
    '"windowsProtectionGACertified"',
    '"windowsProtectionGACertificateSha256"',
])

candidate = read("cli/cmd/neverlauncher/production_release_candidate_01511.go")
delivery = read("cli/cmd/neverlauncher/production_delivery_release_0160.go")
require(candidate, "cli/cmd/neverlauncher/production_release_candidate_01511.go", [
    '"windows-protection-ga-fail-closed-user-mode-boundary"',
    'verifyWindowsProtectionGA0190(dir, ver)',
])
require(delivery, "cli/cmd/neverlauncher/production_delivery_release_0160.go", [
    '"windows-protection-ga-fail-closed-user-mode-boundary"',
    'windowsProtectionGAFile0190',
])

build = read("scripts/release/build-release.sh")
require(build, "scripts/release/build-release.sh", [
    'WINDOWS_PROTECTION_GA_REQUIRED',
    'WINDOWS_PROTECTION_GA_CERTIFICATE.json',
    'release windows-protection-ga-verify "${OUT_DIR}"',
])

workflow = read(".github/workflows/production-release-candidate.yml")
require(workflow, ".github/workflows/production-release-candidate.yml", [
    'WINDOWS_PROTECTION_GA_CERTIFICATE.json',
    'windowsProtectionGACertified',
    'windows-protection-ga',
])

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
for text, path in [(ci, ".github/workflows/ci.yml"), (preflight, "scripts/release/preflight.sh")]:
    if "neverguard-windows-protection-ga-0190.py" not in text:
        raise SystemExit(f"[NeverLauncher] Windows Защита GA 0.19.0 контроль: обязательный контроль не wired в {path}")
if "TestWindowsProtectionGA" not in ci:
    raise SystemExit("[NeverLauncher] Windows Защита GA 0.19.0 контроль: Go GA тесты являются не wired в CI")

for marker in ["todo!", "unimplemented!", "placeholder", "stub"]:
    if marker in impl.lower():
        raise SystemExit(f"[NeverLauncher] Windows Защита GA 0.19.0 контроль: placeholder {marker!r} в реализация")

print(f"[NeverLauncher] NeverGuard Windows Защита GA 0.19.0 рабочий контроль: OK ({version})")
