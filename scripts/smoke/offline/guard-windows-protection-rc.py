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
            f"[Launcher] Проверка RC защиты Windows 0.18.12: {path} отсутствует: {', '.join(missing)}"
        )


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"Некорректное значение VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 18, 12):
    raise SystemExit(f"Кандидат в выпуск защиты Windows: требуется версия не ниже 0.18.12, получено {version}")

impl = read("cli/cmd/launcher/windows_protection_release.go")
require(
    impl,
    "cli/cmd/launcher/windows_protection_release.go",
    [
        'windowsAdversarialCertificateFile01811 = "WINDOWS_ADVERSARIAL_CERTIFICATE.json"',
        'windowsProtectionReleaseFile01812      = "WINDOWS_PROTECTION_RELEASE_CERTIFICATE.json"',
        'windowsProtectionRepository01812       = "DeepLayerTeam/Launcher"',
        "func validateWindowsAdversarialCertificate01812",
        "cert.ScenarioExecutions != 55",
        "expectedJava := []int{8, 16, 17, 21, 25}",
        "func windowsProtectionArtifacts01812",
        "expectedWindowsSignedArtifactsForVersion0157",
        "func windowsProtectionBoundaryDigest01812",
        "verifyWindowsSigningEvidence0152(dir, ver, true)",
        'ProtectionProfile: "aggressive"',
        '"continuous-attestation-v2"',
        '"windows-adversarial-certification-55-executions"',
        '"authenticode-rfc3161-x64-arm64"',
        '"publishedWindowsBytesBound"',
        "func verifyWindowsProtectionRelease01812",
        'cert.CertificateID != "sha256:"+strings.ToLower(expected.BoundarySHA256)',
    ],
)

tests = read("cli/cmd/launcher/windows_protection_release_test.go")
require(
    tests,
    "cli/cmd/launcher/windows_protection_release_test.go",
    [
        "TestWindowsProtectionReleaseRequired01812",
        "TestValidateWindowsAdversarialCertificate01812",
        "TestWindowsProtectionBoundaryDigest01812BindsArtifactsAndCapabilities",
    ],
)

release = read("cli/cmd/launcher/release_commands.go")
require(
    release,
    "cli/cmd/launcher/release_commands.go",
    [
        'case "windows-protection-verify":',
        "writeWindowsProtectionRelease01812(out, ver, expectedCommit)",
        "verifyWindowsProtectionRelease01812(out, ver)",
        '"windows-protection-rc-adversarial-signed-production-boundary"',
        '"windowsProtectionReleaseCertified"',
        '"windowsProtectionReleaseCertificateSha256"',
        '"windowsAdversarialCertificateSha256"',
        "artifacts = append(artifacts, windowsAdversarialCertificateFile01811, windowsProtectionReleaseFile01812)",
    ],
)

candidate = read("cli/cmd/launcher/production_release_candidate.go")
delivery = read("cli/cmd/launcher/production_delivery_release.go")
for path, text in [
    ("cli/cmd/launcher/production_release_candidate.go", candidate),
    ("cli/cmd/launcher/production_delivery_release.go", delivery),
]:
    require(
        text, path, ["windows-protection-rc-adversarial-signed-production-boundary"]
    )
require(
    candidate,
    "cli/cmd/launcher/production_release_candidate.go",
    ["verifyWindowsProtectionRelease01812(dir, ver)"],
)
require(
    delivery,
    "cli/cmd/launcher/production_delivery_release.go",
    [
        "windowsAdversarialCertificateFile01811, windowsProtectionReleaseFile01812",
    ],
)

build = read("scripts/release/build-release.sh")
require(
    build,
    "scripts/release/build-release.sh",
    [
        "LAUNCHER_WINDOWS_ADVERSARIAL_CERTIFICATE_FILE",
        "WINDOWS_PROTECTION_RC_REQUIRED",
        'cp "${WINDOWS_ADVERSARIAL_CERTIFICATE}" "${OUT_DIR}/WINDOWS_ADVERSARIAL_CERTIFICATE.json"',
        'release windows-protection-verify "${OUT_DIR}"',
    ],
)

workflow = read(".github/workflows/production-release-candidate.yml")
require(
    workflow,
    ".github/workflows/production-release-candidate.yml",
    [
        "Download exact-commit Windows adversarial certificate",
        "guard-windows-adversarial-certificate-${{ github.sha }}",
        "LAUNCHER_WINDOWS_ADVERSARIAL_CERTIFICATE_FILE",
        "WINDOWS_PROTECTION_RELEASE_CERTIFICATE.json",
        ".windowsProtectionReleaseCertified == true",
    ],
)

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
for text, path in [
    (ci, ".github/workflows/ci.yml"),
    (preflight, "scripts/release/preflight.sh"),
]:
    if "guard-windows-protection-rc.py" not in text:
        raise SystemExit(
            f"[Launcher] Проверка защиты Windows RC 0.18.12: обязательная проверка не подключена в {path}"
        )
if "TestWindowsProtection" not in ci:
    raise SystemExit(
        "[Launcher] Проверка RC защиты Windows 0.18.12: Go-тесты сертификации не подключены к CI"
    )

lowered = impl.lower()
for marker in ["todo!", "unimplemented!", "placeholder", "stub"]:
    if marker in lowered:
        raise SystemExit(
            f"[Launcher] Проверка RC защиты Windows 0.18.12: заглушка {marker!r} в cli/cmd/launcher/windows_protection_release.go"
        )

print(
    f"[Launcher] Сертификат RC защиты Windows и производственные проверки 0.18.12: ПРОЙДЕНО ({version})"
)
print('Windows Protection RC release certificate + production gates 0.18.12 gate: OK')
