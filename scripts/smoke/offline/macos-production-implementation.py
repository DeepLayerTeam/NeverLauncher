#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]


def read(path):
    return (root / path).read_text(encoding="utf-8")


def require(text, needles, label):
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


def version_tuple(value):
    return tuple(int(part) for part in value.split("."))


if version_tuple((root / "VERSION").read_text().strip()) < (0, 13, 8):
    raise SystemExit("VERSION ниже 0.13.8")

policy = read("runtime/runtime/src/macos_policy.rs")
require(
    policy,
    [
        "PT_DENY_ATTACH",
        "RLIMIT_CORE",
        "kqueue",
        "EVFILT_PROC",
        "NOTE_EXIT",
        "setpgid",
        "codesign",
        "Hardened Runtime",
        "guard/macos-runtime-process-policy/v1",
    ],
    "Усиление защиты Runtime для macOS",
)
ipc = read("runtime/runtime/src/macos_guard.rs")
require(
    ipc,
    [
        "UnixListener",
        "UnixStream",
        "peer_cred",
        "0o600",
        "client-auth",
        "Hmac",
        "MACOS_PACKAGE_MANIFEST.json",
        "spctl",
        "guard-attestation",
        "integrity-evidence",
        "desktop_sha256",
        "guard_sha256",
        "ru.skif4er.launcher.guard",
    ],
    "Проверка аутентифицированного IPC и пакета macOS",
)
integrity = read("runtime/runtime/src/integrity.rs")
require(
    integrity,
    [
        "guard/macos-integrity-evidence/v1",
        "proc_pidinfo",
        "proc_pidpath",
        "MacOSProcessSecurityEvidence",
        "hardened_runtime",
        "library_validation",
    ],
    "Свидетельства целостности macOS",
)
att = read("runtime/runtime/src/attestation.rs")
require(
    att,
    ["guard/macos-guard-attestation/v1", "Guard Attestation Core macOS v1"],
    "Аттестация macOS",
)
desktop = read("apps/desktop/src-tauri/src/main.rs")
require(
    desktop,
    [
        'target_os = "macos"',
        "GUARD_MACOS_PROCESS_POLICY_VERSION",
        "ensure_macos_production_hardening",
        "не пройдена проверка усиленной защиты Guard для рабочей сборки macOS",
    ],
    "Принудительное применение политик macOS в Desktop",
)
backend = read("services/api/internal/httpapi/guard_attestation.go")
require(
    backend,
    [
        "guardMacOSAttestationSchema0138",
        "guardMacOSIntegritySchema0138",
        "guardMacOSProcessPolicySchema0138",
        "isMacOSDevicePlatform0138",
        "Guard macOS process policy verification failed",
    ],
    "Проверка macOS на Backend",
)
tests = read("services/api/internal/httpapi/guard_attestation_test.go")
require(
    tests,
    ["TestMacOSGuardAttestationValidation0138", "LibraryValidation = false"],
    "Тесты Backend для macOS",
)
release = read("scripts/release/build-macos-desktop.sh")
require(
    release,
    [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "lipo -create",
        "Developer",
        "notarytool submit",
        "stapler staple",
        "spctl --assess",
        "GUARD_RELEASE_ALLOWLIST_MACOS.json",
        "MACOS_PACKAGE_MANIFEST.json",
        "desktopSha256",
        "guardSha256",
        "desktopSize",
        "guardSize",
        "--identifier ru.skif4er.launcher.guard",
    ],
    "Релизный пакет macOS",
)
ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        "guard-macos:",
        "guard_macos",
        "codesign --force --sign - --options runtime",
        "build-macos-desktop.sh",
        "macos-production-implementation.py",
    ],
    "Обязательная проверка macOS в CI",
)
preflight = read("scripts/release/preflight.sh")
require(preflight, ["macos-production-implementation.py"], "Предварительная обязательная проверка macOS")
print("Launcher 0.13.8: проверка готовности macOS: OK")
