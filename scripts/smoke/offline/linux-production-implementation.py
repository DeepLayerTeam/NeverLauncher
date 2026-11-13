#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]


def read(p):
    return (root / p).read_text(encoding="utf-8")


def require(text, needles, label):
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


def version_tuple(value):
    return tuple(int(part) for part in value.split("."))


if version_tuple((root / "VERSION").read_text().strip()) < (0, 13, 7):
    raise SystemExit("VERSION ниже 0.13.7")
policy = read("runtime/runtime/src/linux_policy.rs")
require(
    policy,
    [
        "PR_SET_NO_NEW_PRIVS",
        "PR_SET_DUMPABLE",
        "RLIMIT_CORE",
        "PR_SET_PDEATHSIG",
        "SIGKILL",
        "setpgid",
        "guard/linux-runtime-process-policy/v1",
    ],
    "Политика Runtime для Linux",
)
ipc = read("runtime/runtime/src/linux_guard.rs")
require(
    ipc,
    [
        "UnixListener",
        "UnixStream",
        "SO_PEERCRED",
        "XDG_RUNTIME_DIR",
        "0o600",
        "client-auth",
        "Hmac",
        "LINUX_PACKAGE_MANIFEST.json",
        "guard-attestation",
        "integrity-evidence",
    ],
    "Аутентифицированный IPC Linux",
)
integrity = read("runtime/runtime/src/integrity.rs")
require(
    integrity,
    [
        "guard/linux-integrity-evidence/v1",
        "/proc/{pid}/maps",
        "/proc/{pid}/status",
        "LinuxProcessSecurityEvidence",
    ],
    "Свидетельства целостности Linux",
)
att = read("runtime/runtime/src/attestation.rs")
require(
    att,
    ["guard/linux-guard-attestation/v1", "Guard Attestation Core Linux v1"],
    "Аттестация Linux",
)
desktop = read("apps/desktop/src-tauri/src/main.rs")
require(
    desktop,
    [
        'target_os = "linux"',
        "GUARD_LINUX_PROCESS_POLICY_VERSION",
        "ensure_linux_production_hardening",
        "не пройдена проверка усиленной защиты Guard для рабочей сборки Linux",
    ],
    "Принудительное применение политик Linux в Desktop",
)
backend = read("services/api/internal/httpapi/guard_attestation.go")
require(
    backend,
    [
        "guardLinuxAttestationSchema0137",
        "guardLinuxIntegritySchema0137",
        "guardLinuxProcessPolicySchema0137",
        "isLinuxDevicePlatform0137",
        "Проверка политики процесса Guard в Linux не пройдена",
    ],
    "Проверка Linux на Backend",
)
release = read("scripts/release/build-linux-desktop.sh")
require(
    release,
    [
        "guard-linux-amd64",
        "LINUX_PACKAGE_MANIFEST.json",
        "GUARD_RELEASE_ALLOWLIST_LINUX.json",
        "sha256sum",
    ],
    "Релизный пакет Linux",
)
ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        "guard_linux",
        "build-linux-desktop.sh",
        "linux-production-implementation.py",
    ],
    "Обязательная проверка Linux в CI",
)
preflight = read("scripts/release/preflight.sh")
require(preflight, ["linux-production-implementation.py"], "Предварительная обязательная проверка Linux")
print("Launcher 0.13.7: проверка готовности Linux: OK")
