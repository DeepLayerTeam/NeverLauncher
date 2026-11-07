#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствуют {', '.join(missing)}")


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"Некорректное значение VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 13, 4):
    raise SystemExit(f"Guard Guard Attestation gate: требуется «>=0.13.4, got» {version}")

attestation = read("runtime/runtime/src/attestation.rs")
require(
    attestation,
    [
        "guard/windows-guard-attestation/v1",
        "Launcher Guard Attestation Core v1",
        "challenge_sha256",
        "recompute_attestation_sha256",
        "process_policy",
        "evidence_sha256",
        "session_proof",
    ],
    "Аттестация Guard с привязкой к запросу",
)

guard = read("runtime/runtime/src/guard_ipc.rs")
require(
    guard,
    [
        "GUARD_PROTOCOL_VERSION: u32 = 4",
        "send_command_with_payload",
        '"guard-attestation"',
        "GuardAttestationRequest",
        "GuardRemoteAttestation",
        "attestation_session_proof",
        "validate_remote_attestation",
    ],
    "Аутентифицированный IPC аттестации Guard",
)

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(
    desktop,
    [
        "guard_guard_attestation",
        ".remote_attestation(",
        "sign_guard_attestation",
        "hardware_bound",
    ],
    "Команда аттестации Guard в Desktop",
)

device_keys = read("apps/desktop/src-tauri/src/device_keys.rs")
require(
    device_keys,
    [
        "Launcher Guard Attestation Device Binding v1",
        "purpose=guard-attest",
        "sign_guard_attestation",
        "attestation-sha256=",
        "evidence-sha256=",
    ],
    "Привязка Guard к аппаратному ключу устройства",
)

frontend = read("apps/desktop/src/main.tsx")
require(
    frontend,
    [
        "createGuardLaunchTicket",
        "/guard-attest/begin",
        "guard_guard_attestation",
        "/guard-attest/complete",
        "guardAttestationTicket",
    ],
    "Сквозной процесс проверки Guard в Desktop",
)

guard_purpose_migration_api = read(
    "services/api/internal/dbmigrate/sql/0031_guard_attestation_challenge_purposes_0161.sql"
)
guard_purpose_migration_cli = resource_read_text(ROOT, "cli/internal/dbmigrate/sql/0031_guard_attestation_challenge_purposes_0161.sql")
if guard_purpose_migration_api != guard_purpose_migration_cli:
    raise SystemExit("Миграция назначения проверочного запроса Guard 0.16.1 отличается между API и CLI")
require(
    guard_purpose_migration_api,
    [
        "device_challenges_purpose_check",
        "guard-attest-v1",
        "guard-launch-v1",
        "key-rotate",
        "key-recover",
    ],
    "Схема PostgreSQL для назначения запроса Guard",
)

guard_migration_e2e = read("e2e/scripts/run-device-trust-migration-e2e.sh")
require(
    guard_migration_e2e,
    [
        "0031_guard_attestation_challenge_purposes_0161",
        "dtmig-guard-attest",
        "guard-attest-v1",
        "dtmig-guard-launch",
        "guard-launch-v1",
        "guardPurposeMigrationSealed:true",
    ],
    "Сквозная миграция PostgreSQL для назначения запроса Guard",
)

backend = read("services/api/internal/httpapi/guard_attestation_0134.go")
require(
    backend,
    [
        "guardAttestationChallengeTTL0134",
        "canonicalGuardAttestationTime0134",
        "Truncate(time.Microsecond)",
        "guardLaunchTicketTTL0134",
        "SaveDeviceChallenge",
        "ConsumeDeviceChallenge",
        "validateGuardAttestation0134",
        "verifyDeviceSignature0123",
        "Guard/Desktop release hash is not allowlisted",
        "guard-launch-v1",
        "consumeGuardLaunchTicket0134",
        "isWindowsDevicePlatform0134",
    ],
    "Проверка Guard и защита от повторов на Backend",
)

minecraft = read("services/api/internal/httpapi/minecraft_auth_119.go")
require(
    minecraft,
    [
        "GuardAttestationTicket",
        "guardAttestationRequiredForSession0134",
        "consumeGuardLaunchTicket0134",
    ],
    "Обязательная проверка билета Guard для сеанса Minecraft",
)

config = read("services/api/internal/config/config.go")
require(
    config,
    [
        "GuardReleaseAllowlistJSON",
        "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
        "обязателен в production",
    ],
    "Настройка списка разрешённых файлов промышленного релиза",
)

backend_test = read("services/api/internal/httpapi/guard_attestation_0134_test.go")
require(
    backend_test,
    [
        "TestGuardAttestationBackendVerificationAndOneTimeLaunchTicket0134",
        "guardAttestationTicket",
        "http.StatusCreated",
        "http.StatusPreconditionFailed",
        "TestGuardAttestationRejectsReleaseHashOutsideAllowlist0134",
    ],
    "Сквозные тесты аттестации Guard на Backend",
)

integration = read("runtime/runtime/tests/guard_windows.rs")
require(
    integration,
    [
        ".remote_attestation(",
        "GUARD_REMOTE_ATTESTATION_SCHEMA",
        "attestation.attestation_sha256.len()",
    ],
    "Интеграционный тест удалённой аттестации Windows Guard",
)

release = read("scripts/release/build-windows-desktop.ps1")
require(
    release,
    [
        "GuardProtocolVersion = 4",
        "windows-named-pipe+current-user-system-acl+hmac-sha256-v4",
        "GUARD_RELEASE_ALLOWLIST.json",
        "guardSha256",
        "launcherSha256",
    ],
    "Создание списка разрешённых файлов Windows-релиза",
)

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "guard-guard-attestation-0134.py" not in ci:
    raise SystemExit("Guard 0.13.4: проверка аттестации не подключена к CI")
if "guard-guard-attestation-0134.py" not in preflight:
    raise SystemExit(
        "Guard 0.13.4 Guard Attestation gate: не подключено к предварительной проверке релиза"
    )
require(
    ci,
    [
        "cargo test --manifest-path runtime/runtime/Cargo.toml --lib attestation::tests",
        "cargo test --manifest-path runtime/runtime/Cargo.toml --test guard_windows",
    ],
    "Нативная проверка аттестации Windows Guard в CI",
)

# Документация безопасности Markdown необязательна; выполнение правил проверено выше.
print(
    f"[Launcher] Проверка аттестации Guard и Backend 0.13.4 пройдена: {version}"
)
