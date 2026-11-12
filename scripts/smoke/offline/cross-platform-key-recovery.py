#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path
import subprocess, sys

ROOT = Path(__file__).resolve().parents[3]


def read(path):
    p = ROOT / path
    if not p.is_file():
        raise SystemExit(f"Отсутствует обязательный файл: {path}")
    return p.read_text(encoding="utf-8")


def require(text, needles, label):
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствуют {', '.join(missing)}")


version = (ROOT / "VERSION").read_text().strip()
try:
    version_tuple = tuple(int(part) for part in version.split("."))
except ValueError as exc:
    raise SystemExit(f"Некорректное значение VERSION: {version}") from exc
if version_tuple < (0, 12, 8):
    raise SystemExit(f"Версия: требуется версия не ниже 0.12.8, получено {version}")

handler = read("services/api/internal/httpapi/device_key_recovery.go")
repo = read("services/api/internal/repository/devices.go")
model = read("services/api/internal/model/model.go")
routes = read("services/api/internal/httpapi/routes_auth.go")
native = read("apps/desktop/src-tauri/src/device_keys.rs")
tauri = read("apps/desktop/src-tauri/src/main.rs")
desktop = read("apps/desktop/src/main.tsx")
migration_api = read(
    "services/api/internal/dbmigrate/sql/0017_device_key_recovery_rotation.sql"
)
migration_cli = resource_read_text(ROOT, "cli/internal/dbmigrate/sql/0017_device_key_recovery_rotation.sql")
tests = read("services/api/internal/httpapi/device_key_recovery_test.go")

require(
    handler,
    [
        "Launcher Device Key Replacement v1",
        'purpose := "key-" + mode',
        "oldSignature",
        "newSignature",
        "phishing-resistant",
        "ConsumeDeviceChallenge",
        "ReplaceTrustedDeviceKey",
        "oldFingerprintPermanentTombstone",
    ],
    "Процедура замены ключа",
)
require(
    routes,
    [
        "key-rotation/begin",
        "key-rotation/complete",
        "key-recovery/begin",
        "key-recovery/complete",
    ],
    "Маршруты",
)
require(
    repo,
    [
        "func (r *SQLRepository) ReplaceTrustedDeviceKey",
        "BeginTx",
        "FOR UPDATE",
        "SET CONSTRAINTS ALL DEFERRED",
        "ON CONFLICT DO NOTHING RETURNING",
        "SET CONSTRAINTS ALL IMMEDIATE",
        "binding_epoch=GREATEST(binding_epoch,1)+1",
        "current session changed during replacement",
        "replaced_by_device_id",
        "refresh_token_families",
        "minecraft_sessions",
        "jsonb_build_object('oldDeviceId',$4::text,'newDeviceId',$5::text,'mode',$6::text)",
        "trusted-device-key-replaced",
        "replace trusted device: commit: %w",
    ],
    "Атомарная замена ключа SQL",
)
require(
    model,
    [
        "ReplacedAt",
        "ReplacedByDeviceID",
        "ReplacementReason",
        "DeviceKeyReplacementResult",
    ],
    "Модель замены устройства",
)
if migration_api != migration_cli:
    raise SystemExit("Миграции 0017 для API и CLI различаются")
require(
    migration_api,
    [
        "replaced_at",
        "replaced_by_device_id",
        "replacement_reason",
        "idx_trusted_devices_replacement",
    ],
    "Миграция 0017",
)
require(
    native,
    [
        "hardware_key_label_generation",
        "stage_device_key_replacement",
        "sign_staged_device_replacement",
        "sign_current_device_replacement",
        "commit_staged_device_key",
        "abort_staged_device_key",
        "random_key_generation",
        "staged_keyring_entry",
    ],
    "Жизненный цикл поэтапно активируемого ключа",
)
require(
    tauri,
    [
        "stage_device_key_replacement",
        "sign_staged_device_replacement",
        "sign_current_device_replacement",
        "commit_staged_device_key",
        "abort_staged_device_key",
    ],
    "Граница полномочий команд Tauri",
)
require(
    desktop,
    [
        "replaceDesktopDeviceKey",
        "passkeyStepUp",
        "reconcileStagedReplacement",
        "key-rotation/begin",
        "key-recovery/begin",
        "stage_device_key_replacement",
        "commit_staged_device_key",
        "serverCommitted",
    ],
    "Процесс замены устройства в Desktop",
)
require(
    tests,
    [
        "TestDeviceKeyRotationRequiresOldAndNewProofAndTombstonesOldIdentity0128",
        "TestDeviceKeyRecoveryRequiresFreshPhishingResistantAuthAndOnlyNewKeyProof0128",
        "TestBoundSessionCannotBypassReplacementViaOrdinaryRegistration0128",
    ],
    "Регрессионные проверки 0.12.8",
)

subprocess.run(
    [
        "go",
        "test",
        "-tags",
        "launcher_nopgx",
        "./internal/httpapi",
        "-run",
        "TestDeviceKey(Rotation|Recovery)|TestBoundSessionCannot",
        "-count=1",
    ],
    cwd=ROOT / "services/api",
    check=True,
)
subprocess.run(
    ["go", "test", "-tags", "launcher_nopgx", "./internal/dbmigrate"],
    cwd=ROOT / "services/api",
    check=True,
)
subprocess.run(["go", "test", "./internal/dbmigrate"], cwd=ROOT / "cli", check=True)
print("[Launcher] Кроссплатформенная защита и восстановление/ротация ключей 0.12.8: OK")
