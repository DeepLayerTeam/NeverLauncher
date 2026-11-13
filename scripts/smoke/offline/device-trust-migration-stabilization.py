#!/usr/bin/env python3
from __future__ import annotations
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        raise SystemExit(f"Отсутствует обязательный файл: {path}")
    return p.read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [item for item in needles if item not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствуют {', '.join(missing)}")


version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
try:
    version_tuple = tuple(int(part) for part in version.split("."))
except ValueError as exc:
    raise SystemExit(f"Некорректное значение VERSION: {version}") from exc
if version_tuple < (0, 12, 10):
    raise SystemExit(f"Версия: требуется версия не ниже 0.12.10, получено {version}")

migration_api = read(
    "services/api/internal/dbmigrate/sql/0018_device_trust_stabilization.sql"
)
migration_cli = resource_read_text(ROOT, "cli/internal/dbmigrate/sql/0018_device_trust_stabilization.sql")
if migration_api != migration_cli:
    raise SystemExit("Миграция 0018 API/CLI 0.12.10 отличается")
require(
    migration_api,
    [
        "key-rotate",
        "key-recover",
        "device_challenges_purpose_check",
        "trusted_devices_lifecycle_check",
        "trusted_devices_replacement_shape_check",
        "auth_sessions_device_binding_shape_check",
        "trusted_devices_id_user_key",
        "auth_sessions_trusted_device_owner_fk",
        "trusted_devices_replacement_owner_fk",
        "minecraft_sessions_session_owner_fk",
        "minecraft_sessions_device_owner_fk",
        "minecraft_sessions_profile_owner_fk",
        "legacy-device-revoked",
        "UPDATE minecraft_sessions SET trusted_device_id=NULL",
    ],
    "Миграция стабилизации 0.12.10",
)

repo_devices = read("services/api/internal/repository/devices.go")
repo_postgres = read("services/api/internal/repository/postgres.go")
require(
    repo_devices,
    [
        "var replacedBy sql.NullString",
        "d.ReplacedByDeviceID = replacedBy.String",
        "NULL,NULL,'')",
        "ON CONFLICT DO NOTHING RETURNING",
    ],
    "Путь к хранилищу замен с поддержкой пустого значения",
)
require(
    repo_postgres,
    [
        "func nullText(value string) any",
        "nullText(item.TrustedDeviceID)",
        "var trustedDeviceID sql.NullString",
        "item.TrustedDeviceID = trustedDeviceID.String",
    ],
    "Путь к хранилищу снимков доверия Minecraft с поддержкой пустого значения",
)

upgrade_e2e = read("e2e/scripts/run-device-trust-migration-e2e.sh")
require(
    upgrade_e2e,
    [
        "0017_device_key_recovery_rotation_0128",
        "0018_device_trust_stabilization_01210",
        "0.12.9 schema (0001..0017)",
        "key-rotate",
        "key-recover",
        "cross-user auth session/device binding unexpectedly succeeded",
        "cross-user replacement link unexpectedly succeeded",
        "cross-user Minecraft device snapshot unexpectedly succeeded",
        "migration-stabilization.json",
    ],
    "Сквозная проверка обновления PostgreSQL 0.12.10",
)

protocol_e2e = read("e2e/scripts/run-device-trust-e2e.sh")
require(
    protocol_e2e,
    [
        "migrationStabilization01210:true",
        "migration-upgrade-e2e.json",
        "run-device-trust-migration-e2e.sh first",
        "0018_device_trust_stabilization_01210",
    ],
    "Публичные свидетельства проверки протокола 0.12.10",
)

targets = json.loads(read("device-trust/targets.json"))
if targets.get("productVersion") != version:
    raise SystemExit("Цели доверия устройств должны соответствовать канонической VERSION")
protocol_targets = [
    row for row in targets.get("targets", []) if row.get("kind") == "protocol-e2e"
]
if len(protocol_targets) != 1 or "migrationStabilization01210" not in protocol_targets[
    0
].get("requiredChecks", []):
    raise SystemExit(
        "Публичная проверка протокола доверия должна требовать migrationStabilization01210"
    )

matrix = read("scripts/device_trust/matrix.py")
require(
    matrix,
    ["migrationStabilization01210", "migration stabilization 0.12.10"],
    "Публичная матрица доверия",
)

preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
workflow = read(".github/workflows/device-trust.yml")
for text, label in [(preflight, "preflight"), (ci, "main CI")]:
    if "device-trust-migration-stabilization.py" not in text:
        raise SystemExit(f"0.12.10: проверка выпуска не подключена к {label}")
    if "run-device-trust-migration-e2e.sh" not in text:
        raise SystemExit(f"0.12.10: E2E-проверка обновления не подключена к {label}")
require(
    workflow,
    [
        "run-device-trust-migration-e2e.sh",
        "run-device-trust-e2e.sh",
        "e2e/device-trust-migration-result/",
        "matrix.py aggregate",
    ],
    "публичный сценарий проверки доверия к устройствам",
)

# Необязательные производственные инструкции и контрольный список не ограничивают безопасность миграций.

subprocess.run(
    ["bash", "-n", str(ROOT / "e2e/scripts/run-device-trust-migration-e2e.sh")],
    check=True,
)
subprocess.run(
    ["bash", "-n", str(ROOT / "e2e/scripts/run-device-trust-e2e.sh")], check=True
)
subprocess.run(
    [
        "go",
        "test",
        "-tags",
        "launcher_nopgx",
        "./internal/dbmigrate",
        "./internal/repository",
        "./internal/httpapi",
    ],
    cwd=ROOT / "services/api",
    check=True,
)
subprocess.run(["go", "test", "./internal/dbmigrate"], cwd=ROOT / "cli", check=True)
subprocess.run(
    [
        sys.executable,
        str(ROOT / "scripts/device_trust/matrix.py"),
        "validate",
        "--targets",
        str(ROOT / "device-trust/targets.json"),
    ],
    check=True,
)
subprocess.run(
    [sys.executable, str(ROOT / "scripts/device_trust/test_matrix.py")], check=True
)
print(f"[Launcher] Доверие к устройствам: миграция и стабилизация 0.12.10 проверены: OK ({version})")
print('Device Trust migration + stabilization 0.12.10 gate OK')
