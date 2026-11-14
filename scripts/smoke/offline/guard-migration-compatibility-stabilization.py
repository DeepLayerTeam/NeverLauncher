#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path
import json

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 13, 10):
    raise SystemExit("VERSION ниже 0.13.10")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


api_migration = read(
    "services/api/internal/dbmigrate/sql/0020_guard_migration_compatibility_stabilization.sql"
)
cli_migration = resource_read_text(root, "cli/internal/dbmigrate/sql/0020_guard_migration_compatibility_stabilization.sql")
if api_migration != cli_migration:
    raise SystemExit("Миграции API/CLI 0.13.10 различаются")
require(
    api_migration,
    [
        "minecraft_sessions_guard_snapshot_shape_01310",
        "minecraft_sessions_guard_snapshot_freshness_01310",
        "integrity_verified = FALSE",
        "integrity_verified = TRUE",
        "trusted_device_id IS NOT NULL",
        "105 seconds",
        "partial Guard snapshot",
    ],
    "Миграция стабилизации Guard 0.13.10",
)

integrity = read(
    "services/api/internal/httpapi/minecraft_serverbridge_integrity.go"
)
require(
    integrity,
    [
        "isWindowsDevicePlatform0134(device.Platform)",
        "isLinuxDevicePlatform0137(device.Platform)",
        "isMacOSDevicePlatform0138(device.Platform)",
    ],
    "Совместимость Guard с платформами Minecraft/ServerBridge",
)

tests = read(
    "services/api/internal/httpapi/minecraft_serverbridge_integrity_test.go"
)
require(
    tests,
    ["TestGuardIntegrityRequirementIncludesMacOS01310", "darwin-arm64"],
    "Регрессионный тест Guard для macOS",
)

matrix = read("scripts/guard_ci/matrix.py")
require(
    matrix,
    [
        '"repository": repository',
        '"repository": args.repository',
        "repository=args.repository",
    ],
    "Привязка хранилища Guard в CI",
)

go_release = read("cli/cmd/launcher/guard_ci_release.go")
require(
    go_release,
    [
        "Repository     string",
        "result.Repository != matrix.Repository",
    ],
    "Привязка CLI к хранилищу свидетельств Guard",
)

go_tests = read("cli/cmd/launcher/guard_ci_release_test.go")
require(
    go_tests,
    ["TestGuardCICertificationRejectsRepositoryMismatch01310", "fork/launcher"],
    "Регрессионная проверка несовпадения хранилища CLI",
)

migration_e2e = read("e2e/scripts/run-guard-migration-e2e.sh")
require(
    migration_e2e,
    [
        "(( 10#$ordinal > 19 )) && continue",
        "0019_minecraft_serverbridge_integrity_0135",
        "0020_guard_migration_compatibility_stabilization_01310",
        "ограничение структуры снимка допустило",
        "ограничение актуальности снимка допустило",
    ],
    "Сквозные тесты миграции Guard",
)

legacy_migration_e2e = read("e2e/scripts/run-device-trust-migration-e2e.sh")
require(
    legacy_migration_e2e,
    [
        "(( 10#$ordinal > 17 )) && continue",
        "0017_device_key_recovery_rotation_0128",
    ],
    "Совместимость сквозной миграции старых механизмов доверия устройствам",
)

preflight = read("scripts/release/preflight.sh")
require(
    preflight,
    [
        "guard-migration-compatibility-stabilization.py",
        "run-guard-migration-e2e.sh",
    ],
    "Предварительная проверка релиза",
)
ci = read(".github/workflows/ci.yml")
require(
    ci,
    [
        "guard-migration-compatibility-stabilization.py",
        "run-guard-migration-e2e.sh",
        "launcher-guard-migration-e2e-evidence",
    ],
    "Обязательная проверка CI",
)
if (
    "guard-macos:\n    name: Guard для macOS — промышленная реализация\n    runs-on: macos-14\n    timeout-minutes: 45\n    steps:\n    steps:"
    in ci
):
    raise SystemExit("Задание CI macOS по-прежнему содержит повторяющийся ключ steps")

migration_tests = read("services/api/internal/dbmigrate/migrate_test.go")
latest_migration = "0118_release_snapshot_variable"
require(
    migration_tests,
    [
        f'st.Current != "{latest_migration}"',
        "TestGuardMigrationCompatibilityStabilization01310",
    ],
    "Тесты каталога миграций Backend",
)
cli_migration_tests = read("cli/internal/dbmigrate/migrate_test.go")
require(
    cli_migration_tests,
    [
        "0020_guard_migration_compatibility_stabilization_01310",
        "0021_serverbridge_protocol_v2_0141",
        "0022_serverbridge_crypto_node_identities_0142",
        "0023_one_time_join_tickets_0143",
        "0024_bukkit_family_0144",
        "0025_proxy_family_0145",
        "0026_fabric_server_bridge_0146",
        "0027_forge_neoforge_server_bridge_0147",
        "0028_zero_patch_topology_handoff_0148",
        "0029_serverbridge_public_matrix_ha_hardening_0149",
        "0030_serverbridge_migration_stabilization_01410",
        "0031_guard_attestation_challenge_purposes_0161",
    ],
    "Тесты каталога миграций CLI",
)

# Менеджер версий должен был перенести 0.13.10 в метаданные политики Guard.
targets = json.loads(read("guard-ci/targets.json"))
if targets.get("productVersion") != version:
    raise SystemExit("Цели Guard CI не соответствуют VERSION")

print(
    f"Launcher 0.13.10: проверка миграции Guard, совместимости и стабилизации — OK ({version})"
)
