#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[3]


def read(rel):
    return resource_read_text(ROOT, rel)


def require(ok, msg):
    if not ok:
        raise SystemExit(msg)


version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 11), "Требуется VERSION не ниже 0.20.11")
required = [
    "services/api/internal/extensionresolver/semver.go",
    "services/api/internal/extensionresolver/resolver.go",
    "services/api/internal/extensionupdates/updates.go",
    "services/api/internal/repository/extension_updates.go",
    "services/api/internal/model/extension_updates.go",
    "services/api/internal/dbmigrate/sql/0047_extensions_dependencies_updates.sql",
    "cli/internal/dbmigrate/sql/0047_extensions_dependencies_updates.sql",
    "cli/cmd/launcher/extension_updates.go",
]
for rel in required:
    require(resource_exists(ROOT, rel), f"Отсутствует рабочий файл зависимостей/обновлений: {rel}")

semver = read("services/api/internal/extensionresolver/semver.go")
for token in ("ParseVersion", "Matches", "^", "~", "||"):
    require(token in semver, f"Отсутствует обработчик версий SemVer: {token}")
resolver = read("services/api/internal/extensionresolver/resolver.go")
for token in (
    "required",
    "optional",
    "conflict",
    "topologicalOrder",
    "cycle",
    "stable",
    "beta",
    "dev",
    "MinAPI",
    "MaxAPI",
    "SupportedOS",
    "SupportedArchitectures",
    "ListExtensionUpdatePins",
):
    require(token.lower() in resolver.lower(), f"Отсутствует обработчик зависимостей: {token}")
updates = read("services/api/internal/extensionupdates/updates.go")
for token in (
    "AcquireExtensionUpdateLease",
    "SaveExtensionUpdateTransaction",
    "recoverInterrupted02011",
    "InFlight",
    "PermissionDiff",
    "stale update plan",
    "Rollback",
    "waitHealthy",
    "rollback_failed",
    "PackageIdentity",
):
    require(token in updates, f"Отсутствует движок транзакций: {token}")
repo = read("services/api/internal/repository/extension_updates.go")
for token in (
    "SetExtensionUpdatePin",
    "AcquireExtensionUpdateLease",
    "ReleaseExtensionUpdateLease",
    "SaveExtensionUpdateTransaction",
    "GetExtensionUpdateTransaction",
):
    require(token in repo, f"Отсутствует репозиторий обновлений: {token}")
migration = read(
    "services/api/internal/dbmigrate/sql/0047_extensions_dependencies_updates.sql"
)
for token in (
    "min_api",
    "max_api",
    "extension_update_pins",
    "extension_update_leases",
    "extension_update_transactions",
    "in_flight",
):
    require(token in migration, f"Отсутствует миграция 0047 {token}")
manifest = json.loads(read("schemas/launcher-extension.schema.json"))
require(
    "conflicts" in manifest.get("properties", {}),
    "В канонической схеме манифеста отсутствует описание конфликтов",
)
routes = read("services/api/internal/httpapi/routes_packages.go")
for token in (
    "/api/v1/admin/extension-updates/plan",
    "/api/v1/admin/extension-updates/apply",
    "/api/v1/admin/extension-updates/pins/{extensionId}",
):
    require(token in routes, f"Отсутствует маршрут API обновлений: {token}")
legacy = read("services/api/internal/httpapi/extension_lifecycle.go")
require(
    "resolver02011" in legacy and "updateManager02011" in legacy,
    "Старый путь обновления обходит транзакционный механизм учёта зависимостей",
)
cli = read("cli/cmd/launcher/extension_updates.go")
for token in ("plan", "apply", "pins", "pin", "unpin", "transaction"):
    require(token in cli, f"Отсутствует сценарий обновления CLI: {token}")
tables = read("cli/cmd/launcher/release_commands.go")
for token in (
    "extension_update_pins",
    "extension_update_leases",
    "extension_update_transactions",
):
    require(token in tables, f"Отсутствует запись в productionTables: {token}")
print("Extensions 0.20.11: проверка зависимостей и обновлений: OK")
