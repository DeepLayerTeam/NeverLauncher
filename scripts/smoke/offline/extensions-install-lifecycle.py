#!/usr/bin/env python3
from __future__ import annotations
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(rel: str) -> str:
    return resource_read_text(ROOT, rel)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)


version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 4), "Требуется VERSION не ниже 0.20.4")

migration = read(
    "services/api/internal/dbmigrate/sql/0044_extensions_install_lifecycle.sql"
)
for token in (
    "desired_version",
    "current_version",
    "desired_state",
    "current_state",
    "generation",
    "extension_install_revisions",
    "launcher_extension_install_state_guard_0204",
    "current_package_identity",
    "activated_at",
):
    require(token in migration, f"Отсутствует миграция жизненного цикла расширений {token}")

repo = read("services/api/internal/repository/extension_lifecycle.go")
for token in (
    "TransitionExtensionInstall",
    "sql.LevelSerializable",
    "pg_advisory_xact_lock",
    "FOR UPDATE",
    "ExpectedGeneration",
    "extension_install_revisions",
):
    require(token in repo, f"Отсутствует репозиторий жизненного цикла расширений {token}")

manager = read("services/api/internal/extensionlifecycle/lifecycle.go")
for token in (
    "ExtractPayloadFile",
    "VerifyFile",
    "acquireOperationLock0204",
    "extensions.lock.json",
    ".staging",
    "backups",
    "activateStaged0204",
    "deactivateCurrent0204",
    "commitWithLockfile0204",
    "Install(",
    "Enable(",
    "Disable(",
    "Uninstall(",
    "Update(",
    "Rollback(",
    "Для области project требуется scopeId",
    "PackageIdentity",
):
    require(token in manager, f"Отсутствует менеджер жизненного цикла расширений {token}")

http = read("services/api/internal/httpapi/extension_lifecycle.go")
routes = read("services/api/internal/httpapi/routes_packages.go")
for token in (
    "extensionInstall0204",
    "extensionEnable0204",
    "extensionDisable0204",
    "extensionUninstall0204",
    "extensionUpdate0204",
    "extensionRollback0204",
    "VerifyLockfile",
):
    require(token in http, f"Отсутствует HTTP-обработчик жизненного цикла расширений {token}")
for suffix in ("/install", "/enable", "/disable", "/uninstall", "/update", "/rollback"):
    require(
        "/api/v1/admin/extension-installs/{extensionId}" + suffix in routes,
        f"Отсутствует маршрут жизненного цикла расширений {suffix}",
    )

cli = read("cli/cmd/launcher/extension_lifecycle.go")
for token in (
    'case "installed", "installations"',
    'case "status"',
    'case "install"',
    'case "enable", "disable", "uninstall", "rollback"',
    'case "update"',
):
    require(token in cli, f"Отсутствует команда CLI для жизненного цикла расширений {token}")

admin = read("apps/admin/src/main.tsx")
for token in (
    "Install Lifecycle",
    "extensionInstalls",
    "lifecycleScopePayload",
    "lifecycleAction",
    "rollback",
    "uninstall",
):
    require(token in admin, f"Отсутствует интерфейс жизненного цикла расширений в Admin {token}")

release = read("cli/cmd/launcher/release_commands.go")
require(
    "extension_install_revisions" in release,
    "В перечне productionTables отсутствует extension_install_revisions",
)

openapi = read("scripts/contracts/generate_openapi.py")
for token in (
    "/api/v1/admin/extension-installs",
    "ExtensionLifecycleWrite",
    "historyLimit",
):
    require(token in openapi, f"Отсутствует генератор OpenAPI {token}")

for envfile in (
    "deploy/production/env.production.example",
    "cli/cmd/launcher/templates/production/env.production.example",
):
    env = read(envfile)
    require("LAUNCHER_EXTENSION_ROOT=" in env, f"{envfile} не указан корневой каталог расширений")
    require(
        "LAUNCHER_EXTENSION_BACKUP_RETENTION=" in env,
        f"{envfile} не задан срок хранения резервных копий",
    )

print("Extensions 0.20.4: проверка жизненного цикла установки: OK")
