#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)

version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 4), "VERSION must be >= 0.20.4")

migration = read("services/api/internal/dbmigrate/sql/0044_neverextensions_install_lifecycle_0204.sql")
for token in (
    "desired_version", "current_version", "desired_state", "current_state", "generation",
    "extension_install_revisions", "neverlauncher_extension_install_state_guard_0204",
    "current_package_identity", "activated_at",
):
    require(token in migration, f"lifecycle migration missing {token}")

repo = read("services/api/internal/repository/extension_lifecycle_0204.go")
for token in (
    "TransitionExtensionInstall", "sql.LevelSerializable", "pg_advisory_xact_lock",
    "FOR UPDATE", "ExpectedGeneration", "extension_install_revisions",
):
    require(token in repo, f"lifecycle repository missing {token}")

manager = read("services/api/internal/extensionlifecycle/lifecycle_0204.go")
for token in (
    "ExtractPayloadFile", "VerifyFile", "acquireOperationLock0204", "neverextensions.lock.json",
    ".staging", "backups", "activateStaged0204", "deactivateCurrent0204",
    "commitWithLockfile0204", "Install(", "Enable(", "Disable(", "Uninstall(", "Update(", "Rollback(",
    "project scope requires scopeId", "PackageIdentity",
):
    require(token in manager, f"lifecycle manager missing {token}")

http = read("services/api/internal/httpapi/extension_lifecycle_0204.go")
routes = read("services/api/internal/httpapi/routes_packages.go")
for token in (
    "extensionInstall0204", "extensionEnable0204", "extensionDisable0204", "extensionUninstall0204",
    "extensionUpdate0204", "extensionRollback0204", "VerifyLockfile",
):
    require(token in http, f"lifecycle HTTP missing {token}")
for suffix in ("/install", "/enable", "/disable", "/uninstall", "/update", "/rollback"):
    require("/api/v1/admin/extension-installs/{extensionId}" + suffix in routes, f"lifecycle route missing {suffix}")

cli = read("cli/cmd/neverlauncher/extension_lifecycle_0204.go")
for token in ('case "installed", "installations"', 'case "status"', 'case "install"', 'case "enable", "disable", "uninstall", "rollback"', 'case "update"'):
    require(token in cli, f"lifecycle CLI missing {token}")

admin = read("apps/admin/src/main.tsx")
for token in ("Install Lifecycle", "extensionInstalls", "lifecycleScopePayload", "lifecycleAction", "rollback", "uninstall"):
    require(token in admin, f"Admin lifecycle UI missing {token}")

release = read("cli/cmd/neverlauncher/release_commands.go")
require("extension_install_revisions" in release, "productionTables missing extension_install_revisions")

openapi = read("scripts/contracts/generate_openapi.py")
for token in ("/api/v1/admin/extension-installs", "ExtensionLifecycleWrite", "historyLimit"):
    require(token in openapi, f"OpenAPI generator missing {token}")

for envfile in ("deploy/production/env.production.example", "cli/cmd/neverlauncher/templates/production/env.production.example"):
    env = read(envfile)
    require("NEVERLAUNCHER_EXTENSION_ROOT=" in env, f"{envfile} missing extension root")
    require("NEVERLAUNCHER_EXTENSION_BACKUP_RETENTION=" in env, f"{envfile} missing backup retention")

print("NeverExtensions Установка Жизненный цикл 0.20.4 рабочий контроль: OK")
