#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def require(ok, msg):
    if not ok:
        raise SystemExit(msg)


version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 8), "Требуется VERSION не ниже 0.20.8")
model = read("services/api/internal/model/extensions.go")
for token in (
    "ExtensionAdminContributions",
    "ExtensionAdminPage",
    "ExtensionAdminNavigation",
    "ExtensionAdminWidget",
    "ExtensionAdminAction",
):
    require(token in model, f"В модели отсутствует: {token}")
repo = read("services/api/internal/repository/extensions.go")
for token in (
    "Для дополнений Admin требуется разрешение ui:contribute",
    "standalone .html entrypoint",
    "normalizeAdminContributions0208",
):
    require(token in repo, f"В репозитории отсутствует проверка Admin: {token}")
handler = read("services/api/internal/httpapi/extension_admin.go")
for token in (
    "extensions.admin-rpc.v1",
    "sandbox",
    "ui:contribute",
    "safeAdminEntrypoint0208",
    "Content-Security-Policy",
    "connect-src 'none'",
    "projects.list",
    "releases.list",
    "audit.list",
    "telemetry.emit",
    "ExtensionSecurity.Allowed",
    "canAccessProject",
    "adminExtensionProjectAllowed0208",
    "ExtensionHost.Logs",
):
    require(token in handler, f"В Host расширений Admin отсутствует: {token}")
routes = read("services/api/internal/httpapi/routes_packages.go")
for path in (
    "/api/v1/admin/extensions/catalog",
    "/api/v1/admin/extensions/manager",
    "/api/v1/admin/extensions/{extensionId}/ui",
    "/api/v1/admin/extensions/{extensionId}/rpc",
):
    require(path in routes, f"Отсутствует маршрут расширений Admin: {path}")
ui = read("apps/admin/src/admin_extensions.tsx")
for token in (
    'sandbox="allow-scripts"',
    "postMessage",
    "rpc.request",
    "rpc.response",
    "dashboardWidgets",
    "extensionManagerGrid",
    "Host Restart",
):
    require(token in ui, f"В среде выполнения расширений Admin отсутствует: {token}")
main = read("apps/admin/src/main.tsx")
require(
    "extensions-manager" in main and "<AdminExtensions" in main,
    "В интерфейсе Admin не подключены менеджер расширений или виджеты",
)
cli_scaffold = read("cli/cmd/launcher/project_commands.go") + read(
    "cli/cmd/launcher/extension_sdk.go"
)
for token in ('case "admin":', "admin/index.html", "ui:contribute", "uiTemplate02010"):
    require(token in cli_scaffold, f"В шаблоне Admin SDK отсутствует: {token}")
sdk = read("sdk/admin/typescript/launcher-admin.ts")
for token in (
    "LauncherAdminBridge",
    "projects.list",
    "releases.list",
    "telemetry.emit",
):
    require(token in sdk, f"В Admin SDK отсутствует: {token}")
schema = read("schemas/launcher-extension.schema.json")
for token in ('"admin"', '"dashboardWidgets"', '"navigation"', '"actions"'):
    require(token in schema, f"В схеме расширения отсутствует: {token}")
openapi = read("schemas/openapi.yaml")
for path in (
    '"/api/v1/admin/extensions/catalog"',
    '"/api/v1/admin/extensions/manager"',
    '"/api/v1/admin/extensions/{extensionId}/ui"',
    '"/api/v1/admin/extensions/{extensionId}/rpc"',
):
    require(path in openapi, f"В OpenAPI отсутствует {path}")
print("Администрирование расширений 0.20.8: проверка готовности к эксплуатации: OK")
