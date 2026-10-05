#!/usr/bin/env python3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
def read(rel): return (ROOT / rel).read_text(encoding="utf-8")
def require(ok,msg):
    if not ok: raise SystemExit(msg)
version=tuple(int(x) for x in read("VERSION").strip().split(".")[:3]); require(version >= (0,20,8),"VERSION must be >= 0.20.8")
model=read("services/api/internal/model/extensions_0201.go")
for token in ("ExtensionAdminContributions","ExtensionAdminPage","ExtensionAdminNavigation","ExtensionAdminWidget","ExtensionAdminAction"):
    require(token in model, f"model missing {token}")
repo=read("services/api/internal/repository/extensions_0201.go")
for token in ("admin contributions require ui:contribute permission","standalone .html entrypoint","normalizeAdminContributions0208"):
    require(token in repo, f"repository admin validation missing {token}")
handler=read("services/api/internal/httpapi/extension_admin_0208.go")
for token in ("neverextensions.admin-rpc.v1","sandbox","ui:contribute","safeAdminEntrypoint0208","Content-Security-Policy","connect-src 'none'","projects.list","releases.list","audit.list","telemetry.emit","ExtensionSecurity.Allowed","canAccessProject","adminExtensionProjectAllowed0208","ExtensionHost.Logs"):
    require(token in handler, f"Admin extension host missing {token}")
routes=read("services/api/internal/httpapi/routes_packages.go")
for path in ("/api/v1/admin/extensions/catalog","/api/v1/admin/extensions/manager","/api/v1/admin/extensions/{extensionId}/ui","/api/v1/admin/extensions/{extensionId}/rpc"):
    require(path in routes, f"Admin extension route missing {path}")
ui=read("apps/admin/src/admin_extensions_0208.tsx")
for token in ('sandbox="allow-scripts"','postMessage','rpc.request','rpc.response','dashboardWidgets','extensionManagerGrid','Host Restart'):
    require(token in ui, f"Admin SPA extension runtime missing {token}")
main=read("apps/admin/src/main.tsx")
require("extensions-manager" in main and "<AdminExtensions" in main, "Admin SPA did not wire Extension Manager/widgets")
cli_scaffold=read("cli/cmd/neverlauncher/project_commands.go")
for token in ('case "admin":','return "index.html"','ui:contribute','neverextensions.admin-rpc.v1'):
    require(token in cli_scaffold, f"Admin SDK scaffold missing {token}")
sdk=read("sdk/admin/typescript/neverlauncher-admin.ts")
for token in ("NeverLauncherAdminBridge","projects.list","releases.list","telemetry.emit"):
    require(token in sdk, f"Admin SDK missing {token}")
schema=read("schemas/neverlauncher-extension.schema.json")
for token in ('"admin"','"dashboardWidgets"','"navigation"','"actions"'):
    require(token in schema, f"extension schema missing {token}")
openapi=read("schemas/openapi.yaml")
for path in ('"/api/v1/admin/extensions/catalog"','"/api/v1/admin/extensions/manager"','"/api/v1/admin/extensions/{extensionId}/ui"','"/api/v1/admin/extensions/{extensionId}/rpc"'):
    require(path in openapi, f"OpenAPI missing {path}")
print("NeverExtensions Admin Extensions 0.20.8 production gate: OK")
