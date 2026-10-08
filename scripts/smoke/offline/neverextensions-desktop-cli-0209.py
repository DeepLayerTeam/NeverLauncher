#!/usr/bin/env python3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
def read(rel): return (ROOT / rel).read_text(encoding="utf-8")
def require(ok,msg):
    if not ok: raise SystemExit(msg)
version=tuple(int(x) for x in read("VERSION").strip().split(".")[:3]); require(version >= (0,20,9),"VERSION must be >= 0.20.9")
model=read("services/api/internal/model/extensions_0201.go")
for token in ("ExtensionDesktopContributions","ExtensionDesktopPage","ExtensionDesktopNavigation","ExtensionDesktopAction","ExtensionCLIContributions","ExtensionCLICommand"):
    require(token in model, f"model missing {token}")
security=read("services/api/internal/extensionsecurity/security_0207.go")
for token in ('"desktop:contribute"','"desktop:bridge"','"cli:contribute"'):
    require(token in security, f"capability catalog missing {token}")
host=read("services/api/internal/extensionhost/cli_0209.go")
for token in ("RunCLI0209","NEVERLAUNCHER_EXTENSION_TARGET",'"cli"',"NEVERLAUNCHER_EXTENSION_HOST_TOKEN","safeEntrypoint","sanitizedEnvironment","helloCh","MaxMemoryBytes","MaxProcesses"):
    require(token in host, f"CLI Extension Host missing {token}")
handler=read("services/api/internal/httpapi/extension_desktop_cli_0209.go")
for token in ("neverextensions.desktop-rpc.v1","desktop:contribute","desktop:bridge","BridgeAllowed","safeAdminEntrypoint0208","hardenAdminHTML0208","project.get","releases.list","RunCLI0209","cli:contribute"):
    require(token in handler, f"Desktop/CLI HTTP host missing {token}")
routes=read("services/api/internal/httpapi/routes_packages.go")
for path in ("/api/v1/desktop/extensions/catalog","/api/v1/desktop/extensions/{extensionId}/ui","/api/v1/desktop/extensions/{extensionId}/rpc","/api/v1/admin/extension-cli/catalog","/api/v1/admin/extension-cli/{extensionId}/invoke"):
    require(path in routes, f"route missing {path}")
desktop=read("apps/desktop/src/extensions_0209.tsx")
for token in ('sandbox="allow-scripts"',"event.source !== frame","postMessage","neverextensions.desktop-rpc.v1","desktop:bridge","tauri.platform","tauri.openGameDirectory","desktop_extension_platform_info"):
    require(token in desktop, f"Desktop runtime missing {token}")
tauri=read("apps/desktop/src-tauri/src/main.rs")
for token in ("desktop_extension_platform_info","neverextensions.desktop-rpc.v1","generate_handler"):
    require(token in tauri, f"Tauri limited bridge missing {token}")
cli=read("cli/cmd/neverlauncher/extension_cli_0209.go")
for token in ("handleExtensionNamespace0209","extensionCLICompletion0209","/api/v1/admin/extension-cli/catalog","/invoke","namespace"):
    require(token in cli, f"CLI namespace runtime missing {token}")
scaffold=read("cli/cmd/neverlauncher/project_commands.go") + read("cli/cmd/neverlauncher/extension_sdk_02010.go")
for token in ('return "desktop/index.html"','return "cli/bin/extension-cli"',"uiTemplate02010","NEVERLAUNCHER_EXTENSION_HOST_URL","/v1/hello"):
    require(token in scaffold, f"SDK scaffold missing {token}")
schema=read("schemas/neverlauncher-extension.schema.json")
for token in ('"desktop"','"cli"','"namespace"','"commands"'):
    require(token in schema, f"extension schema missing {token}")
rpc_schema=read("schemas/neverlauncher-desktop-extension-rpc.schema.json")
require("neverextensions.desktop-rpc.v1" in rpc_schema, "Desktop RPC schema missing protocol")
openapi=read("schemas/openapi.yaml")
for path in ('"/api/v1/desktop/extensions/catalog"','"/api/v1/desktop/extensions/{extensionId}/ui"','"/api/v1/desktop/extensions/{extensionId}/rpc"','"/api/v1/admin/extension-cli/catalog"','"/api/v1/admin/extension-cli/{extensionId}/invoke"'):
    require(path in openapi, f"OpenAPI missing {path}")
print("NeverExtensions Настольное приложение и CLI Расширения 0.20.9 рабочий контроль: OK")
