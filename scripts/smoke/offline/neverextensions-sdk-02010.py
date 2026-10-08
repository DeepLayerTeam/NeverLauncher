#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[3]

def read(rel): return (ROOT / rel).read_text(encoding="utf-8")
def require(ok,msg):
    if not ok: raise SystemExit(msg)

version=tuple(int(x) for x in read("VERSION").strip().split(".")[:3]); require(version >= (0,20,10),"VERSION must be >= 0.20.10")

required = [
    "sdk/backend/go/go.mod", "sdk/backend/go/client.go", "sdk/backend/go/types_generated.go", "sdk/backend/go/openapi_generated.go", "sdk/backend/go/api_types_generated.go",
    "sdk/cli/go/go.mod", "sdk/cli/go/client.go", "sdk/cli/go/types_generated.go", "sdk/cli/go/openapi_generated.go", "sdk/cli/go/api_types_generated.go",
    "sdk/admin/typescript/package.json", "sdk/admin/typescript/neverlauncher-admin.ts", "sdk/admin/typescript/generated.ts", "sdk/admin/typescript/openapi-generated.ts", "sdk/admin/typescript/api-types-generated.ts", "sdk/admin/typescript/api-requests-generated.ts",
    "sdk/desktop/typescript/package.json", "sdk/desktop/typescript/neverlauncher-desktop.ts", "sdk/desktop/typescript/generated.ts", "sdk/desktop/typescript/openapi-generated.ts", "sdk/desktop/typescript/api-types-generated.ts", "sdk/desktop/typescript/api-requests-generated.ts",
    "sdk/desktop/rust/Cargo.toml", "sdk/desktop/rust/src/lib.rs", "sdk/desktop/rust/src/generated.rs",
    "sdk/api/extension-host-protocol.json", "sdk/api/openapi-operations-generated.json", "scripts/sdk/generate-types.py",
    "cli/cmd/neverlauncher/extension_sdk_02010.go",
]
for rel in required: require((ROOT/rel).is_file(), f"missing SDK production file {rel}")

backend=read("sdk/backend/go/client.go")
for token in ("NewFromEnvironment", "Hello", "HeartbeatLoop", "Capability", "StartCallbackServer", "Subscribe", "Unsubscribe", "NEVERLAUNCHER_EXTENSION_HOST_TOKEN"):
    require(token in backend, f"Backend Go SDK missing {token}")
cli_sdk=read("sdk/cli/go/client.go")
for token in ("NewApp", "Command", "Main", "Hello", "Capability", "ExitError"):
    require(token in cli_sdk, f"CLI Go SDK missing {token}")
admin=read("sdk/admin/typescript/neverlauncher-admin.ts")
for token in ("NeverLauncherAdminBridge", "event.source!==window.parent", "rpc.request", "close()"):
    require(token.replace(" ","") in admin.replace(" ",""), f"Admin TypeScript SDK missing {token}")
desktop=read("sdk/desktop/typescript/neverlauncher-desktop.ts")
for token in ("NeverLauncherDesktopBridge", "tauri.platform", "tauri.openGameDirectory", "event.source!==window.parent"):
    require(token.replace(" ","") in desktop.replace(" ",""), f"Desktop TypeScript SDK missing {token}")
rust=read("sdk/desktop/rust/src/lib.rs")
for token in ("RpcRequest", "DESKTOP_PROTOCOL_VERSION", "validate"):
    require(token in rust, f"Desktop Rust SDK missing {token}")

cmd=read("cli/cmd/neverlauncher/extension_sdk_02010.go")
for token in ("extensionInit02010", "extensionBuildCommand02010", "extensionTest02010", "extensionDev02010", "localDevHost02010", "127.0.0.1:0", "NEVERLAUNCHER_EXTENSION_HOST_TOKEN", "NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN", "--fixtures", "--grant", "packExtensionPackage0202", "verifyExtensionPackage0202"):
    require(token in cmd, f"SDK CLI workflow missing {token}")
require('return "backend/bin/extension-backend"' in read("cli/cmd/neverlauncher/project_commands.go"), "backend SDK entrypoint must be executable payload")
routing=read("cli/cmd/neverlauncher/extension_commands_0201.go")
require('case "init", "dev", "test", "build"' in routing, "extension SDK commands are not routed")

spec=json.loads(read("sdk/api/extension-host-protocol.json"))
require(spec.get("hostProtocolVersion")=="1.0", "Host Protocol generated type source mismatch")
ops=json.loads(read("sdk/api/openapi-operations-generated.json"))
require(len(ops)>=20 and all("extension" in item["path"].lower() for item in ops), "generated NeverExtensions OpenAPI operations are incomplete")

for example in ("backend-health","cli-status","admin-dashboard","desktop-tool"):
    root=ROOT/"examples/extensions"/example
    require((root/"neverlauncher-extension.json").is_file(), f"missing example {example}")

print("NeverExtensions SDK 0.20.10 production gate: OK")
