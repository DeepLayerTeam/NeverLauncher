#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[3]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def require(ok, msg):
    if not ok:
        raise SystemExit(msg)


version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 10), "Требуется VERSION не ниже 0.20.10")

required = [
    "sdk/backend/go/go.mod",
    "sdk/backend/go/client.go",
    "sdk/backend/go/types_generated.go",
    "sdk/backend/go/openapi_generated.go",
    "sdk/backend/go/api_types_generated.go",
    "sdk/cli/go/go.mod",
    "sdk/cli/go/client.go",
    "sdk/cli/go/types_generated.go",
    "sdk/cli/go/openapi_generated.go",
    "sdk/cli/go/api_types_generated.go",
    "sdk/admin/typescript/package.json",
    "sdk/admin/typescript/launcher-admin.ts",
    "sdk/admin/typescript/generated.ts",
    "sdk/admin/typescript/openapi-generated.ts",
    "sdk/admin/typescript/api-types-generated.ts",
    "sdk/admin/typescript/api-requests-generated.ts",
    "sdk/desktop/typescript/package.json",
    "sdk/desktop/typescript/launcher-desktop.ts",
    "sdk/desktop/typescript/generated.ts",
    "sdk/desktop/typescript/openapi-generated.ts",
    "sdk/desktop/typescript/api-types-generated.ts",
    "sdk/desktop/typescript/api-requests-generated.ts",
    "sdk/desktop/rust/Cargo.toml",
    "sdk/desktop/rust/src/lib.rs",
    "sdk/desktop/rust/src/generated.rs",
    "sdk/api/extension-host-protocol.json",
    "sdk/api/openapi-operations-generated.json",
    "scripts/sdk/generate-types.py",
    "cli/cmd/launcher/extension_sdk_02010.go",
]
for rel in required:
    require((ROOT / rel).is_file(), f"Отсутствует обязательный файл SDK: {rel}")

backend = read("sdk/backend/go/client.go")
for token in (
    "NewFromEnvironment",
    "Hello",
    "HeartbeatLoop",
    "Capability",
    "StartCallbackServer",
    "Subscribe",
    "Unsubscribe",
    "LAUNCHER_EXTENSION_HOST_TOKEN",
):
    require(token in backend, f"В Go SDK Backend отсутствует: {token}")
cli_sdk = read("sdk/cli/go/client.go")
for token in ("NewApp", "Command", "Main", "Hello", "Capability", "ExitError"):
    require(token in cli_sdk, f"В Go SDK CLI отсутствует: {token}")
admin = read("sdk/admin/typescript/launcher-admin.ts")
for token in (
    "LauncherAdminBridge",
    "event.source!==window.parent",
    "rpc.request",
    "close()",
):
    require(
        token.replace(" ", "") in admin.replace(" ", ""),
        f"В TypeScript SDK Admin отсутствует: {token}",
    )
desktop = read("sdk/desktop/typescript/launcher-desktop.ts")
for token in (
    "LauncherDesktopBridge",
    "tauri.platform",
    "tauri.openGameDirectory",
    "event.source!==window.parent",
):
    require(
        token.replace(" ", "") in desktop.replace(" ", ""),
        f"В TypeScript SDK Desktop отсутствует: {token}",
    )
rust = read("sdk/desktop/rust/src/lib.rs")
for token in ("RpcRequest", "DESKTOP_PROTOCOL_VERSION", "validate"):
    require(token in rust, f"В Rust SDK Desktop отсутствует: {token}")

cmd = read("cli/cmd/launcher/extension_sdk_02010.go")
for token in (
    "extensionInit02010",
    "extensionBuildCommand02010",
    "extensionTest02010",
    "extensionDev02010",
    "localDevHost02010",
    "127.0.0.1:0",
    "LAUNCHER_EXTENSION_HOST_TOKEN",
    "LAUNCHER_EXTENSION_CALLBACK_TOKEN",
    "--fixtures",
    "--grant",
    "packExtensionPackage0202",
    "verifyExtensionPackage0202",
):
    require(token in cmd, f"В сценарии CLI SDK отсутствует: {token}")
require(
    'return "backend/bin/extension-backend"'
    in read("cli/cmd/launcher/project_commands.go"),
    "Точка входа Backend SDK должна указывать на исполняемый файл",
)
routing = read("cli/cmd/launcher/extension_commands_0201.go")
require(
    'case "init", "dev", "test", "build"' in routing,
    "Маршрутизация команд SDK расширений отсутствует",
)

spec = json.loads(read("sdk/api/extension-host-protocol.json"))
require(
    spec.get("hostProtocolVersion") == "1.0",
    "Источник сгенерированных типов Host Protocol не совпадает с ожидаемым",
)
ops = json.loads(read("sdk/api/openapi-operations-generated.json"))
require(
    len(ops) >= 20 and all("extension" in item["path"].lower() for item in ops),
    "Сгенерированные операции OpenAPI для расширений неполные",
)

for example in ("backend-health", "cli-status", "admin-dashboard", "desktop-tool"):
    root = ROOT / "examples/extensions" / example
    require((root / "launcher-extension.json").is_file(), f"Отсутствует пример: {example}")

print("Extensions SDK 0.20.10: проверка готовности к эксплуатации: OK")
