#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[3]


def read(p):
    return (ROOT / p).read_text(encoding="utf-8")


def require(cond, msg):
    if not cond:
        raise SystemExit(msg)


product_version = (ROOT / "VERSION").read_text().strip()
version = tuple(int(x) for x in product_version.split(".")[:3])
require(version >= (0, 21, 0), "Требуется VERSION не ниже 0.21.0")
contract = read("services/api/internal/extensioncontract/contract.go")
for token in [
    "PackageFormatVersion",
    "ManifestSchemaVersion",
    "HostProtocolVersion",
    "ExtensionAPIVersion",
    "LegacyExtensionAPIVersion",
    "RequireGAAPIVersion",
    "SupportsHostHello",
]:
    require(token in contract, f"Отсутствует контракт GA: {token}")
registry = read("services/api/internal/httpapi/extension_registry.go")
for token in [
    "RequireGAAPIVersion",
    "extension:registry:reject-contract",
    "quarantineRejectedUpload02012",
]:
    require(token in registry, f"Отсутствует применение требований GA в рабочем реестре: {token}")
host = read("services/api/internal/extensionhost/host.go")
for token in [
    "LAUNCHER_EXTENSION_API_VERSION",
    "SupportsHostHello",
    "extensionApiVersion",
]:
    require(token in host, f"Отсутствует согласование Host API на Backend: {token}")
cli_host = read("services/api/internal/extensionhost/cli.go")
require(
    "LAUNCHER_EXTENSION_API_VERSION" in cli_host,
    "Отсутствует согласование версии Host API в CLI",
)
admin = read("apps/admin/src/admin_extensions.tsx")
desktop = read("apps/desktop/src/extensions.tsx")
require(
    "extensionApiVersion: EXTENSION_API_VERSION" in admin,
    "В контексте Host для Admin отсутствует версия API",
)
require(
    "type: 'host.context', context:" in desktop
    and "extensionApiVersion: EXTENSION_API_VERSION" in desktop,
    "В контексте Host для Desktop отсутствует оболочка сообщения или версия API",
)
ga = read("services/api/internal/extensionga/manager.go")
for token in [
    "VerifyLockfile",
    "EvaluatePublication",
    "IsKnownPermission",
    "dependencies.missing",
    "dependencies.conflict",
    "SetExtensionEmergencyDisable",
    "extension:ga:reconcile:disable",
]:
    require(token in ga, f"Отсутствует согласование состояния GA: {token}")
routes = read("services/api/internal/httpapi/routes_packages.go")
for token in ["/extension-ga/status", "/extension-ga/reconcile"]:
    require(token in routes, f"GA Отсутствует маршрут: {token}")
cli = read("cli/cmd/launcher/extension_ga.go")
for token in [
    "upgrade-source",
    "signed .nlext packages are immutable",
    "requiresRepackAndResign",
    "ExtensionsSDKVersion0210",
    "strings.ReplaceAll",
]:
    require(token in cli, f"Отсутствует средство обновления исходников 0.20 → 0.21: {token}")
mig = read("services/api/internal/dbmigrate/sql/0049_extensions_ga.sql")
for token in [
    "extension_ga_contract",
    "package_format_version",
    "manifest_schema_version",
    "host_protocol_version",
    "extension_api_version",
    "3.7",
]:
    require(token in mig, f"Отсутствует миграция GA: {token}")
spec = json.loads(read("sdk/api/extension-host-protocol.json"))
require(
    spec.get("hostProtocolVersion") == "1.0"
    and spec.get("extensionApiVersion") == "1.0",
    "Версия зафиксированного протокола SDK не совпадает с ожидаемой",
)
require(
    spec["types"]["HelloRequest"].get("extensionApiVersion") == "string",
    "В сообщении приветствия SDK отсутствует поле версии API",
)
for f in ["sdk/admin/typescript/package.json", "sdk/desktop/typescript/package.json"]:
    require(
        json.loads(read(f)).get("version") == "0.21.0",
        f"{f} должен сохранять зафиксированную версию SDK GA 0.21.0",
    )
require(
    'version = "0.21.0"' in read("sdk/desktop/rust/Cargo.toml"),
    "Версия Rust SDK должна оставаться зафиксированной на GA 0.21.0",
)
targets = json.loads(read("extensions/ga-targets.json"))
require(
    {x["os"] for x in targets["targets"] if x.get("required")}
    == {"linux", "windows", "macos"},
    "Неполный набор целевых платформ GA",
)
workflow = read(".github/workflows/extensions-ga.yml")
for token in [
    "ubuntu-latest",
    "windows-latest",
    "macos-latest",
    "EXTENSIONS_GA_CERTIFICATE.json",
    "extensioncontract",
    "extensionga",
    "npm ci",
]:
    require(token in workflow, f"Отсутствует workflow GA: {token}")
print("Extensions GA 0.21.0: офлайн-проверка: OK")
