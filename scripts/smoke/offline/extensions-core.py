#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[3]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def require(rel, tokens):
    text = read(rel)
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{rel}: отсутствует {missing}")


version = tuple(int(part) for part in read("VERSION").strip().split(".")[:3])
if version < (0, 20, 1):
    raise SystemExit("Версия: требуется «>= 0.20.1»")

schema = json.loads(read("schemas/launcher-extension.schema.json"))
if schema.get("properties", {}).get("schemaVersion", {}).get("const") != "2.0":
    raise SystemExit("каноническая схема расширения: требуется «2.0»")

require(
    "services/api/internal/dbmigrate/sql/0042_extensions_core.sql",
    [
        "CREATE TABLE IF NOT EXISTS extensions",
        "CREATE TABLE IF NOT EXISTS extension_versions",
        "CREATE TABLE IF NOT EXISTS extension_permissions",
        "CREATE TABLE IF NOT EXISTS extension_dependencies",
        "CREATE TABLE IF NOT EXISTS extension_installs",
        "manifest_sha256",
    ],
)
require(
    "services/api/internal/repository/extensions.go",
    [
        "SaveExtensionVersion",
        "sql.LevelSerializable",
        "ErrImmutable",
        "extension_permissions",
        "extension_dependencies",
        "SaveExtensionInstall",
    ],
)
require(
    "services/api/internal/httpapi/extensions.go",
    [
        "adminExtensionVersionRegister0201",
        "extension:version:register",
        "SaveExtensionVersion",
    ],
)
require(
    "cli/cmd/launcher/extension_commands.go",
    [
        "launcher-extension.json",
        "import-legacy",
        "launcher-plugin.json",
        "DisallowUnknownFields",
    ],
)
require(
    "cli/cmd/launcher/release_commands.go",
    [
        '"extension_versions"',
        '"extension_permissions"',
        '"extension_dependencies"',
        '"extension_installs"',
    ],
)
if "registry_entries" in read(
    "cli/cmd/launcher/release_commands.go"
) or "desktop_packages" in read("cli/cmd/launcher/release_commands.go"):
    raise SystemExit("productionTables по-прежнему содержит несуществующие таблицы устаревшей системы расширений")

print("Ядро расширений 0.20.1: проверка готовности к эксплуатации: OK")
