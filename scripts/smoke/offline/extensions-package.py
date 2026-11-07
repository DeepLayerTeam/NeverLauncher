#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


version = tuple(int(part) for part in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 2), "Требуется VERSION не ниже 0.20.2")
source = read("cli/cmd/launcher/extension_package_0202.go")
for token in (
    "archive/zip",
    "checksums.sha256",
    "SBOM.spdx.json",
    "signature.ed25519",
    "ed25519.Sign",
    "ed25519.Verify",
    "PackageIdentity",
    "SOURCE_DATE_EPOCH",
    "validateExtensionArchivePath0202",
    "os.ModeSymlink",
    "case-insensitive duplicate",
    "ensureExtensionEntrypointsPresent0202",
):
    require(token in source, f"Отсутствует реализация пакета расширения: {token}")

commands = read("cli/cmd/launcher/extension_commands_0201.go")
for command in ('"pack"', '"sign"', '"verify"', '"inspect"'):
    require(command in commands, f"Отсутствует команда расширений в CLI: {command}")

package_schema = json.loads(read("schemas/launcher-extension-package.schema.json"))
signature_schema = json.loads(read("schemas/launcher-extension-signature.schema.json"))
require(
    package_schema["properties"]["formatVersion"]["const"] == "1.0",
    "В схеме пакета не совпадает версия формата formatVersion",
)
require(
    signature_schema["properties"]["algorithm"]["const"] == "Ed25519",
    "В схеме подписи не совпадает алгоритм",
)

print("Пакет расширений 0.20.2: проверка готовности к эксплуатации: OK")
