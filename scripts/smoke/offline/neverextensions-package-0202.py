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
require(version >= (0, 20, 2), "VERSION must be >= 0.20.2")
source = read("cli/cmd/neverlauncher/extension_package_0202.go")
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
    require(token in source, f"extension package implementation missing {token}")

commands = read("cli/cmd/neverlauncher/extension_commands_0201.go")
for command in ('"pack"', '"sign"', '"verify"', '"inspect"'):
    require(command in commands, f"extension CLI missing {command}")

package_schema = json.loads(read("schemas/neverlauncher-extension-package.schema.json"))
signature_schema = json.loads(read("schemas/neverlauncher-extension-signature.schema.json"))
require(package_schema["properties"]["formatVersion"]["const"] == "1.0", "package schema formatVersion mismatch")
require(signature_schema["properties"]["algorithm"]["const"] == "Ed25519", "signature schema algorithm mismatch")

print("NeverExtensions Extension Package 0.20.2 production gate: OK")
