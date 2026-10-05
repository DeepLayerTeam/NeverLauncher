#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


version = tuple(int(part) for part in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 3), "VERSION must be >= 0.20.3")

migration = read("services/api/internal/dbmigrate/sql/0043_neverextensions_registry_0203.sql")
for token in (
    "extension_registry_publishers", "extension_registry_publisher_keys", "extension_registry_versions",
    "extension_registry_compatibility", "extension_registry_artifacts", "extension_registry_channels",
    "package_identity", "signature_key_fingerprint", "neverlauncher_registry_immutable_guard_0203",
    "neverlauncher_registry_channel_guard_0203", "yank state is irreversible",
):
    require(token in migration, f"registry migration missing {token}")

repo = read("services/api/internal/repository/extension_registry_0203.go")
for token in (
    "PublishExtensionRegistryVersion", "SearchExtensionRegistry", "GetExtensionRegistryExtension",
    "SetExtensionRegistryChannel", "YankExtensionRegistryVersion", "sql.LevelSerializable",
    "compatibilityMatches0203", "registry version already exists with different immutable publication metadata",
):
    require(token in repo, f"registry repository missing {token}")

verifier = read("services/api/internal/extensionpackage/package_0203.go")
for token in (
    "InspectSignedFile", "VerifyFile", "ed25519.Verify", "checksums.sha256", "SBOM.spdx.json",
    "signature.ed25519", "case-colliding", "symlink/special", "PackageIdentity",
):
    require(token in verifier, f"server package verifier missing {token}")

http = read("services/api/internal/httpapi/extension_registry_0203.go")
routes = read("services/api/internal/httpapi/routes_packages.go")
for token in (
    "extensionRegistryPublish0203", "extensionRegistrySearch0203", "extensionRegistryYank0203",
    "extensionRegistryChannelSet0203", "extensionRegistryArtifact0203", "extensionRegistryInstall0203",
    "artifact signature verification failed", "registry artifact verification failed",
):
    require(token in http, f"registry HTTP implementation missing {token}")
for route in (
    "/api/v1/admin/extension-registry/publishers",
    "/api/v1/admin/extension-registry/publish",
    "/api/v1/admin/extension-registry/extensions",
    "/versions/{version}/artifact", "/versions/{version}/install", "/versions/{version}/yank", "/channels/{channel}",
):
    require(route in routes, f"registry route missing {route}")

cli = read("cli/cmd/neverlauncher/extension_registry_0203.go")
for token in ('"publishers"', '"publisher-add"', '"key-add"', '"search"', '"list"', '"show"', '"publish"', '"yank"', '"channel-set"', '"pull"', '"install"', "ETag"):
    require(token in cli, f"registry CLI missing {token}")

admin = read("apps/admin/src/main.tsx")
for token in ("NeverExtensions Registry", "Publisher trust", "Publish signed .nlext", "Установить verified artifact", "Registry yank"):
    require(token in admin, f"Admin Registry UI missing {token}")

release = read("cli/cmd/neverlauncher/release_commands.go")
for table in ("extension_registry_publishers", "extension_registry_publisher_keys", "extension_registry_versions", "extension_registry_compatibility", "extension_registry_artifacts", "extension_registry_channels"):
    require(table in release, f"productionTables missing {table}")

openapi_generator = read("scripts/contracts/generate_openapi.py")
for token in ("/api/v1/admin/extension-registry/extensions", "ExtensionRegistryPublisherWrite", "ExtensionRegistryInstallWrite", '"multipart/form-data"'):
    require(token in openapi_generator, f"OpenAPI generator missing registry token {token}")

print("NeverExtensions Registry 0.20.3 production gate: OK")
