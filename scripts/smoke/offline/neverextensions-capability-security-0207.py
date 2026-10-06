#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)

version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 7), "VERSION must be >= 0.20.7")

migration = read("services/api/internal/dbmigrate/sql/0046_neverextensions_capability_security_0207.sql")
for token in (
    "extension_permission_grants", "extension_secrets", "PRIMARY KEY (extension_id, scope, scope_id, permission)",
    "ciphertext BYTEA", "nonce BYTEA", "octet_length(nonce) = 12", "AES-256-GCM",
):
    require(token in migration, f"capability-security migration missing {token}")

security = read("services/api/internal/extensionsecurity/security_0207.go")
for token in (
    "project:read", "release:read", "storage:read", "telemetry:write", "ui:contribute", "http:outbound",
    "events:subscribe", "events:sync", "secrets:read", "PermissionDiff", "AddedNotGranted", "cipher.NewGCM",
    "Grant(", "Revoke(", "Allowed(", "Effective(", "extension secrets broker is not configured",
):
    require(token in security, f"security manager missing {token}")

host = read("services/api/internal/extensionhost/host_0205.go")
for token in (
    "permissionAllowed0207", "auditCapability0207", 'case "secret.get"', 'case "telemetry.emit"', 'case "http.fetch"',
    "capability policy unavailable", "validateEventPermission0206",
):
    require(token in host, f"Extension Host capability security missing {token}")
http_broker = read("services/api/internal/extensionhost/http_broker_0207.go")
for token in ("https", "IsLoopback", "IsPrivate", "CheckRedirect", "Proxy: nil", "MaxHTTPResponseBytes"):
    require(token in http_broker, f"secure HTTP broker missing {token}")

lifecycle = read("services/api/internal/httpapi/extension_lifecycle_0204.go")
updates = read('services/api/internal/extensionupdates/updates_02011.go') if (ROOT/'services/api/internal/extensionupdates/updates_02011.go').is_file() else ''
require(("AddedNotGranted" in lifecycle and "permissionDiff" in lifecycle) or ("AddedNotGranted" in updates and "PermissionDiff" in updates), "update permission-diff gate missing")

routes = read("services/api/internal/httpapi/routes_packages.go")
for path in (
    "/api/v1/admin/extension-capabilities",
    "/api/v1/admin/extensions/{extensionId}/permissions",
    "/api/v1/admin/extensions/{extensionId}/secrets",
):
    require(path in routes, f"Admin capability route missing {path}")

cli = read("cli/cmd/neverlauncher/extension_security_0207.go")
for token in ("permission-grant", "permission-revoke", "secret-set", "secret-delete", "--stdin", "NEVERLAUNCHER_EXTENSION_SECRET_VALUE"):
    require(token in cli, f"CLI capability security missing {token}")
routing = read("cli/cmd/neverlauncher/extension_commands_0201.go")
require("handleExtensionSecurity0207" in routing and '"permission-grant"' in routing and '"secret-set"' in routing, "CLI capability commands are not wired into nl extension")

prod = read("cli/cmd/neverlauncher/release_commands.go")
for table in ("extension_permission_grants", "extension_secrets"):
    require(table in prod, f"productionTables missing {table}")

openapi = read("schemas/openapi.yaml")
for path in (
    '"/api/v1/admin/extension-capabilities"',
    '"/api/v1/admin/extensions/{extensionId}/permissions"',
    '"/api/v1/admin/extensions/{extensionId}/secrets/{secretName}"',
):
    require(path in openapi, f"OpenAPI missing {path}")

for envfile in ("deploy/production/env.production.example", "cli/cmd/neverlauncher/templates/production/env.production.example"):
    env = read(envfile)
    for key in (
        "NEVERLAUNCHER_EXTENSION_SECRETS_KEY=", "NEVERLAUNCHER_EXTENSION_HTTP_MAX_REQUEST_BYTES=",
        "NEVERLAUNCHER_EXTENSION_HTTP_MAX_RESPONSE_BYTES=", "NEVERLAUNCHER_EXTENSION_HTTP_TIMEOUT_SECONDS=",
    ):
        require(key in env, f"{envfile} missing {key}")

print("NeverExtensions Permissions & Capability Security 0.20.7 production gate: OK")
