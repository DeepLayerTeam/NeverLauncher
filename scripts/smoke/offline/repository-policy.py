#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# 1. VERSION — единственный редактируемый источник версии. Обязательные
# package/Cargo/Tauri/env metadata синхронизируются scripts/version/manage.py,
# а исполняемый код получает version через build/runtime integration.
version_check = subprocess.run(
    [sys.executable, str(ROOT / "scripts/version/manage.py"), "check"],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
if version_check.returncode != 0:
    fail("version metadata drift: " + version_check.stdout.strip())

dynamic_version_expectations = {
    "cli/cmd/neverlauncher/main.go": 'var version = "dev"',
    "services/api/cmd/neverlauncher-api/main.go": 'var version = "dev"',
    "apps/admin/src/main.tsx": "const TOOL_VERSION = __NEVERLAUNCHER_VERSION__;",
    "apps/desktop/src/main.tsx": "const DESKTOP_VERSION = __NEVERLAUNCHER_VERSION__;",
    "apps/admin/vite.config.ts": "../../VERSION",
    "apps/desktop/vite.config.ts": "../../VERSION",
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeDefaults.java": "BridgeVersion.VERSION",
    "plugins/bridge-common/build.gradle.kts": "generated/sources/version/java",
    "plugins/proxy-family-common/build.gradle.kts": "version = rootProject.file(\"VERSION\").readText().trim()",
    "plugins/bungee-family-common/build.gradle.kts": "version = rootProject.file(\"VERSION\").readText().trim()",
    "plugins/bukkit-family-common/build.gradle.kts": "version = rootProject.file(\"VERSION\").readText().trim()",
    "plugins/velocity-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/bungeecord-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/waterfall-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/bukkit-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/spigot-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/paper-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/purpur-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/folia-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/fabric-bridge/build.gradle.kts": "version = rootProject.file(\"VERSION\").readText().trim()",
    "e2e/scripts/run-minecraft-e2e.sh": '< "$ROOT/VERSION"',
    "e2e/scripts/run-federation-postgres-e2e.sh": '< "$ROOT/VERSION"',
    "scripts/compatibility/matrix.py": 'PRODUCT_VERSION = (ROOT / "VERSION")',
    "scripts/contracts/generate_openapi.py": 'PRODUCT_VERSION = (ROOT / "VERSION")',
}
for rel, expected in dynamic_version_expectations.items():
    path = ROOT / rel
    if not path.is_file():
        fail(f"отсутствует version integration: {rel}")
    elif expected not in read(rel):
        fail(f"{rel}: отсутствует canonical VERSION integration")

for rel in (
    "plugins/velocity-bridge/src/main/resources/velocity-plugin.json",
    "plugins/bungeecord-bridge/src/main/resources/bungee.yml",
    "plugins/waterfall-bridge/src/main/resources/bungee.yml",
    "plugins/bukkit-bridge/src/main/resources/plugin.yml",
    "plugins/spigot-bridge/src/main/resources/plugin.yml",
    "plugins/paper-bridge/src/main/resources/plugin.yml",
    "plugins/purpur-bridge/src/main/resources/plugin.yml",
    "plugins/folia-bridge/src/main/resources/plugin.yml",
    "plugins/fabric-bridge/src/main/resources/fabric.mod.json",
):
    if "${version}" not in read(rel):
        fail(f"{rel}: plugin descriptor должен получать version из Gradle")

if '"productVersion"' in read("compatibility/targets.json"):
    fail("compatibility/targets.json: productVersion не должен дублировать VERSION")

# 1.1 Backend auto-migrate и `nl db migrate apply` обязаны содержать одну и ту же
# immutable migration chain. Иначе manual production install может считаться
# успешным, оставив схему старее той, которую требует Backend.
api_migrations = ROOT / "services/api/internal/dbmigrate/sql"
cli_migrations = ROOT / "cli/internal/dbmigrate/sql"
api_files = {p.name: p for p in api_migrations.glob("*.sql")}
cli_files = {p.name: p for p in cli_migrations.glob("*.sql")}
if set(api_files) != set(cli_files):
    missing_cli = sorted(set(api_files) - set(cli_files))
    missing_api = sorted(set(cli_files) - set(api_files))
    fail(f"migration chain drift: missing-in-cli={missing_cli}, missing-in-api={missing_api}")
else:
    for name in sorted(api_files):
        api_digest = hashlib.sha256(api_files[name].read_bytes()).digest()
        cli_digest = hashlib.sha256(cli_files[name].read_bytes()).digest()
        if api_digest != cli_digest:
            fail(f"migration checksum drift between Backend and CLI: {name}")
if "0011_auth_federation_release_0120.sql" not in api_files:
    fail("0.12.0 Auth Federation release migration is missing")
release_migration = api_files["0011_auth_federation_release_0120.sql"].read_text(encoding="utf-8")
for required in ["trg_users_require_local_identity", "trg_auth_identities_preserve_local", "auth_identities_provider_canonical_check"]:
    if required not in release_migration:
        fail(f"0.12.0 federation release migration missing invariant: {required}")
if "0012_device_trust_core_0121.sql" not in api_files:
    fail("0.12.1 Device Trust Core migration is missing")
device_migration = api_files["0012_device_trust_core_0121.sql"].read_text(encoding="utf-8")
for required in ["trusted_devices", "device_challenges", "trusted_device_id", "device_trust_state", "auth_sessions_trusted_device_fk"]:
    if required not in device_migration:
        fail(f"0.12.1 device trust migration missing invariant: {required}")
if "0014_challenge_response_attestation_0124.sql" not in api_files:
    fail("0.12.4 Challenge-response attestation migration is missing")
attestation_migration = api_files["0014_challenge_response_attestation_0124.sql"].read_text(encoding="utf-8")
for required in ["attestation_state", "attestation_method", "attestation_expires_at", "challenge-response-attested", "'attest'"]:
    if required not in attestation_migration:
        fail(f"0.12.4 attestation migration missing invariant: {required}")

# 2. Исторические milestone-версии 4.x-8.x запрещены как schemaVersion в CLI.
legacy_schema_patterns = [
    re.compile(r'"schemaVersion"\s*:\s*"([4-8]\.\d+(?:\.\d+)?)"'),
    re.compile(r'\bSchemaVersion\s*:\s*"([4-8]\.\d+(?:\.\d+)?)"'),
    re.compile(r'\["schemaVersion"\]\s*=\s*"([4-8]\.\d+(?:\.\d+)?)"'),
]
for path in sorted((ROOT / "cli/cmd/neverlauncher").glob("*.go")):
    text = path.read_text(encoding="utf-8")
    for pattern in legacy_schema_patterns:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            fail(f"{path.relative_to(ROOT)}:{line}: запрещён исторический schemaVersion {match.group(1)}")

main_go = read("cli/cmd/neverlauncher/main.go")
if 'const cliSchemaVersion = "1.0"' not in main_go:
    fail('cli/cmd/neverlauncher/main.go: отсутствует canonical cliSchemaVersion = "1.0"')

# 3. Текущая документация и UI должны ссылаться на VERSION, а не на старый P3.2/stable baseline.
current_docs = [
    "README.md",
    "SECURITY.md",
    "cli/README.md",
    "services/api/README.md",
    "apps/admin/README.md",
    "apps/desktop/README.md",
    "deploy/production/README.md",
    "deploy/production/TLS.md",
    "deploy/production/production-checklist.md",
    "e2e/README.md",
    "compatibility/README.md",
    "scripts/smoke/README.md",
]
for rel in current_docs:
    text = read(rel)
    for match in re.finditer(r"0\.10\.0-P3\.2(?:v\d+)?", text):
        if match.group(0) != VERSION:
            fail(f"{rel}: найдено устаревшее упоминание {match.group(0)} вместо {VERSION}")

ui_files = ["apps/admin/src/main.tsx", "apps/desktop/src/main.tsx"]
for rel in ui_files:
    text = read(rel)
    if "__NEVERLAUNCHER_VERSION__" not in text:
        fail(f"{rel}: UI должен получать версию из Vite define, связанного с VERSION")
    for match in re.finditer(r"(?<![0-9])\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", text):
        line = text.count("\n", 0, match.start()) + 1
        fail(f"{rel}:{line}: UI содержит ручной product version literal {match.group(0)}")

# 4. Минимальная защита русскоязычной документации: вне code fences не допускаются
#    длинные полностью англоязычные фразы. Технические идентификаторы/названия разрешены.
english_word = re.compile(r"[A-Za-z]{3,}")
cyrillic = re.compile(r"[А-Яа-яЁё]")
for rel in current_docs:
    in_code = False
    for lineno, raw in enumerate(read(rel).splitlines(), 1):
        line = raw.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not line:
            continue
        # Удаляем inline-code и Markdown URL, чтобы команды/пути не считались прозой.
        prose = re.sub(r"`[^`]*`", "", line)
        prose = re.sub(r"https?://\S+", "", prose)
        words = english_word.findall(prose)
        if len(words) >= 5 and not cyrillic.search(prose):
            fail(f"{rel}:{lineno}: полностью англоязычная пользовательская фраза: {line[:120]}")

# 5. Явно запрещаем известные англоязычные UI-регрессии.
forbidden_ui = {
    "apps/admin/src/main.tsx": [
        "Product Package Pipeline / Operator Experience",
        ">Validate</button>",
        ">Publish</button>",
        ">Upload file</button>",
        'placeholder="password"',
        'placeholder="admin email"',
    ],
    "apps/desktop/src/main.tsx": [
        ">Launch plan<",
        ">Launch result<",
        ">Launch history<",
        ">Repair</button>",
        ">Refresh</button>",
        "Product Desktop Launcher",
        "Desktop 0.10.0",
    ],
}
for rel, forbidden in forbidden_ui.items():
    text = read(rel)
    for needle in forbidden:
        if needle in text:
            fail(f"{rel}: запрещён устаревший/англоязычный UI-текст: {needle}")


# 6. P3.2v3 production hardening: auth/storage/backup/CORS должны быть fail-closed.
config_go = read("services/api/internal/config/config.go")
admin_handlers = read("services/api/internal/httpapi/admin_handlers.go")
api_main = read("services/api/cmd/neverlauncher-api/main.go")
server_go = read("services/api/internal/httpapi/server.go")
routes_operations = read("services/api/internal/httpapi/routes_operations.go")
backup_go = read("services/api/internal/httpapi/operations_backup.go")
compose = read("deploy/production/docker-compose.yml")
preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")

for forbidden in ["AdminPassword", "AdminEmail", "NEVERLAUNCHER_ADMIN_PASSWORD", "NEVERLAUNCHER_ADMIN_EMAIL"]:
    if forbidden in config_go or forbidden in admin_handlers or forbidden in compose:
        fail(f"production auth содержит запрещённый password/email fallback: {forbidden}")
for rel in ["scripts/install/production-setup.sh", "scripts/test/admin-crud-smoke.sh", "scripts/test/package-product-smoke.sh"]:
    text = read(rel)
    if "NEVERLAUNCHER_ADMIN_PASSWORD" in text or "NEVERLAUNCHER_ADMIN_EMAIL" in text:
        fail(f"{rel}: устаревшие runtime admin credentials запрещены")
admin_ui = read("apps/admin/src/main.tsx")
if "useState('admin@neverlauncher.local')" in admin_ui or "useState('admin')" in admin_ui:
    fail("Admin UI не должен предзаполнять production credentials")
if 'req.Password == s.Config.' in admin_handlers:
    fail("admin login содержит config-password fallback")
if 'используется local storage' in api_main or 'return storage.NewLocalStorage(cfg.StorageLocalPath)' in api_main.split('case "s3", "s3-compatible":', 1)[-1].split('default:', 1)[0]:
    fail("S3 init не должен иметь local-storage fallback")
if 'Access-Control-Allow-Origin", "*"' in server_go:
    fail("CORS wildcard запрещён")
for required in ["BackupRoot", "CORSAllowedOrigins", "ValidateProduction"]:
    if required not in config_go:
        fail(f"config: отсутствует production hardening {required}")
for required in ["NEVERLAUNCHER_BACKUP_ROOT", "NEVERLAUNCHER_CORS_ALLOWED_ORIGINS"]:
    if required not in compose:
        fail(f"production compose: отсутствует {required}")
if 'POST /api/v1/operations/backups/{backupId}/restore"' not in routes_operations:
    fail("реальный backup restore route отсутствует")
for required in ["pg_dump", "pg_restore", "restoreStorageObjects880", "extractAndVerifyOperationsBackup880"]:
    if required not in backup_go:
        fail(f"backup production implementation incomplete: {required}")
for legacy in ["release_manager.go", "client_package.go", "package_pipeline.go", "loader_handlers.go", "operations_observability.go"]:
    if (ROOT / "services/api/internal/httpapi" / legacy).exists():
        fail(f"legacy handler должен быть удалён из production tree: {legacy}")
if "compatibility-matrix" not in preflight:
    fail("preflight не запускает compatibility matrix definition/hardening tests")
if "federation-e2e" not in preflight or "scripts/test/federation-e2e.py" not in preflight:
    fail("preflight не запускает federation E2E release gate")
if "NEVERLAUNCHER_PREFLIGHT_FEDERATION_POSTGRES" not in preflight:
    fail("strict preflight не умеет запускать PostgreSQL multi-instance federation E2E")
federation_routes = read("services/api/internal/httpapi/routes_auth.go")
federation_registry = read("services/api/internal/httpapi/sql_connector_113.go")
for required in ["/api/v1/auth/providers/{providerId}/link/begin", "/api/v1/auth/providers/{providerId}/link/complete", "/api/v1/admin/auth/federation/status"]:
    if required not in federation_routes:
        fail(f"0.12.0 Auth Federation route missing: {required}")
for required in ["func NewFederationCore(", "conformance.Run(ctx, local)"]:
    if required not in federation_registry:
        fail(f"0.12.0 canonical federation registry missing: {required}")
auth_session_postgres = read("services/api/internal/httpapi/auth_core_postgres_111.go")
if "INSERT INTO auth_identities" in auth_session_postgres:
    fail("0.12.0 session issuance must not fabricate local identities; identity lifecycle belongs to canonical user/password operations")
passkey_handlers = read("services/api/internal/httpapi/webauthn_handlers_117.go")
if '"local", "identity-local-"+user.ID' in passkey_handlers or 'firstNonEmpty(provider, "local")' in passkey_handlers:
    fail("0.12.0 passwordless passkey must not masquerade as a local provider identity")
device_routes = read("services/api/internal/httpapi/routes_auth.go")
device_trust = read("services/api/internal/httpapi/device_trust_0121.go")
device_repo = read("services/api/internal/repository/devices_0121.go")
for required in ["/api/v1/auth/devices/register/begin", "/api/v1/auth/devices/register/complete", "/api/v1/auth/devices/{deviceId}/verify/complete", "/api/v1/auth/device-trust", "/api/v1/admin/auth/devices"]:
    if required not in device_routes:
        fail(f"0.12.1 Device Trust route missing: {required}")
for required in ["ed25519.Verify", "ConsumeDeviceChallenge", "bindTrustedDevice121", "deviceProofPayload0121"]:
    if required not in device_trust:
        fail(f"0.12.1 Device Trust proof path missing: {required}")
for required in ["key_fingerprint", "status='revoked'", "device_challenges", "trusted_device_id"]:
    if required not in device_repo:
        fail(f"0.12.1 Device Trust persistence/revocation incomplete: {required}")
if not (ROOT / "services/api/internal/httpapi/device_trust_0121_test.go").is_file():
    fail("0.12.1 Device Trust HTTP E2E test is missing")
# 0.12.2 official Desktop must own the device private-key lifecycle.  The
# private seed may exist only inside the native Tauri/keyring boundary; React
# receives public metadata and signatures, never secret key material.
desktop_device_keys = read("apps/desktop/src-tauri/src/device_keys.rs")
desktop_tauri = read("apps/desktop/src-tauri/src/main.rs")
desktop_ui = read("apps/desktop/src/main.tsx")
for required in ["SigningKey::generate", "keyring::v1::Entry::new", "private_seed_hex", "secret.zeroize()", "private_key_exposed_to_frontend: false", "sign_device_payload"]:
    if required not in desktop_device_keys:
        fail(f"0.12.2 Desktop device key secure-storage implementation missing: {required}")
for required in ["ensure_device_key", "sign_device_payload", "bind_device_key", "reset_device_key"]:
    if required not in desktop_tauri:
        fail(f"0.12.2 Tauri device-key command missing: {required}")
for required in ["ensureDesktopDeviceTrust", "/api/v1/auth/devices/register/begin", "/verify/begin", "privateKeyExposedToFrontend"]:
    if required not in desktop_ui:
        fail(f"0.12.2 Desktop automatic Device Trust flow missing: {required}")
for forbidden in ["privateSeed", "private_seed", "localStorage.setItem('neverlauncher.device"]:
    if forbidden in desktop_ui:
        fail(f"0.12.2 private device key material leaked into React/localStorage: {forbidden}")
if "device-key-storage.py" not in preflight:
    fail("preflight не запускает 0.12.2 device key / OS secure storage gate")
if "scripts/smoke/offline/device-key-storage.py" not in ci:
    fail("CI не запускает 0.12.2 device key / OS secure storage gate")
if "cargo test --manifest-path src-tauri/Cargo.toml" not in ci:
    fail("CI не запускает Tauri device-key unit tests")

# 0.12.3 hardware-bound identities: real non-exportable P-256 platform key
# path with explicit software downgrade.  Hardware binding metadata is NOT
# remote attestation and must never elevate MFA/authorization assurance.
hardware_gate = read("scripts/smoke/offline/hardware-bound-identity.py")
hardware_migration = read("services/api/internal/dbmigrate/sql/0013_hardware_bound_identities_0123.sql")
for required in ["hardware-enclave", "try_new_hardware_record", "key_binding: \"hardware\".into()", "P256Signature::from_der", "!p.contains(\"keyring\")"]:
    if required not in desktop_device_keys:
        fail(f"0.12.3 hardware-bound Desktop path missing: {required}")
for required in ["ecdsa.Verify", "elliptic.Unmarshal(elliptic.P256()", "keyBinding", "hardwareProvider"]:
    if required not in device_trust:
        fail(f"0.12.3 P-256 server proof path missing: {required}")
for required in ["key_algorithm IN ('ed25519','p256')", "key_binding IN ('software','hardware')", "key_binding='hardware' AND key_algorithm='p256'"]:
    if required not in hardware_migration:
        fail(f"0.12.3 hardware identity migration incomplete: {required}")
if "TestDeviceTrustHardwareP256RegistrationAndBinding0123" not in read("services/api/internal/httpapi/device_trust_0121_test.go"):
    fail("0.12.3 P-256 HTTP E2E test missing")
if "hardware-bound-identity.py" not in preflight or "scripts/smoke/offline/hardware-bound-identity.py" not in ci:
    fail("0.12.3 hardware-bound identity gate is not wired into preflight/CI")
if "libtss2-dev" not in ci:
    fail("0.12.3 Linux TPM build dependency libtss2-dev missing from CI")
if "Hardware-bound identity gate OK" not in hardware_gate:
    fail("0.12.3 hardware identity gate is incomplete")
if 'Assurance:         "hardware"' in device_trust or 'Assurance:         "attested"' in device_trust:
    fail("0.12.3 self-reported hardware binding must not elevate server assurance before attestation")

# 0.12.4 challenge-response attestation is a separate server-issued, single-use
# ceremony bound to the already verified session and registered hardware key.
# It may raise only device assurance while fresh; it must not claim vendor TPM /
# Secure Enclave provenance or raise RBAC/MFA authentication strength.
attestation_gate = read("scripts/smoke/offline/challenge-response-attestation.py")
attestation_handler = read("services/api/internal/httpapi/device_attestation_0124.go")
attestation_test = read("services/api/internal/httpapi/device_attestation_0124_test.go")
for required in ["Purpose:       \"attest\"", "ConsumeDeviceChallenge", "sessionBoundToDevice0124", "verifyDeviceSignature0123", "AttestTrustedDevice", "not-remotely-verified"]:
    if required not in attestation_handler:
        fail(f"0.12.4 challenge-response attestation path missing: {required}")
for required in ["TestDeviceChallengeResponseAttestation0124", "TestDeviceChallengeResponseAttestationRejectsSoftwareKey0124", "attestation replay accepted", "wrong attestation signature accepted"]:
    if required not in attestation_test:
        fail(f"0.12.4 attestation E2E test missing: {required}")
if "challenge-response-attestation.py" not in preflight or "scripts/smoke/offline/challenge-response-attestation.py" not in ci:
    fail("0.12.4 challenge-response attestation gate is not wired into preflight/CI")
if "Challenge-response attestation gate OK" not in attestation_gate:
    fail("0.12.4 challenge-response attestation gate is incomplete")
for forbidden in ["authorizationElevation\": true", "phishingResistantElevation\": true", "hardwareProvenance\": \"verified\""]:
    if forbidden in attestation_handler:
        fail(f"0.12.4 attestation overstates authorization/vendor assurance: {forbidden}")
# 0.12.5 Device Management + Revocation: device revoke is an irreversible
# security lifecycle transition, not a UI-only delete. Production PostgreSQL
# must cascade revocation transactionally and clients/admins must expose the
# management flow without allowing the old fingerprint to be re-enrolled.
device_management_gate = read("scripts/smoke/offline/device-management-revocation.py")
device_management = read("services/api/internal/httpapi/device_management_0125.go")
device_management_test = read("services/api/internal/httpapi/device_management_0125_test.go")
device_repository = read("services/api/internal/repository/devices_0121.go")
for required in ["RevokeOtherTrustedDevices", "invalidatedChallenges", "revokedMinecraftSessions", "invalidatedBridgeJoins", "reEnrollmentRequiresNewKey", "currentTrustedDeviceID0125"]:
    if required not in device_management:
        fail(f"0.12.5 device management path missing: {required}")
for required in ["UPDATE device_challenges SET consumed_at", "UPDATE auth_sessions SET status='revoked'", "UPDATE refresh_token_families SET status='revoked'", "UPDATE refresh_tokens SET status='revoked'", "UPDATE minecraft_sessions SET status='revoked'", "FOR UPDATE", "assurance='proof-of-possession'"]:
    if required not in device_repository:
        fail(f"0.12.5 transactional device revocation missing: {required}")
for required in ["TestDeviceManagementRevokeOthersAndChallengeInvalidation0125", "TestDeviceManagementSelfRevokeIsPermanentAndIdempotent0125", "pre-revocation challenge completed after revoke", "revoked device key was re-enrolled", "repeat revoke is not idempotent", "self-revoked session remained active"]:
    if required not in device_management_test:
        fail(f"0.12.5 device management regression coverage missing: {required}")
if "device-management-revocation.py" not in preflight or "scripts/smoke/offline/device-management-revocation.py" not in ci:
    fail("0.12.5 device management gate is not wired into preflight/CI")
if "Device Management + Revocation gate OK" not in device_management_gate:
    fail("0.12.5 device management gate is incomplete")

# 0.12.6 Session <-> Device binding + risk integration. Binding is
# server-authoritative, stale access tokens fail on binding_epoch mismatch,
# bound refresh requires proof by the current device key, and risk decisions
# are enforced by sensitive-operation step-up/reattest/revoke policy.
session_device_gate = read("scripts/smoke/offline/session-device-risk-0126.py")
session_risk = read("services/api/internal/httpapi/session_device_risk_0126.go")
session_risk_test = read("services/api/internal/httpapi/session_device_risk_0126_test.go")
auth_go = read("services/api/internal/httpapi/auth.go")
auth_accounts = read("services/api/internal/httpapi/auth_accounts.go")
for required in ["binding_epoch", "sessionBindingClaimsMatch0126", "reconcileSessionDeviceRisk0126"]:
    if required not in auth_go:
        fail(f"0.12.6 authoritative session/device binding missing: {required}")
for required in ["NeverLauncher Session Device Binding v1", "refresh-token-sha256=", "verifyRefreshDeviceProof0126", "device-attestation-stale", '"step-up"', '"reattest"', '"revoke"']:
    if required not in session_risk:
        fail(f"0.12.6 risk/device proof path missing: {required}")
for required in ["previewRefresh0126(req.RefreshToken)", "verifyRefreshDeviceProof0126", "deviceSignature", "device-bound-refresh"]:
    if required not in auth_accounts:
        fail(f"0.12.6 bound refresh integration missing: {required}")
for required in ["TestSessionDeviceBindingInvalidatesPreBindTokenAndRequiresRefreshProof0126", "TestSessionRiskUserAgentDriftIsPersistedAndRequiresStepUp0126", "refresh family survived replay compromise"]:
    if required not in session_risk_test:
        fail(f"0.12.6 session/device risk regression coverage missing: {required}")
if "session-device-risk-0126.py" not in preflight or "scripts/smoke/offline/session-device-risk-0126.py" not in ci:
    fail("0.12.6 session/device risk gate is not wired into preflight/CI")
if "Session <-> Device binding + risk integration gate OK" not in session_device_gate:
    fail("0.12.6 session/device risk gate is incomplete")

# 0.12.7 Minecraft/ServerBridge trust enforcement. Gameplay credentials carry
# the trusted-device/binding snapshot and every server-side join confirmation
# re-evaluates the current parent session/device/risk state without mutating
# player network observations from the game server request.
gameplay_trust_gate = read("scripts/smoke/offline/minecraft-serverbridge-trust-0127.py")
gameplay_trust = read("services/api/internal/httpapi/minecraft_serverbridge_trust_0127.go")
minecraft_auth = read("services/api/internal/httpapi/minecraft_auth_119.go")
server_bridge = read("services/api/internal/httpapi/server_bridge.go")
bridge_plugins = read("services/api/internal/httpapi/bridge_plugins.go")
gameplay_trust_test = read("services/api/internal/httpapi/minecraft_serverbridge_trust_0127_test.go")
for required in ["evaluateGameplayTrust0127", "session-device-risk-v1", "credential_trust_snapshot_missing", "session_binding_changed", "device_reattest_required", "session_step_up_required"]:
    if required not in gameplay_trust:
        fail(f"0.12.7 gameplay trust evaluator missing: {required}")
for required in ["issueMinecraftSessionWithTrust119", "TrustedDeviceID: trustedDeviceID", "BindingEpoch: bindingEpoch", "parentSession.BindingEpoch != bindingEpoch", "trust-policy:", "evaluateGameplayTrust0127"]:
    if required not in minecraft_auth:
        fail(f"0.12.7 Minecraft credential trust binding missing: {required}")
for required in ["TrustedDeviceID", "BindingEpoch", "invalidateJoin", "evaluateGameplayTrust0127"]:
    if required not in server_bridge:
        fail(f"0.12.7 ServerBridge trust binding missing: {required}")
for required in ["channel_mismatch", "trustEnforcement", "evaluateGameplayTrust0127"]:
    if required not in bridge_plugins:
        fail(f"0.12.7 plugin trust enforcement missing: {required}")
for required in ["TestMinecraftTrust0127RequiresBoundDeviceAndInvalidatesTokenAfterRebind", "TestServerBridgeTrust0127LiveBindingAndRiskEnforcement", "bridge accepted mismatched channel"]:
    if required not in gameplay_trust_test:
        fail(f"0.12.7 gameplay trust regression coverage missing: {required}")
if "minecraft-serverbridge-trust-0127.py" not in preflight or "scripts/smoke/offline/minecraft-serverbridge-trust-0127.py" not in ci:
    fail("0.12.7 Minecraft/ServerBridge trust gate is not wired into preflight/CI")
if "Minecraft/ServerBridge trust enforcement gate OK" not in gameplay_trust_gate:
    fail("0.12.7 Minecraft/ServerBridge trust gate is incomplete")

for required in ["NEVERLAUNCHER_PREFLIGHT_STRICT", "NEVERLAUNCHER_PREFLIGHT_PGX"]:
    if required not in preflight:
        fail(f"preflight не содержит strict gate {required}")
if "release doctor" not in ci.lower():
    fail("CI не запускает release doctor")
if "NEVERLAUNCHER_CORS_ALLOWED_ORIGINS" not in ci:
    fail("CI Compose validation не задаёт обязательный CORS origin")

e2e_compose = read("e2e/docker-compose.minecraft-e2e.yml")
for required in ["NEVERLAUNCHER_ENV: e2e-production", "NEVERLAUNCHER_BACKUP_ROOT", "NEVERLAUNCHER_CORS_ALLOWED_ORIGINS", "e2e-backups:/var/lib/neverlauncher/backups"]:
    if required not in e2e_compose:
        fail(f"production E2E не содержит обязательный hardening: {required}")
federation_e2e_compose = read("e2e/docker-compose.federation-e2e.yml")
for required in ["api-a:", "api-b:", "api-c:", "NEVERLAUNCHER_PERSISTENT_SESSIONS", "NEVERLAUNCHER_DATABASE_AUTO_MIGRATE: \"false\""]:
    if required not in federation_e2e_compose:
        fail(f"federation PostgreSQL E2E incomplete: {required}")
federation_e2e = read("e2e/scripts/run-federation-postgres-e2e.sh")
for required in ["db migrate verify", "0011_auth_federation_release_0120", "localIdentityInvariant", "passwordPromotionIdentityInvariant", "user-federation-external-e2e", "compose restart api-a", "api/v1/auth/refresh", "replay old refresh"]:
    if required not in federation_e2e:
        fail(f"federation PostgreSQL E2E missing stabilization check: {required}")
if 'case "production", "prod", "e2e-production"' not in config_go:
    fail("config: e2e-production должен проходить production validation")

# 7. P3.2v3 production completion: real release signing, strict artifacts,
#    real pipeline/storage/migrate/install checks and deterministic deployment permissions.
dockerfile = read("services/api/Dockerfile")
release_signing = read("cli/cmd/neverlauncher/release_signing.go")
release_commands = read("cli/cmd/neverlauncher/release_commands.go")
package_commands = read("cli/cmd/neverlauncher/package_commands.go")
security_commands = read("cli/cmd/neverlauncher/auth_security_commands.go")
install_commands = read("cli/cmd/neverlauncher/operations_commands.go")
operations_integrity = read("services/api/internal/httpapi/operations_integrity.go")
maintenance_go = read("services/api/internal/httpapi/maintenance.go")
install_handlers = read("services/api/internal/httpapi/install_handlers.go")
build_release = read("scripts/release/build-release.sh")
release_bundle_gate = read("scripts/smoke/release-required/release-bundle.sh")

for required in [
    "mkdir -p /var/lib/neverlauncher/storage/current /var/lib/neverlauncher/backups",
    "chown -R 10001:10001 /var/lib/neverlauncher",
    "USER neverlauncher",
]:
    if required not in dockerfile:
        fail(f"services/api/Dockerfile: отсутствует volume ownership hardening: {required}")
for required in ["api-volume-init:", "chown -R 10001:10001 /storage /backups", "condition: service_completed_successfully", "NEVERLAUNCHER_STORAGE_LOCAL_PATH: /var/lib/neverlauncher/storage/current"]:
    if required not in compose:
        fail(f"production compose: отсутствует deterministic volume ownership gate: {required}")

for required in ["ed25519.Sign", "ed25519.Verify", "loadEd25519PrivateKey", "loadEd25519PublicKey", "KeyFingerprint"]:
    if required not in release_signing:
        fail(f"release signing не реализует настоящий Ed25519 primitive: {required}")
if 'bundled key не считается trust anchor' not in release_signing:
    fail("release verification должен требовать внешний trusted public key")
for forbidden in ['[]byte(hex.EncodeToString(sum[:])+"  SHA256SUMS\\n")', 'SHA256SUMS.sig"), []byte(hex.EncodeToString']:
    if forbidden in release_commands or forbidden in release_signing:
        fail("release signature снова сведена к checksum вместо Ed25519")
for required in ["required artifact", 'artifact.Status != "present"', "verifyReleaseSignature", "releaseArtifacts(ver)"]:
    if required not in release_commands:
        fail(f"release verify не содержит strict required-artifact gate: {required}")

for rel in ["scripts/release/source-package.py", "scripts/release/secret-scan.py", "scripts/release/zip-dir.py"]:
    if not (ROOT / rel).is_file():
        fail(f"отсутствует production release utility: {rel}")
for required in ["source-package.py", "secret-scan.py", "neverruntime-linux-amd64", "neverlauncher-desktop-linux-amd64", "bridge-plugins.sh", "artifacts/plugins/neverlauncher-${bridge}-bridge-${VERSION}.jar"]:
    if required not in build_release:
        fail(f"build-release не собирает/проверяет обязательный artifact: {required}")
if "NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE" not in build_release or "NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE" not in build_release:
    fail("build-release должен требовать внешний Ed25519 private/public key")
if "release-bundle:" not in ci or "Build and cryptographically verify complete release bundle" not in ci:
    fail("CI не собирает полный production release bundle")
if "NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE" not in release_bundle_gate:
    fail("release-bundle smoke gate не требует trusted Ed25519 public key")

for legacy_helper in ["packagePipelinePayload", "packagePipelineStagePayload", "packagePipelinePublishPayload"]:
    if legacy_helper in package_commands:
        fail(f"CLI pipeline содержит статический legacy helper: {legacy_helper}")
for required in ["/validate", "/sign", "/stage", "/smoke-test", "/publish", "httpJSONWithAuth"]:
    if required not in package_commands:
        fail(f"CLI pipeline не вызывает реальный Backend API: {required}")
for required in ["/api/v1/operations/storage/audit", "/api/v1/operations/storage/consistency", "/api/v1/operations/migrations/apply", "/restore"]:
    if required not in security_commands:
        fail(f"CLI storage/migrate operation не связан с production Backend primitive: {required}")
for required in ["verifyReleaseBundle", "verifyDetachedEd25519"]:
    if required not in security_commands:
        fail(f"security verify-signature не выполняет cryptographic verification: {required}")
for required in ["/health", "/ready", "/api/v1/admin/storage/health", "/api/v1/operations/storage/consistency"]:
    if required not in install_commands:
        fail(f"install verify/storage-check не содержит реальную проверку: {required}")
for required in ["readCanonicalProductionTemplate", "standaloneProductionCompose", "--api-image", "--admin-image", "@sha256:"]:
    if required not in install_commands:
        fail(f"install first-run не является standalone/pinned production deployment: {required}")
for name in ["docker-compose.yml", "nginx.conf", "env.production.example", "README.md", "TLS.md", "production-checklist.md"]:
    canonical = ROOT / "deploy/production" / name
    embedded = ROOT / "cli/cmd/neverlauncher/templates/production" / name
    if not embedded.is_file():
        fail(f"first-run embedded template отсутствует: {name}")
    elif canonical.read_bytes() != embedded.read_bytes():
        fail(f"first-run embedded template рассинхронизирован с canonical deploy/production: {name}")
if '"beta-smoke"' in install_handlers:
    fail("install readiness содержит удалённый beta-smoke placeholder")

for required in ["storageIntegrityReport", "sha256.New", "orphan", "beginMaintenanceExclusive"]:
    if required not in operations_integrity:
        fail(f"storage audit/consistency не выполняет полный integrity scan: {required}")
for required in ["operations/migrations/apply", "isMaintenanceOperation"]:
    if required not in maintenance_go:
        fail(f"maintenance gate не защищает migration/backup lifecycle: {required}")
for required in ["safety backup", "restoreLocalStorageAtomic880", "os.Rename", "--single-transaction"]:
    if required not in backup_go:
        fail(f"backup/restore не содержит maintenance-safe/atomic primitive: {required}")


# 8. P3.2v4 production completion: immutable published releases, real client/desktop
#    lifecycle, standalone first-run and persistent supply-chain key lifecycle.
memory_repo = read("services/api/internal/repository/memory.go")
postgres_repo = read("services/api/internal/repository/postgres.go")
package_product = read("services/api/internal/httpapi/package_product.go")
package_mutation_lock = read("services/api/internal/httpapi/package_mutation_lock.go")
client_lifecycle = read("cli/cmd/neverlauncher/client_lifecycle.go")
desktop_package = read("cli/cmd/neverlauncher/desktop_package.go")
security_keyring = read("cli/cmd/neverlauncher/security_keyring.go")
supply_chain = read("cli/cmd/neverlauncher/supply_chain.go")
release_signing_v4 = read("cli/cmd/neverlauncher/release_signing.go")
product_tests = read("cli/cmd/neverlauncher/p32v4_product_test.go")
immutable_tests = read("services/api/internal/repository/immutable_test.go")
package_product_tests = read("services/api/internal/httpapi/package_product_test.go")

for required in ["ErrImmutable", 'Status == "published"']:
    if required not in memory_repo or required not in postgres_repo:
        fail(f"repository immutable guard отсутствует на memory/postgres слое: {required}")
for required in ["published release immutable", "http.StatusConflict", "lockPackageMutation", "rolled-back-as-new-immutable-release"]:
    if required not in package_product:
        fail(f"HTTP package lifecycle не блокирует/не сериализует immutable release: {required}")
if "FOR UPDATE" not in postgres_repo or "status <> 'published'" not in postgres_repo:
    fail("PostgreSQL immutable guard должен использовать row locking и conditional mutation")
for required in ["UpdateVersionStatus", "UpdateVersionManifest", "AddFile", "PublishVersionWithManifest"]:
    if required not in immutable_tests:
        fail(f"repository immutable regression-test не покрывает {required}")
if "TestPublishedPackageIsImmutable" not in package_product_tests:
    fail("HTTP immutable published-release regression-test отсутствует")
if "lockPackageMutation" not in package_mutation_lock:
    fail("package storage+metadata mutation serialization отсутствует")

for required in ["clientInstallOrUpdate", "verifyClientInstallation", "repairClientInstallation", "cleanupClientInstallation", "rollbackClientInstallation", "createClientSnapshot", "verifiedCopyClientFile"]:
    if required not in client_lifecycle:
        fail(f"client lifecycle не реализован рабочим кодом: {required}")
for legacy in ["clientDeliveryPlan", "clientVerifyReport", "clientRepairPlan", "clientCleanupPlan", "clientRollbackPlan"]:
    if legacy in package_commands:
        fail(f"client lifecycle содержит удалённую status-only заглушку: {legacy}")
if "TestClientLifecycleInstallRepairCleanupRollback" not in product_tests:
    fail("client lifecycle end-to-end regression-test отсутствует")

for required in ["buildDesktopPackage", "verifyDesktopPackage", "SHA256SUMS.desktop", "hashFile"]:
    if required not in desktop_package:
        fail(f"desktop package/verify не проверяет реальный artifact: {required}")
if "checksums are populated by the native release build" in read("cli/cmd/neverlauncher/admin_desktop_commands.go"):
    fail("desktop package вернулся к placeholder checksum")
if "TestDesktopPackageRequiresRealArtifactAndDetectsTampering" not in product_tests:
    fail("desktop package integrity regression-test отсутствует")

for required in ["ed25519.GenerateKey", "trusted-keys.json", "saveKeyRegistry", "Revoke", "securityAttest", "ensurePublicKeyNotRevoked"]:
    if required not in security_keyring:
        fail(f"persistent key rotation/revocation/attestation incomplete: {required}")
for forbidden in ["rotation-policy", "attestation-plan"]:
    if forbidden in security_commands or forbidden in security_keyring:
        fail(f"security key lifecycle содержит declaration-only status: {forbidden}")
if "TestKeyRotationAttestationAndRevocation" not in product_tests:
    fail("key rotation/revocation/attestation regression-test отсутствует")

for required in ["SPDX-2.3", "parseGoMod", "parseNPMLock", "parseCargoLock", "https://in-toto.io/Statement/v1", "https://slsa.dev/provenance/v1", "resolvedDependencies"]:
    if required not in supply_chain:
        fail(f"dependency SBOM/provenance incomplete: {required}")
for required in ["PROVENANCE.json.sig", "signDetachedFileWithKey", "verifyDetachedFileWithKey"]:
    if required not in release_signing_v4:
        fail(f"provenance attestation не подписывается/проверяется: {required}")
for required in ["neverlauncher-desktop-package-${VERSION}.zip", "desktop package", "desktop verify"]:
    if required not in build_release:
        fail(f"release bundle не включает реальный Desktop package: {required}")
if "neverlauncher-desktop-package-" not in release_commands:
    fail("release manifest не требует Desktop package artifact")
if "PROVENANCE.json.sig" not in release_commands:
    fail("release verify не требует signed provenance attestation")
if "TestDependencySBOMAndProvenanceUseRealInputs" not in product_tests:
    fail("dependency SBOM/provenance regression-test отсутствует")
if "TestStandaloneFirstRunUsesPinnedImagesWithoutBuildContext" not in product_tests:
    fail("standalone first-run regression-test отсутствует")

# 9. Real Minecraft client E2E: the release gate must materialize and
#    launch an actual Mojang client, not regress to a synthetic Java fixture.
e2e_script = read("e2e/scripts/run-minecraft-e2e.sh")
e2e_publish = read("e2e/scripts/publish-client-package.py")
for required in [
    "runtime vanilla-package",
    "materialized-client-verify.json",
    "publish-client-package.py",
    "xvfb-run",
    "--quick-play",
    "runtime-launch-minecraft.json",
    "joined the game",
    "--max-runtime-seconds",
]:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E отсутствует обязательный primitive: {required}")
for forbidden in ["LaunchFixture", "NEVERLAUNCHER_E2E_FIXTURE_OK", "launch-fixture"]:
    if forbidden in e2e_script:
        fail(f"production Minecraft E2E снова использует synthetic fixture: {forbidden}")
for required in ["hashlib.sha256", "backend checksum mismatch after upload", "local package file changed before upload", "manifestSettings"]:
    if required not in e2e_publish:
        fail(f"E2E package publisher не проверяет реальный artifact lifecycle: {required}")
if "actual-mojang-client" not in ci or "xvfb" not in ci or "Minecraft Client E2E" not in ci:
    fail("CI не содержит блокирующий actual Minecraft Client E2E gate")


# 10. 0.10.6 public CI Compatibility Matrix + hardening: targets contain no
#     hand-written PASS state; actual-client evidence is generated by CI and
#     aggregated fail-closed for the exact commit/run.
compat_targets = read("compatibility/targets.json")
compat_tool = read("scripts/compatibility/matrix.py")
compat_workflow = read(".github/workflows/compatibility.yml")
compat_case = read("e2e/scripts/run-compatibility-case.sh")
for required in ["vanilla", "fabric", "quilt", "forge", "neoforge", '"required": true']:
    if required not in compat_targets:
        fail(f"compatibility targets incomplete: {required}")
for forbidden in ['"status": "passed"', '"status":"passed"', '"pass": true', '"passed": true']:
    if forbidden in compat_targets.lower():
        fail("compatibility/targets.json must never contain manually editable PASS state")
for required in [
    "verify_result", "missing required result", "loader result did not resolve to a concrete immutable version",
    "actualClient", "signedManifest", "cleanSync", "paperJoin", "sessionRevokeDeny", "paperHealthy", "evidenceSha256",
]:
    if required not in compat_tool:
        fail(f"compatibility matrix aggregator missing hardening primitive: {required}")
if not (ROOT / "scripts/compatibility/test_matrix.py").is_file():
    fail("compatibility matrix regression tests are missing")
if not (ROOT / "e2e/scripts/test_publish_client_package.py").is_file():
    fail("E2E publisher path-hardening regression tests are missing")
for required in [
    "run-compatibility-case.sh", "strategy:", "matrix:", "actions/upload-artifact@v4",
    "actions/download-artifact@v4", "GITHUB_STEP_SUMMARY", "matrix.py aggregate",
]:
    if required not in compat_workflow:
        fail(f"public compatibility workflow incomplete: {required}")
for required in [
    "NEVERLAUNCHER_E2E_MODE=compatibility", "GITHUB_SHA", "GITHUB_RUN_ID",
    "actualClient", "paperJoin", "signedManifest", "cleanSync", "sessionRevokeDeny", "paperHealthy",
]:
    if required not in compat_case:
        fail(f"compatibility case does not bind result to real CI evidence: {required}")
for required in [
    'LOADER="$(printf', "runtime \"${LOADER}-package\"", "RESOLVED_LOADER_VERSION",
    "mutable loader selector leaked into release", '.signature.valid == true', "joined the game",
]:
    if required not in e2e_script:
        fail(f"generic real-client E2E hardening missing: {required}")
if 'NEVERLAUNCHER_PROFILE_ID: ${NEVERLAUNCHER_E2E_PROFILE_ID:-vanilla}' not in e2e_compose:
    fail("E2E server profile must be bound to compatibility target instead of hard-coded Vanilla")
if "symlink package path is forbidden" not in e2e_publish or "resolve(strict=True)" not in e2e_publish:
    fail("E2E publisher must reject symlink/path ambiguity before upload")


# 11. 0.10.7 compatibility stabilization: concurrent materializers are locked,
#     transient upstream failures are retried, client-tree symlink escapes are
#     rejected, portable atomic replacement is used, and the NeverRuntime bin
#     source must exist whenever Cargo declares it.
stability_go = read("cli/cmd/neverlauncher/compatibility_stability.go")
stability_tests = read("cli/cmd/neverlauncher/compatibility_stability_test.go")
vanilla_runtime = read("cli/cmd/neverlauncher/vanilla_runtime.go")
managed_java = read("runtime/neverruntime/src/managed_java.rs")
runtime_compat = read("runtime/neverruntime/src/compatibility.rs")
if not (ROOT / "runtime/neverruntime/src/bin/neverruntime.rs").is_file():
    fail("Cargo declares neverruntime binary but src/bin/neverruntime.rs is missing")
for required in [
    "acquireCompatibilityMaterializationLock", "compatibilityGET", "secureClientDestination",
    "validateAssetLogicalPath", "replaceFileAtomicPortable", "retryableCompatibilityStatus",
]:
    if required not in stability_go:
        fail(f"0.10.7 compatibility stabilization missing primitive: {required}")
for required in [
    "TestCompatibilityGETRetriesTransientStatus", "TestMaterializationLockIsExclusive",
    "TestSecureClientDestinationRejectsSymlinkComponent", "TestValidateAssetLogicalPath",
    "TestReplaceFileAtomicPortableReplacesExisting",
]:
    if required not in stability_tests:
        fail(f"0.10.7 compatibility stabilization missing regression test: {required}")
for required in ["maxCompatibilityArtifact+1", "secureClientDestination", "validateAssetLogicalPath"]:
    if required not in vanilla_runtime:
        fail(f"Vanilla stabilization missing: {required}")
if managed_java.count("check_java(Some(java.to_string_lossy().to_string()), Some(major)).await?") != 1:
    fail("Managed Java cached runtime validation must invoke java -version exactly once")
if "compatibility path содержит symlink" not in runtime_compat:
    fail("NeverRuntime Compatibility Engine must reject symlink path components")
if "runtime record java path вышел за Managed Java root через symlink" not in managed_java:
    fail("Managed Java cache validation must reject symlink escape")
for required in ["paperHealthy", "exitCode", "evidence files are incomplete", "evidence manifestLoader mismatch"]:
    if required not in compat_tool:
        fail(f"compatibility evidence stabilization missing: {required}")



# 12. Minecraft Compatibility Release: production publication must be
#     bound to machine-verifiable compatibility evidence for the same version
#     and source commit, and the evidence must live inside signed SHA256SUMS.
compat_release = read("cli/cmd/neverlauncher/compatibility_release.go")
release_commands = read("cli/cmd/neverlauncher/release_commands.go")
build_release = read("scripts/release/build-release.sh")
for required in [
    "COMPATIBILITY_TARGETS.json", "COMPATIBILITY_MATRIX.json", "COMPATIBILITY_CERTIFICATION.json",
    "validateCompatibilityEvidence", "verifyCompatibilityCertificationInBundle",
    "all-required-targets-must-pass-actual-client-e2e", "evidenceSha256",
]:
    if required not in compat_release:
        fail(f"compatibility release certification missing: {required}")
for required in [
    "--compatibility-matrix", "--compatibility-targets", "--source-commit",
    "Minecraft compatibility certification", "compatibilityCertificationRequired",
]:
    if required not in release_commands:
        fail(f"release CLI is not compatibility-certified: {required}")
for required in [
    "NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE", "NEVERLAUNCHER_SOURCE_COMMIT",
    "release publish-check", "Certification evidence не передан",
]:
    if required not in build_release:
        fail(f"build-release compatibility certification incomplete: {required}")
if not (ROOT / "cli/cmd/neverlauncher/compatibility_release_test.go").is_file():
    fail("compatibility release certification regression tests are missing")


# 0.12.8 Cross-platform hardening + device key recovery/rotation.
key_recovery_gate = read("scripts/smoke/offline/cross-platform-key-recovery-0128.py")
key_recovery_handler = read("services/api/internal/httpapi/device_key_recovery_0128.go")
key_recovery_native = read("apps/desktop/src-tauri/src/device_keys.rs")
key_recovery_desktop = read("apps/desktop/src/main.tsx")
key_recovery_migration_api = read("services/api/internal/dbmigrate/sql/0017_device_key_recovery_rotation_0128.sql")
key_recovery_migration_cli = read("cli/internal/dbmigrate/sql/0017_device_key_recovery_rotation_0128.sql")
for required in ["NeverLauncher Device Key Replacement v1", "oldSignature", "newSignature", "phishing-resistant", "ReplaceTrustedDeviceKey", "oldFingerprintPermanentTombstone"]:
    if required not in key_recovery_handler:
        fail(f"0.12.8 key replacement ceremony missing: {required}")
for required in ["hardware_key_label_generation", "stage_device_key_replacement", "sign_staged_device_replacement", "commit_staged_device_key", "abort_staged_device_key"]:
    if required not in key_recovery_native:
        fail(f"0.12.8 native staged-key lifecycle missing: {required}")
for required in ["replaceDesktopDeviceKey", "passkeyStepUp", "reconcileStagedReplacement", "serverCommitted"]:
    if required not in key_recovery_desktop:
        fail(f"0.12.8 desktop replacement flow missing: {required}")
if key_recovery_migration_api != key_recovery_migration_cli:
    fail("0.12.8 API/CLI migration 0017 differs")
if "cross-platform-key-recovery-0128.py" not in preflight or "scripts/smoke/offline/cross-platform-key-recovery-0128.py" not in ci:
    fail("0.12.8 key recovery gate is not wired into preflight/CI")


# 0.12.9 Device Trust E2E + public trust matrix. PASS state must come only
# from exact-commit/run CI evidence; public targets are policy, not results.
device_trust_targets = read("device-trust/targets.json")
device_trust_matrix = read("scripts/device_trust/matrix.py")
device_trust_workflow = read(".github/workflows/device-trust.yml")
device_trust_e2e = read("e2e/scripts/run-device-trust-e2e.sh")
device_trust_webauthn = read("e2e/scripts/webauthn-test-authenticator.py")
device_trust_native_result = read("e2e/scripts/write-device-trust-native-result.py")
device_trust_gate = read("scripts/smoke/offline/device-trust-e2e-matrix-0129.py")
for required in ["postgres-protocol-linux-x64", "native-linux", "native-windows", "native-macos", '"required": true']:
    if required not in device_trust_targets:
        fail(f"0.12.9 public Device Trust targets incomplete: {required}")
for forbidden in ['"status": "passed"', '"status":"passed"', '"passed": true', '"pass": true']:
    if forbidden in device_trust_targets.lower():
        fail("device-trust/targets.json must not contain manually editable PASS state")
for required in [
    "verify_result", "missing required device trust result", "evidenceSha256", "evidence SHA-256 mismatch",
    "vendorHardwareProvenance", "headless-ci-does-not-prove-os-secure-storage-runtime", "safe-basename",
    "exact commit/run ID",
]:
    if required not in device_trust_matrix:
        fail(f"0.12.9 trust matrix aggregator missing hardening primitive: {required}")
for required in [
    "db migrate apply", "/api/v1/auth/devices/register/begin", "/api/v1/auth/refresh",
    "/api/v1/auth/devices/key-rotation/begin", "/api/v1/server-bridge/validate-join",
    "/api/v1/auth/sessions", "/attest/begin", "/api/v1/auth/devices/key-recovery/begin",
    "/api/v1/auth/passkeys/register/begin", "/api/v1/auth/passkeys/step-up/begin",
    "recoveryPhishingResistantEndToEnd:true", "replacement_reason='recover'",
    "secret material leaked into public evidence", 'repository:"postgresql"',
]:
    if required not in device_trust_e2e:
        fail(f"0.12.9 PostgreSQL Device Trust E2E missing runtime primitive: {required}")
for required in ["webauthn.create", "webauthn.get", "registration_auth_data", "assertion_auth_data", '"openssl", "dgst", "-sha256", "-sign"']:
    if required not in device_trust_webauthn:
        fail(f"0.12.9 WebAuthn Device Trust E2E helper incomplete: {required}")
for required in [
    "matrix.py plan", "runs-on: ${{ matrix.runner }}", "run-device-trust-e2e.sh",
    "device_keys::tests", "write-device-trust-native-result.py", "matrix.py aggregate",
    "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_STEP_SUMMARY",
]:
    if required not in device_trust_workflow:
        fail(f"0.12.9 public Device Trust workflow incomplete: {required}")
for required in [
    "hardware_generation_labels_are_scoped_and_rotate",
    "replacement_payload_is_canonical_and_user_scoped",
    "refresh_payload_binds_session_device_epoch_and_token_hash_without_token_disclosure",
    "attestation_payload_is_hardware_only_and_identity_bound",
]:
    if required not in device_trust_native_result:
        fail(f"0.12.9 native Device Trust evidence incomplete: {required}")
if "device-trust-e2e-matrix-0129.py" not in preflight or "scripts/smoke/offline/device-trust-e2e-matrix-0129.py" not in ci:
    fail("0.12.9 Device Trust matrix gate is not wired into preflight/CI")
if "run-device-trust-e2e.sh" not in ci or "RUN_DEVICE_TRUST_E2E" not in preflight:
    fail("0.12.9 production/strict E2E wiring is incomplete")
if "Device Trust E2E + public trust matrix 0.12.9+ gate OK" not in device_trust_gate:
    fail("0.12.9+ mandatory Device Trust release gate is incomplete")


# 0.12.10 Migration + stabilization. The upgrade from the exact 0.12.9
# schema is a first-class release property, not just a fresh-install check.
stabilization_migration_api = read("services/api/internal/dbmigrate/sql/0018_device_trust_stabilization_01210.sql")
stabilization_migration_cli = read("cli/internal/dbmigrate/sql/0018_device_trust_stabilization_01210.sql")
stabilization_upgrade_e2e = read("e2e/scripts/run-device-trust-migration-e2e.sh")
stabilization_gate = read("scripts/smoke/offline/device-trust-migration-stabilization-01210.py")
if stabilization_migration_api != stabilization_migration_cli:
    fail("0.12.10 API/CLI migration 0018 differs")
for required in [
    "key-rotate", "key-recover", "device_challenges_purpose_check",
    "trusted_devices_lifecycle_check", "trusted_devices_replacement_shape_check",
    "auth_sessions_device_binding_shape_check", "auth_sessions_trusted_device_owner_fk",
    "trusted_devices_replacement_owner_fk", "minecraft_sessions_never_session_owner_fk",
    "minecraft_sessions_device_owner_fk", "minecraft_sessions_profile_owner_fk",
    "UPDATE minecraft_sessions SET trusted_device_id=NULL", "legacy-device-revoked",
]:
    if required not in stabilization_migration_api:
        fail(f"0.12.10 stabilization migration missing invariant: {required}")
for required in [
    "0.12.9 schema (0001..0017)", "0017_device_key_recovery_rotation_0128",
    "0018_device_trust_stabilization_01210", "key-rotate", "key-recover",
    "cross-user auth session/device binding unexpectedly succeeded",
    "cross-user replacement link unexpectedly succeeded",
    "cross-user Minecraft device snapshot unexpectedly succeeded",
    "migration-stabilization.json",
]:
    if required not in stabilization_upgrade_e2e:
        fail(f"0.12.10 exact-upgrade E2E missing: {required}")
for required in ["migrationStabilization01210", "migration-upgrade-e2e.json", "0018_device_trust_stabilization_01210"]:
    if required not in device_trust_e2e:
        fail(f"0.12.10 public Device Trust evidence missing: {required}")
if '"productVersion": "' + VERSION + '"' not in device_trust_targets or "migrationStabilization01210" not in device_trust_targets:
    fail("0.12.10 public Device Trust policy is not aligned with VERSION/migration stabilization")
if "migrationStabilization01210" not in device_trust_matrix or "migration stabilization 0.12.10" not in device_trust_matrix:
    fail("0.12.10 public trust matrix does not expose migration stabilization evidence")
if "device-trust-migration-stabilization-01210.py" not in preflight or "scripts/smoke/offline/device-trust-migration-stabilization-01210.py" not in ci:
    fail("0.12.10 stabilization gate is not wired into preflight/CI")
if "run-device-trust-migration-e2e.sh" not in preflight or "run-device-trust-migration-e2e.sh" not in ci or "run-device-trust-migration-e2e.sh" not in device_trust_workflow:
    fail("0.12.10 exact-upgrade E2E is not wired into release/CI/public Device Trust workflow")
if "e2e/device-trust-migration-result/" not in ci or "e2e/device-trust-migration-result/" not in device_trust_workflow:
    fail("0.12.10 migration evidence is not retained by CI/public Device Trust workflow")
if "Device Trust migration + stabilization 0.12.10 gate OK" not in stabilization_gate:
    fail("0.12.10 mandatory migration stabilization release gate is incomplete")

# 0.13.2 NeverGuard Windows Integrity Evidence v1. Evidence is collected by the
# separate guard process and authenticated over the existing local IPC session.
integrity_0132 = read("runtime/neverruntime/src/integrity.rs")
guard_0132 = read("runtime/neverruntime/src/guard_ipc.rs")
desktop_0132 = read("apps/desktop/src-tauri/src/main.rs")
integrity_gate_0132 = read("scripts/smoke/offline/neverguard-integrity-evidence-0132.py")
for required in [
    "WinVerifyTrust", "GetProcessMitigationPolicy", "QueryFullProcessImageNameW",
    "CreateToolhelp32Snapshot", "module_set_sha256", "recompute_evidence_sha256",
    "observed_parent_pid", "neverguard/windows-integrity-evidence/v1",
]:
    if required not in integrity_0132:
        fail(f"0.13.2 Windows integrity evidence missing primitive: {required}")
for required in ["integrity-evidence", "integrity_session_proof", "collect_windows_integrity_evidence"]:
    if required not in guard_0132:
        fail(f"0.13.2 authenticated integrity IPC missing: {required}")
if "launch заблокирован: NeverGuard Windows Integrity Evidence v1 недоступен" not in desktop_0132:
    fail("0.13.2 Desktop launch is not fail-closed on integrity evidence collection")
if "neverguard-integrity-evidence-0132.py" not in preflight or "neverguard-integrity-evidence-0132.py" not in ci:
    fail("0.13.2 integrity evidence gate is not wired into preflight/CI")
if "Integrity Evidence v1 gate OK" not in integrity_gate_0132:
    fail("0.13.2 mandatory integrity evidence gate is incomplete")

# 0.13.3 NeverGuard Windows runtime/process policy enforcement. NeverGuard
# self-mitigations are applied before Tokio starts; Java starts suspended and
# is assigned to a non-breakaway kill-on-close Job Object before execution.
policy_0133 = read("runtime/neverruntime/src/windows_policy.rs")
guard_0133 = read("runtime/neverruntime/src/guard_ipc.rs")
supervisor_0133 = read("runtime/neverruntime/src/supervisor.rs")
desktop_0133 = read("apps/desktop/src-tauri/src/main.rs")
policy_gate_0133 = read("scripts/smoke/offline/neverguard-process-policy-0133.py")
for required in [
    "SetProcessMitigationPolicy", "GetProcessMitigationPolicy", "CreateJobObjectW",
    "SetInformationJobObject", "AssignProcessToJobObject", "IsProcessInJob",
    "QueryInformationJobObject", "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION", "CREATE_SUSPENDED", "ResumeThread",
]:
    if required not in policy_0133:
        fail(f"0.13.3 Windows runtime/process policy missing primitive: {required}")
for required in ["process-policy", "process_policy_enforced", "validate_guard_process_policy"]:
    if required not in guard_0133:
        fail(f"0.13.3 authenticated process-policy IPC missing: {required}")
for required in ["prepare_runtime_command", "enforce_runtime_process", "runtime_policy: Some(runtime_policy)"]:
    if required not in supervisor_0133:
        fail(f"0.13.3 runtime supervisor policy enforcement missing: {required}")
if "launch заблокирован: NeverGuard Windows process policy verification failed" not in desktop_0133:
    fail("0.13.3 Desktop launch is not fail-closed on process policy verification")
if "neverguard-process-policy-0133.py" not in preflight or "neverguard-process-policy-0133.py" not in ci:
    fail("0.13.3 process policy gate is not wired into preflight/CI")
if "runtime/process policy 0.13.3 gate OK" not in policy_gate_0133:
    fail("0.13.3 mandatory process policy release gate is incomplete")


# 0.13.9 Cross-platform Guard CI matrix + release certification. Certification
# must come from exact-commit CI artifacts for Linux, Windows, and macOS and
# publish-check must re-hash those exact artifacts from the release bundle.
guard_targets_0139 = read("guard-ci/targets.json")
guard_matrix_0139 = read("scripts/guard_ci/matrix.py")
guard_stage_0139 = read("scripts/guard_ci/stage_release.py")
guard_release_0139 = read("cli/cmd/neverlauncher/guard_ci_release.go")
guard_gate_0139 = read("scripts/smoke/offline/guard-ci-release-certification-0139.py")
build_release_0139 = read("scripts/release/build-release.sh")
for required in [
    '"productVersion": "' + VERSION + '"',
    '"id": "guard-linux-amd64"', '"id": "guard-windows-amd64"',
    '"id": "guard-macos-universal"', '"required": true',
    '"guardRelease0139"', '"artifactHashesVerified"',
]:
    if required not in guard_targets_0139:
        fail(f"0.13.9 Guard CI targets incomplete: {required}")
for required in [
    '"commit"', '"runId"', "evidenceSha256", "artifactHashesVerified",
    "vendorSigningProvenance", "not-certified-by-ci", "command_aggregate",
]:
    if required not in guard_matrix_0139:
        fail(f"0.13.9 Guard CI matrix verifier incomplete: {required}")
for required in ["copy_verified", "os.replace", "sha256_file", "exact Guard CI-certified artifacts", "missing certified platform artifacts"]:
    if required not in guard_stage_0139:
        fail(f"0.13.9 exact-artifact staging incomplete: {required}")
for required in [
    "GUARD_CI_TARGETS.json", "GUARD_CI_MATRIX.json", "GUARD_CI_CERTIFICATION.json",
    "verifyGuardCICertificationInBundle", "verifyGuardCIArtifactsInDir",
    "all-required-cross-platform-guard-targets-pass-exact-commit-and-release-artifact-hashes",
]:
    if required not in guard_release_0139:
        fail(f"0.13.9 release certification enforcement incomplete: {required}")
for required in [
    "NEVERLAUNCHER_GUARD_CI_MATRIX_FILE", "NEVERLAUNCHER_GUARD_CI_TARGETS_FILE",
    "NEVERLAUNCHER_GUARD_PLATFORM_ARTIFACTS_DIR", "scripts/guard_ci/stage_release.py",
]:
    if required not in build_release_0139:
        fail(f"0.13.9 build-release Guard certification incomplete: {required}")
for required in [
    "guard-ci-release-certification-0139.py", "Guard CI matrix",
    "guard-ci-linux-amd64", "guard-ci-windows-amd64", "guard-ci-macos-universal",
]:
    if required not in ci and required != "Guard CI matrix":
        fail(f"0.13.9 CI matrix wiring missing: {required}")
if "guard-certification:" not in ci:
    fail("0.13.9 aggregate Guard certification CI job is missing")
if "guard-ci-release-certification-0139.py" not in preflight or "guard-ci-release-certification-0139.py" not in ci:
    fail("0.13.9 Guard release certification gate is not wired into preflight/CI")
if "cross-platform Guard CI matrix + release certification gate" not in guard_gate_0139:
    fail("0.13.9 mandatory Guard release gate is incomplete")
if not (ROOT / "cli/cmd/neverlauncher/guard_ci_release_test.go").is_file():
    fail("0.13.9 Guard release certification regression tests are missing")




# 0.14.2 Cryptographic Node Identities. Privileged ServerBridge traffic must be
# signed by a node-local Ed25519 private key; Backend stores only public identity
# material and PostgreSQL-enforced single-use nonces.
if tuple(int(p) for p in VERSION.split(".")[:3]) >= (0, 14, 2):
    crypto_migration_0142 = read("services/api/internal/dbmigrate/sql/0022_serverbridge_crypto_node_identities_0142.sql")
    crypto_identity_0142 = read("services/api/internal/httpapi/server_bridge_identity_0142.go")
    crypto_repo_0142 = read("services/api/internal/repository/server_bridge_v2.go")
    crypto_java_identity_0142 = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NodeIdentity.java")
    crypto_java_client_0142 = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java")
    crypto_gate_0142 = read("scripts/smoke/offline/serverbridge-crypto-node-identities-0142.py")
    for required in ["server_bridge_node_nonces_v2", "identity-enrollment-required", "key_fingerprint", "identity_epoch"]:
        if required not in crypto_migration_0142:
            fail(f"0.14.2 cryptographic node identity migration incomplete: {required}")
    for required in ["ed25519.Verify", "serverbridge_node_nonce_replayed", "ConsumeServerBridgeNodeNonce", "subtle.ConstantTimeCompare"]:
        if required not in crypto_identity_0142:
            fail(f"0.14.2 signed node authentication incomplete: {required}")
    for required in ["RotateServerBridgeNodeIdentity", "server_bridge_node_nonces_v2", '"replayProtection": "postgresql-single-use-nonce"']:
        if required not in crypto_repo_0142:
            fail(f"0.14.2 PostgreSQL node identity repository incomplete: {required}")
    for required in ["KeyPairGenerator.getInstance(\"Ed25519\")", "privateKeyPkcs8", "rw-------"]:
        if required not in crypto_java_identity_0142:
            fail(f"0.14.2 plugin node private-key lifecycle incomplete: {required}")
    for required in ["NeverLauncher-ServerBridge-Node-v1", "X-NeverLauncher-Node-Signature", "identity.sign(canonical)"]:
        if required not in crypto_java_client_0142:
            fail(f"0.14.2 plugin request signing incomplete: {required}")
    if "X-NeverLauncher-Server-Token" in crypto_java_client_0142:
        fail("0.14.2 plugin still contains shared ServerBridge bearer authentication")
    if "serverbridge-crypto-node-identities-0142.py" not in preflight or "serverbridge-crypto-node-identities-0142.py" not in ci:
        fail("0.14.2 cryptographic node identity gate is not wired into preflight/CI")
    if "run-serverbridge-crypto-identity-migration-e2e.sh" not in preflight or "run-serverbridge-crypto-identity-migration-e2e.sh" not in ci:
        fail("0.14.2 exact 0.14.1 -> 0.14.2 migration E2E is not wired into preflight/CI")
    if "Cryptographic Node Identities gate" not in crypto_gate_0142:
        fail("0.14.2 mandatory cryptographic identity release gate is incomplete")

# 0.14.3 One-Time Join Tickets. A join authorization is identity-bound,
# atomically consumed once, and carries a persisted redemption proof.
if tuple(int(p) for p in VERSION.split(".")[:3]) >= (0, 14, 3):
    ticket_migration_0143 = read("services/api/internal/dbmigrate/sql/0023_one_time_join_tickets_0143.sql")
    ticket_helper_0143 = read("services/api/internal/httpapi/server_bridge_join_tickets_0143.go")
    ticket_repo_0143 = read("services/api/internal/repository/server_bridge_v2.go")
    minecraft_repo_0143 = read("services/api/internal/repository/postgres.go")
    ticket_gate_0143 = read("scripts/smoke/offline/serverbridge-one-time-join-tickets-0143.py")
    for required in ["issued_identity_epoch", "issued_key_fingerprint", "redeemed_nonce_hash", "DELETE FROM minecraft_joins", "minecraft_joins_0143_terminal_check"]:
        if required not in ticket_migration_0143:
            fail(f"0.14.3 one-time join migration incomplete: {required}")
    for required in ["make([]byte, 24)", "rand.Read(buf)", '"jt_" + base64.RawURLEncoding.EncodeToString(buf)']:
        if required not in ticket_helper_0143:
            fail(f"0.14.3 CSPRNG ticket generation incomplete: {required}")
    for required in ["ConsumeServerBridgeJoinTicket", "j.ticket_version=2", "j.issued_identity_epoch=$3", "redeemed_nonce_hash"]:
        if required not in ticket_repo_0143:
            fail(f"0.14.3 atomic ServerBridge redemption incomplete: {required}")
    for required in ["ConsumeMinecraftJoin", "status='consumed'", "status='active'"]:
        if required not in minecraft_repo_0143:
            fail(f"0.14.3 Yggdrasil consume-once repository incomplete: {required}")
    if "serverbridge-one-time-join-tickets-0143.py" not in preflight or "serverbridge-one-time-join-tickets-0143.py" not in ci:
        fail("0.14.3 one-time join ticket gate is not wired into preflight/CI")
    if "run-one-time-join-ticket-migration-e2e.sh" not in preflight or "run-one-time-join-ticket-migration-e2e.sh" not in ci:
        fail("0.14.3 exact 0.14.2 -> 0.14.3 migration E2E is not wired into preflight/CI")
    if "One-Time Join Tickets gate" not in ticket_gate_0143:
        fail("0.14.3 mandatory one-time join ticket release gate is incomplete")


# 0.15.1 Production Delivery starts with an inventory that is generated from
# actual bundle bytes. Platform/architecture aliases are canonicalized in code,
# and release verify must re-hash every delivery artifact fail-closed.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 1):
    delivery_0151 = read("cli/cmd/neverlauncher/delivery_manifest.go")
    release_0151 = read("cli/cmd/neverlauncher/release_commands.go")
    delivery_gate_0151 = read("scripts/smoke/offline/delivery-manifest-platform-architecture-0151.py")
    for required in [
        'DELIVERY_MANIFEST.json', "normalizeDeliveryPlatform", "normalizeDeliveryArchitecture",
        "verifyDeliveryManifest0151", "resolveDeliveryArtifacts0151", "checksum/size mismatch",
    ]:
        if required not in delivery_0151:
            fail(f"0.15.1 delivery implementation incomplete: {required}")
    for required in ["writeDeliveryManifest0151(out, ver)", "verifyDeliveryManifest0151(out, ver)", "delivery-manifest-platform-architecture"]:
        if required not in release_0151:
            fail(f"0.15.1 release integration incomplete: {required}")
    if "DELIVERY_MANIFEST.json" not in read("scripts/smoke/release-required/release-bundle.sh"):
        fail("0.15.1 publish gate does not require DELIVERY_MANIFEST.json")
    if "delivery-manifest-platform-architecture-0151.py" not in preflight or "delivery-manifest-platform-architecture-0151.py" not in ci:
        fail("0.15.1 delivery gate is not wired into preflight/CI")
    if "Delivery Manifest + platform/architecture gate: OK" not in delivery_gate_0151:
        fail("0.15.1 mandatory delivery gate is incomplete")
    if not (ROOT / "cli/cmd/neverlauncher/delivery_manifest_test.go").is_file():
        fail("0.15.1 delivery regression tests are missing")


# 0.15.3 Linux production delivery is a native dual-architecture package boundary.
# x64 and ARM64 artifacts are built on native Linux runners, checked as ELF64,
# packed deterministically, and rebound to DELIVERY_MANIFEST.json before publish.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 3):
    linux_delivery_0153 = read("cli/cmd/neverlauncher/linux_delivery.go")
    linux_builder_0153 = read("scripts/release/build-linux-production.sh")
    linux_packager_0153 = read("scripts/release/linux-package.py")
    linux_release_0153 = read("scripts/release/build-release.sh")
    linux_gate_0153 = read("scripts/smoke/offline/linux-x64-arm64-production-packages-0153.py")
    release_bundle_0153 = read("scripts/smoke/release-required/release-bundle.sh")
    for required in [
        "LINUX_PRODUCTION_EVIDENCE.json", "GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json",
        "inspectLinuxELFBytes0153", "EM_X86_64", "EM_AARCH64",
        "verifyLinuxPackageArchive0153", "verifyLinuxProductionEvidence0153",
    ]:
        if required not in linux_delivery_0153:
            fail(f"0.15.3 Linux delivery verifier incomplete: {required}")
    for required in [
        'ARCH="x64"', 'ARCH="arm64"', "neverlauncher-cli-linux-${ARCH}",
        "neverlauncher-api-linux-${ARCH}", "neverlauncher-desktop-linux-${ARCH}",
        "neverguard-linux-${ARCH}", "neverruntime-linux-${ARCH}", "linux-package.py",
    ]:
        if required not in linux_builder_0153:
            fail(f"0.15.3 native Linux builder incomplete: {required}")
    for required in ["gzip.GzipFile", "mtime=0", "LINUX_PACKAGE_MANIFEST_", "production package requires ELF64 little-endian"]:
        if required not in linux_packager_0153:
            fail(f"0.15.3 deterministic Linux packager incomplete: {required}")
    for required in ["NEVERLAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR", "LINUX_DUAL_ARCH_REQUIRED", "neverlauncher-linux-${arch}-${VERSION}.tar.gz"]:
        if required not in linux_release_0153:
            fail(f"0.15.3 release staging incomplete: {required}")
    for required in ["linux-production:", "ubuntu-24.04-arm", "build-linux-production.sh", "NEVERLAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR"]:
        if required not in ci:
            fail(f"0.15.3 Linux native CI matrix incomplete: {required}")
    for required in ["LINUX_PRODUCTION_EVIDENCE.json", "LINUX_PACKAGE_MANIFEST_X64.json", "LINUX_PACKAGE_MANIFEST_ARM64.json"]:
        if required not in release_bundle_0153:
            fail(f"0.15.3 release bundle gate incomplete: {required}")
    if "linux-x64-arm64-production-packages-0153.py" not in preflight or "linux-x64-arm64-production-packages-0153.py" not in ci:
        fail("0.15.3 Linux dual-arch package gate is not wired into preflight/CI")
    if "Linux x64 + ARM64 production packages gate: OK" not in linux_gate_0153:
        fail("0.15.3 mandatory Linux production package gate is incomplete")
    if not (ROOT / "cli/cmd/neverlauncher/linux_delivery_test.go").is_file():
        fail("0.15.3 Linux delivery regression tests are missing")


# 0.15.4 macOS production delivery is a thin dual-architecture Developer ID +
# Apple notarization boundary. Ad-hoc signing is CI-only; publish must prove
# accepted notarization, stapling and Gatekeeper validation for x64 and ARM64.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 4):
    macos_delivery_0154 = read("cli/cmd/neverlauncher/macos_delivery.go")
    macos_builder_0154 = read("scripts/release/build-macos-production.sh")
    macos_packager_0154 = read("scripts/release/macos-package.py")
    macos_release_0154 = read("scripts/release/build-release.sh")
    macos_gate_0154 = read("scripts/smoke/offline/notarized-macos-x64-arm64-0154.py")
    macos_workflow_0154 = read(".github/workflows/macos-production-delivery.yml")
    release_bundle_0154 = read("scripts/smoke/release-required/release-bundle.sh")
    for required in [
        "MACOS_NOTARIZATION_EVIDENCE.json", "GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json",
        "CPU_TYPE_X86_64", "CPU_TYPE_ARM64", "LC_CODE_SIGNATURE",
        "verifyMacOSPackageArchive0154", "verifyMacOSNotarizationEvidence0154",
        "Developer ID + Apple notarization", "stapler", "Gatekeeper",
    ]:
        if required not in macos_delivery_0154:
            fail(f"0.15.4 macOS delivery verifier incomplete: {required}")
    for required in [
        "x86_64-apple-darwin", "aarch64-apple-darwin", "Developer ID Application",
        "--options runtime", "notarytool submit", "stapler staple", "stapler validate", "spctl --assess",
    ]:
        if required not in macos_builder_0154:
            fail(f"0.15.4 macOS production builder incomplete: {required}")
    for required in ["MACOS_PACKAGE_MANIFEST_", "MACOS_NOTARIZATION_EVIDENCE.json", "GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json", "Accepted"]:
        if required not in macos_packager_0154:
            fail(f"0.15.4 macOS packager/evidence generator incomplete: {required}")
    for required in ["NEVERLAUNCHER_MACOS_PRODUCTION_ARTIFACTS_DIR", "MACOS_DUAL_ARCH_REQUIRED", "MACOS_NOTARIZATION_EVIDENCE.json"]:
        if required not in macos_release_0154:
            fail(f"0.15.4 release staging incomplete: {required}")
    for required in ["MACOS_DEVELOPER_ID_P12_BASE64", "APPLE_NOTARY_PRIVATE_KEY_BASE64", "notarytool store-credentials", "verify-macos --bundle", "--production"]:
        if required not in macos_workflow_0154:
            fail(f"0.15.4 production notarization workflow incomplete: {required}")
    for required in ["MACOS_NOTARIZATION_EVIDENCE.json", "MACOS_PACKAGE_MANIFEST_X64.json", "MACOS_PACKAGE_MANIFEST_ARM64.json", "macos-x64.zip", "macos-arm64.zip"]:
        if required not in release_bundle_0154:
            fail(f"0.15.4 release bundle gate incomplete: {required}")
    if "notarized-macos-x64-arm64-0154.py" not in preflight or "notarized-macos-x64-arm64-0154.py" not in ci:
        fail("0.15.4 macOS notarization gate is not wired into preflight/CI")
    if "notarized macOS x64 + ARM64 gate: OK" not in macos_gate_0154:
        fail("0.15.4 mandatory macOS notarization gate is incomplete")
    if not (ROOT / "cli/cmd/neverlauncher/macos_delivery_test.go").is_file():
        fail("0.15.4 macOS delivery regression tests are missing")


# 0.15.5 Managed JRE Distribution is a six-target first-party delivery boundary.
# Release bytes remain the exact vendor Temurin archives; NeverRuntime verifies the
# pinned distribution manifest, archive checksum/size and java runtime before use.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 5):
    jre_delivery_0155 = read("cli/cmd/neverlauncher/managed_jre_delivery.go")
    jre_builder_0155 = read("scripts/release/managed-jre-distribution.py")
    jre_runtime_0155 = read("runtime/neverruntime/src/managed_java.rs")
    jre_release_0155 = read("scripts/release/build-release.sh")
    jre_gate_0155 = read("scripts/smoke/offline/managed-jre-distribution-0155.py")
    jre_workflow_0155 = read(".github/workflows/managed-jre-production-delivery.yml")
    release_bundle_0155 = read("scripts/smoke/release-required/release-bundle.sh")
    for required in [
        "MANAGED_JRE_MANIFEST.json", "MANAGED_JRE_EVIDENCE.json",
        "exact-vendor-archive-sha256", "inspectWindowsPEBytes0152",
        "inspectLinuxELFBytes0153", "inspectMacOSMachOBytes0154",
        "verifyManagedJREDistribution0155", "managed-jre",
    ]:
        if required not in jre_delivery_0155:
            fail(f"0.15.5 Managed JRE verifier incomplete: {required}")
    for required in [
        "https://api.adoptium.net/v3", '"image_type": "jre"',
        '"jvm_impl": "hotspot"', '"vendor": "eclipse"',
        "download_exact", "sourceSha256", "MANAGED_JRE_EVIDENCE.json",
    ]:
        if required not in jre_builder_0155:
            fail(f"0.15.5 Managed JRE builder incomplete: {required}")
    for required in [
        "ensure_managed_java_from_distribution", "NEVERLAUNCHER_MANAGED_JRE_MANIFEST",
        "NEVERLAUNCHER_MANAGED_JRE_MANIFEST_SHA256", "exact vendor archive SHA-256",
        "ensure_local_archive", "Managed JRE javaEntry mismatch",
    ]:
        if required not in jre_runtime_0155:
            fail(f"0.15.5 NeverRuntime Managed JRE consumer incomplete: {required}")
    for required in [
        "NEVERLAUNCHER_MANAGED_JRE_ARTIFACTS_DIR", "MANAGED_JRE_REQUIRED",
        "MANAGED_JRE_MANIFEST.json", "neverlauncher-jre-temurin21-",
    ]:
        if required not in jre_release_0155:
            fail(f"0.15.5 release JRE staging incomplete: {required}")
    for required in ["Managed JRE Production Delivery", "managed-jre-distribution.py", "delivery verify-jre"]:
        if required not in jre_workflow_0155:
            fail(f"0.15.5 Managed JRE production workflow incomplete: {required}")
    for required in [
        "MANAGED_JRE_MANIFEST.json", "MANAGED_JRE_EVIDENCE.json",
        "neverlauncher-jre-temurin21-windows-x64", "neverlauncher-jre-temurin21-windows-arm64",
        "neverlauncher-jre-temurin21-linux-x64", "neverlauncher-jre-temurin21-linux-arm64",
        "neverlauncher-jre-temurin21-macos-x64", "neverlauncher-jre-temurin21-macos-arm64",
    ]:
        if required not in release_bundle_0155:
            fail(f"0.15.5 release bundle JRE gate incomplete: {required}")
    if "managed-jre-distribution-0155.py" not in preflight or "managed-jre-distribution-0155.py" not in ci:
        fail("0.15.5 Managed JRE gate is not wired into preflight/CI")
    if "Managed JRE Distribution gate: OK" not in jre_gate_0155:
        fail("0.15.5 mandatory Managed JRE Distribution gate is incomplete")
    if not (ROOT / "cli/cmd/neverlauncher/managed_jre_delivery_test.go").is_file():
        fail("0.15.5 Managed JRE regression tests are missing")


# 0.15.6 Unified Transactional Updater Core must be an executable file-update path,
# not a manifest-only declaration. It is used by client install/update/package-apply
# and is self-tested on native Linux/Windows/macOS CI runners.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 6):
    updater_core_0156 = read("cli/cmd/neverlauncher/transactional_updater.go")
    updater_cmd_0156 = read("cli/cmd/neverlauncher/transactional_updater_command.go")
    updater_client_0156 = read("cli/cmd/neverlauncher/client_lifecycle.go") + read("cli/cmd/neverlauncher/package_commands.go")
    updater_gate_0156 = read("scripts/smoke/offline/unified-transactional-updater-core-0156.py")
    updater_tests_0156 = read("cli/cmd/neverlauncher/transactional_updater_test.go")
    for required in [
        "prepareLocked", "commitLocked", "rollbackLocked", "recoverIncompleteLocked",
        "Stage verified bytes before touching the live tree", "replaceFileAtomicPortable", "updaterProcessAlive0156",
        "updater refuses symlink parent", 'Phase = "committing"', 'Phase = "verifying"',
    ]:
        if required not in updater_core_0156:
            fail(f"0.15.6 transactional updater core incomplete: {required}")
    for required in ["applyManifestUpdate0156", "runUpdaterSelfTest0156", "automatic-rollback", "durable-journal"]:
        if required not in updater_cmd_0156:
            fail(f"0.15.6 updater command path incomplete: {required}")
    for required in ["clientPackageConsumeTransactional0156", "client-repair", "client-rollback", "unified-transactional-updater/0.15.6", ".neverlauncher/client-state.json"]:
        if required not in updater_client_0156:
            fail(f"0.15.6 client updater integration incomplete: {required}")
    for required in ["TestTransactionalUpdaterCommitAndDelete0156", "TestTransactionalUpdaterPostVerifyFailureRollsBack0156", "TestTransactionalUpdaterCrashRecovery0156"]:
        if required not in updater_tests_0156:
            fail(f"0.15.6 updater regression tests missing: {required}")
    if "Unified Transactional Updater Core gate: OK" not in updater_gate_0156:
        fail("0.15.6 updater mandatory gate incomplete")
    if "unified-transactional-updater-core-0156.py" not in preflight or "unified-transactional-updater-core-0156.py" not in ci:
        fail("0.15.6 updater gate is not wired into preflight/CI")
    if ci.count("update self-test") < 4:
        fail("0.15.6 updater native runtime self-tests are missing from CI")

# 0.15.7 Desktop/Guard/Runtime transactional update must wire the 0.15.6 core
# into the actual self-update path and preserve platform signing/package boundaries.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 7):
    component_core_0157 = read("cli/cmd/neverlauncher/component_update.go")
    component_main_0157 = read("cli/cmd/neverlauncher/main.go")
    component_tests_0157 = read("cli/cmd/neverlauncher/component_update_test.go")
    desktop_0157 = read("apps/desktop/src-tauri/src/main.rs")
    windows_0157 = read("scripts/release/build-windows-desktop.ps1")
    linux_0157 = read("scripts/release/linux-package.py")
    macos_0157 = read("scripts/release/macos-package.py") + read("scripts/release/build-macos-production.sh")
    component_gate_0157 = read("scripts/smoke/offline/desktop-guard-runtime-transactional-update-0157.py")
    rust_guard_0157 = read("runtime/neverruntime/src/guard_ipc.rs") + read("runtime/neverruntime/src/linux_guard.rs") + read("runtime/neverruntime/src/macos_guard.rs")
    for required in [
        "applyComponentPackage0157", "applyAdjacentComponentUpdate0157", "applyComponentTree0157",
        "recoverComponentTreesLocked0157", "rollbackComponentTreeLocked0157", "hashPackagePin0157",
        "authenticode-rfc3161", "sha256-delivery", "developer-id-notarized", "macosTreeRollback",
    ]:
        if required not in component_core_0157:
            fail(f"0.15.7 component transactional updater incomplete: {required}")
    for required in ['case "components":', 'case "component-self-test":', '"--wait-pid"', '"--restart"']:
        if required not in component_main_0157:
            fail(f"0.15.7 update CLI integration incomplete: {required}")
    for required in ["install_launcher_update", "neverguard.shutdown().await", "--current-desktop", "--expected-sha256", "exit_handle.exit(0)"]:
        if required not in desktop_0157:
            fail(f"0.15.7 Desktop self-update handoff incomplete: {required}")
    for required in ["neverruntime.exe", "neverlauncher-cli.exe", "COMPONENT_UPDATE_MANIFEST.json", "authenticode-rfc3161"]:
        if required not in windows_0157:
            fail(f"0.15.7 Windows component package incomplete: {required}")
    for required in ["COMPONENT_UPDATE_MANIFEST.json", "sha256-delivery", "neverruntime"]:
        if required not in linux_0157:
            fail(f"0.15.7 Linux component package incomplete: {required}")
    for required in ["COMPONENT_UPDATE_MANIFEST.json", "macos-app-bundle", "developer-id-notarized", "adhoc-development"]:
        if required not in macos_0157:
            fail(f"0.15.7 macOS component package incomplete: {required}")
    for required in ["canonical_arch", "canonical_identity", "package_path", "MacOSPackageArtifact"]:
        if required not in rust_guard_0157:
            fail(f"0.15.7 Guard canonical package verification incomplete: {required}")
    for required in ["TestComponentUpdateAdjacentCommit0157", "TestComponentTreePostVerifyFailureRollsBack0157", "TestComponentUpdateRequiresPinnedProductionArchive0157"]:
        if required not in component_tests_0157:
            fail(f"0.15.7 component updater regression tests missing: {required}")
    if "Desktop/Guard/Runtime transactional update gate: OK" not in component_gate_0157:
        fail("0.15.7 component updater mandatory gate incomplete")
    if "desktop-guard-runtime-transactional-update-0157.py" not in preflight or "desktop-guard-runtime-transactional-update-0157.py" not in ci:
        fail("0.15.7 component updater gate is not wired into preflight/CI")
    if ci.count("update component-self-test") < 4:
        fail("0.15.7 native component updater self-tests are missing from CI")


if errors:
    print("[NeverLauncher] repository policy: FAILED", file=sys.stderr)
    for item in errors:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)

print(f"[NeverLauncher] repository policy OK: {VERSION}; immutable releases/client/desktop/key lifecycle/SBOM/provenance production gates активны")

# 0.13.0 Device Trust Release certification and runtime contract.
if (ROOT / "VERSION").read_text(encoding="utf-8").strip() >= "0.13.0":
    dt_release = read("cli/cmd/neverlauncher/device_trust_release.go")
    dt_runtime = read("services/api/internal/httpapi/device_trust_release_0130.go")
    dt_targets_0130 = read("device-trust/targets.json")
    build_release_0130 = read("scripts/release/build-release.sh")
    if "DEVICE_TRUST_CERTIFICATION.json" not in dt_release or "deviceTrustCertificationRequired" not in dt_release:
        fail("0.13.0 release bundle lacks Device Trust certification enforcement")
    if "exact-commit-public-device-trust-matrix" not in dt_runtime or "0018_device_trust_stabilization_01210" not in dt_runtime:
        fail("0.13.0 runtime Device Trust release contract is incomplete")
    if "deviceTrustRelease0130" not in dt_targets_0130:
        fail("0.13.0 public Device Trust targets do not require release acceptance")
    if "NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE" not in build_release_0130:
        fail("0.13.0 build-release cannot embed Device Trust matrix")
    if "device-trust-release-0130.py" not in preflight or "device-trust-release-0130.py" not in ci:
        fail("0.13.0 Device Trust Release gate is not wired into preflight/CI")
