#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
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
production_release_workflow = read(".github/workflows/production-release-candidate.yml")
compatibility_workflow = read(".github/workflows/compatibility.yml")
if 'group: neverlauncher-compatibility-${{ github.ref }}-${{ github.event_name }}' not in compatibility_workflow:
    fail("Compatibility concurrency must isolate push from scheduled certification")
if "needs.compatibility-e2e.result != 'cancelled'" not in compatibility_workflow:
    fail("Compatibility publish must not convert a cancelled matrix into a failing check")

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
if "release-bundle:" not in production_release_workflow or "Build and cryptographically verify complete release bundle" not in production_release_workflow:
    fail("dedicated production workflow не собирает полный production release bundle")
if "release-bundle:" in ci or "windows-production-signed:" in ci or "macos-production-notarized:" in ci:
    fail("ordinary main CI не должен зависеть от publish-only signing credentials")
if "production-e2e:" not in ci or "release-bundle" in ci.split("production-e2e:", 1)[1].split("needs:", 1)[1].split("\n", 1)[0]:
    fail("main functional E2E должен выполняться независимо от production signing")
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
if 'expect="$4" out="$RUNTIME_DIR/validate-$id-$expect.json"' in e2e_script:
    fail("actual Minecraft E2E validate_join снова разыменовывает local id/expect до их присваивания при set -u")
for required in [
    'local id="$1" key="$2" plugin_sha="$3" expect="$4"',
    'local out="$RUNTIME_DIR/validate-${id}-${expect}.json" code body',
]:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E validate_join nounset regression guard missing: {required}")
for forbidden in [
    '$fingerprint_match" == "t"',
    '$redeemed_ip_present" == "t"',
    'consumed\\|t\\|t\\|64\\|t',
]:
    if forbidden in e2e_script:
        fail(f"actual Minecraft E2E сравнивает PostgreSQL ::text boolean с устаревшим psql token t: {forbidden}")
for required in [
    '$fingerprint_match" == "true"',
    '$redeemed_ip_present" == "true"',
    'consumed\\|true\\|true\\|64\\|true',
]:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E PostgreSQL redemption/handoff boolean assertion missing: {required}")
for required in ["onboardAccessibility:false", "skipMultiplayerWarning:true", "joinedFirstServer:true"]:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E pristine client may block Quick Play on first-run UI: {required}")
for required in [
    "paper_bootstrap_hash_failure", "wait_paper_healthy_with_bootstrap_recovery",
    "Hash check failed for downloaded file mojang_", "for attempt in 1 2 3",
    "rm -f /data/mojang_*.jar /data/paper-*.jar", "compose up -d --force-recreate paper",
]:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E Paper/Mojang bootstrap recovery hardening missing: {required}")
if "compose down -v" in e2e_script[e2e_script.find("paper_bootstrap_hash_failure"):e2e_script.find("wait_bridge_heartbeat")]:
    fail("Paper bootstrap recovery must not reset PostgreSQL/Redis/security state")
for required in [
    "hashlib.sha256", "backend checksum mismatch after upload", "local package file changed before upload", "manifestSettings",
    'response.status == 429', 'Retry-After', 'X-RateLimit-Reset', 'time.sleep(delay)',
    'passkey_step_up', '/api/v1/auth/passkeys/step-up/begin', '--webauthn-state', 'f"--challenge={challenge}"',
]:
    if required not in e2e_publish:
        fail(f"E2E package publisher не проверяет реальный artifact lifecycle/rate-limit contract: {required}")
neverruntime_lib = read("runtime/neverruntime/src/lib.rs")
if '#[serde(default)]\n    pub executable: bool,' not in neverruntime_lib:
    fail("NeverRuntime manifest signing payload must preserve executable=false exactly like Go ManifestFile")
for required in [
    'reqwest::StatusCode::TOO_MANY_REQUESTS', 'Retry-After', 'X-RateLimit-Reset',
    'tokio::time::sleep(Duration::from_secs(delay)).await', 'FILE_DOWNLOAD_RATE_LIMIT_RETRIES',
]:
    if required not in neverruntime_lib:
        fail(f"NeverRuntime clean sync не уважает production rate-limit retry contract: {required}")

for required in ['JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"', '${JAVA_HOME}/bin/java', '--java "$JAVA_BIN"']:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E не закрепляет setup-java runtime: {required}")
for required in ['webauthn-test-authenticator.py', '/api/v1/auth/passkeys/register/begin', '--webauthn-helper "$WEBAUTHN"', '--webauthn-state "$PASSKEY_STATE"']:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E не выполняет реальный fresh WebAuthn step-up перед publish: {required}")
for required in ['"--transaction-token=$(jq -er', '"--challenge=$(jq -er', '"--user-handle=$(jq -er']:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E передаёт opaque WebAuthn argv небезопасно: {required}")
for required in [
    'device-trust-crypto.py', 'guard-attestation-e2e.py', 'keyAlgorithm:"p256"', 'keyBinding:"hardware"',
    '/attest/begin', '/guard-attest/begin', 'guardAttestationTicket', '/api/v1/minecraft/session',
    'minecraftAccessToken:$token', 'GUARD_E2E_VERSION="$VERSION"', 'guard-policy.override.yml',
]:
    if required not in e2e_script:
        fail(f"actual Minecraft E2E не проходит hardware-attested Guard-bound Minecraft integrity flow: {required}")
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
forge_runtime = read("cli/cmd/neverlauncher/forge_runtime.go")
forge_runtime_tests = read("cli/cmd/neverlauncher/forge_runtime_test.go")
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
for required in ["maxCompatibilityArtifact", "secureClientDestination", "validateAssetLogicalPath"]:
    if required not in vanilla_runtime:
        fail(f"Vanilla stabilization missing: {required}")
for required in [
    "fetchForgeLikeMetadata", "compatibilityHTTPAttempts", 'strings.Contains(err.Error(), "HTTP 404")',
    "compatibilityRetryDelay", "forgeLikeMetadataRefreshURL", "_neverlauncher_refresh",
    "fresh metadata snapshots",
]:
    if required not in forge_runtime:
        fail(f"Forge/NeoForge mutable Maven metadata retry hardening missing: {required}")
for required in [
    "TestNeoForgeMavenMetadataRetriesTransientNotFound",
    "TestNeoForgeMavenMetadataPersistentNotFoundFailsClosed",
    "TestNeoForgeMavenMetadataRetriesSemanticallyIncompleteSnapshot",
    "TestNeoForgeMavenMetadataPersistentSemanticMismatchFailsClosed",
]:
    if required not in forge_runtime_tests:
        fail(f"NeoForge Maven metadata retry regression test missing: {required}")
if managed_java.count("check_java(Some(java.to_string_lossy().to_string()), Some(major)).await?") != 1:
    fail("Managed Java cached runtime validation must invoke java -version exactly once")
if "compatibility path содержит symlink" not in runtime_compat:
    fail("NeverRuntime Compatibility Engine must reject symlink path components")
for required in [
    "ensure_neoforge_bootstrap_ignores_base_client",
    'value == "--fml.neoForgeVersion"',
    "neoforge_bootstrap_ignores_base_client_jar_module",
    'file_name.starts_with(prefix)',
]:
    if required not in runtime_compat:
        fail(f"NeverRuntime NeoForge BootstrapLauncher module-isolation regression guard missing: {required}")
if "runtime record java path вышел за Managed Java root через symlink" not in managed_java:
    fail("Managed Java cache validation must reject symlink escape")
for required in ["paperHealthy", "exitCode", "evidence files are incomplete", "evidence manifestLoader mismatch"]:
    if required not in compat_tool:
        fail(f"compatibility evidence stabilization missing: {required}")

# 11b. 0.16.11 compatibility hardening: interrupted downloads must be
# recoverable, corrupt cache entries quarantined, exact-version Mojang
# metadata may recover from a verified local snapshot during an outage, and
# archive/security boundaries must remain fail-closed.
compat_hardening = read("cli/cmd/neverlauncher/compatibility_hardening.go")
for required in [
    "resolveVanillaMetadataWithRecovery", "latest/snapshot metadata recovery запрещён",
    "quarantineCompatibilityArtifact", "fetchVerifiedBytesWithLocalCache",
]:
    if required not in compat_hardening:
        fail(f"0.16.11 compatibility hardening missing recovery primitive: {required}")
for required in [
    "inspectVanillaPartial", "validateContentRange", "Range", "Resumed",
    "maxCompatibilityNativeExtract", "replaceDirectoryAtomicPortable", "virtual assets staging", "resources staging",
]:
    if required not in vanilla_runtime and required not in stability_go:
        fail(f"0.16.11 compatibility hardening missing cache/security primitive: {required}")
for required in [
    "TestDownloadVanillaArtifactResumesVerifiedPartial",
    "TestVanillaMetadataRecoveryExactVersionOnly",
    "TestDownloadVanillaArtifactQuarantinesCorruptCache",
    "TestDownloadVanillaArtifactRepairsCorruptCompletedPartialInSameRun",
    "TestVanillaMetadataRecoveryDoesNotResurrectMissingAuthoritativeVersion",
]:
    if required not in read("cli/cmd/neverlauncher/compatibility_hardening_test.go"):
        fail(f"0.16.11 compatibility hardening regression test missing: {required}")
for required in [
    "java_sha256", "schema_version: \"1.2\"", "managed_java_send_with_retry",
    "quarantine_broken_archive", "Managed Java partial archive must not be a symlink",
]:
    if required not in managed_java:
        fail(f"0.16.11 Managed Java hardening missing: {required}")



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
    'ProductVersion string                       `json:"productVersion,omitempty"`',
    "targetsProductVersion := strings.TrimSpace(targets.ProductVersion)",
    'targetsProductVersion != "" && targetsProductVersion != ver',
    "matrix.ProductVersion != ver",
]:
    if required not in compat_release:
        fail(f"compatibility release VERSION single-source contract missing: {required}")
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
compat_release_tests_path = ROOT / "cli/cmd/neverlauncher/compatibility_release_test.go"
if not compat_release_tests_path.is_file():
    fail("compatibility release certification regression tests are missing")
compat_release_tests = compat_release_tests_path.read_text(encoding="utf-8")
for required in [
    "TestCompatibilityCertificationAcceptsVersionlessTargetsFromRepositoryContract",
    "TestCompatibilityCertificationRejectsExplicitTargetsVersionMismatch",
    "TestCompatibilityCertificationRejectsMatrixVersionMismatch",
]:
    if required not in compat_release_tests:
        fail(f"compatibility release VERSION regression test missing: {required}")
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 11):
    if "compatibility-hardening-cache-recovery-upstream-failure-security" not in compat_release:
        fail("0.16.11 release certification does not bind compatibility hardening policy")
    if "TestCompatibilityCertificationHardening01611Policy" not in compat_release_tests:
        fail("0.16.11 compatibility hardening release regression test missing")

release_cert_fetch = read("scripts/release/fetch-exact-certifications.py")
for required in [
    'head_sha', 'refusing release fallback', 'status": "passed"', 'archive_download_url',
    'neverlauncher-compatibility-matrix-', 'neverlauncher-device-trust-matrix-', 'exact-commit',
    'ArtifactRedirectHandler', 'ARTIFACT_REDIRECT_SUFFIXES', 'artifact redirect host is not trusted',
    'Never forward the GitHub bearer token',
]:
    if required not in release_cert_fetch:
        fail(f"release exact-commit certification fetcher incomplete: {required}")
for required in [
    'actions: read', 'fetch-exact-certifications.py', '--commit "$GITHUB_SHA"',
    'NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE', 'NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE',
    'external-certifications/compatibility/matrix.json', 'external-certifications/device-trust/matrix.json',
]:
    if required not in production_release_workflow:
        fail(f"production release не ждёт exact-commit Compatibility/Device Trust certification: {required}")


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
    "/api/v1/server-bridge/servers/dt-e2e-paper/heartbeat", "BRIDGE_RELEASE_ALLOWLIST_JSON",
    "bungeeCordSha256", "waterfallSha256", "bukkitSha256", "spigotSha256", "foliaSha256",
    "fabricSha256", "forgeSha256", "neoforgeSha256",
    "bridge_integrity_verified", "pluginVersion:$version", "pluginSha256:$sha",
    "/api/v1/auth/sessions", "/attest/begin", "/api/v1/auth/devices/key-recovery/begin",
    "/api/v1/auth/passkeys/register/begin", "/api/v1/auth/passkeys/step-up/begin",
    "recoveryPhishingResistantEndToEnd:true", "replacement_reason='recover'",
    "launcher_session_or_handoff_missing_or_expired", "recovery-replay.json",
    "recovery challenge replay after source-device tombstone", "purpose='key-recover' AND consumed_at IS NOT NULL",
    "активное исходное устройство не найдено",
    "require 0.12.9 -> current shipping migration upgrade evidence",
    '--arg migration "$EXPECTED_CURRENT_MIGRATION"', '.upgrade.toMigration==$migration',
    '.upgrade.guardPurposeMigrationSealed==true',
    "secret material leaked into public evidence", 'repository:"postgresql"',
]:
    if required not in device_trust_e2e:
        fail(f"0.12.9 PostgreSQL Device Trust E2E missing runtime primitive: {required}")
for required in ['"--transaction-token=$(jq -er', '"--challenge=$(jq -er', '"--user-handle=$(jq -er']:
    if required not in device_trust_e2e:
        fail(f"Device Trust E2E передаёт opaque WebAuthn argv небезопасно: {required}")
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


# 0.16.1 Guard Attestation PostgreSQL challenge-purpose completion. The runtime
# security flow is useless if the sealed SQL schema rejects its one-shot purposes.
guard_purpose_migration_api = read("services/api/internal/dbmigrate/sql/0031_guard_attestation_challenge_purposes_0161.sql")
guard_purpose_migration_cli = read("cli/internal/dbmigrate/sql/0031_guard_attestation_challenge_purposes_0161.sql")
if guard_purpose_migration_api != guard_purpose_migration_cli:
    fail("0.16.1 API/CLI Guard challenge-purpose migration 0031 differs")
for required in [
    "device_challenges_purpose_check", "guard-attest-v1", "guard-launch-v1",
    "key-rotate", "key-recover",
]:
    if required not in guard_purpose_migration_api:
        fail(f"0.16.1 Guard challenge-purpose migration missing invariant: {required}")

guard_migration_e2e = read("e2e/scripts/run-device-trust-migration-e2e.sh")
for required in [
    "0031_guard_attestation_challenge_purposes_0161", "dtmig-guard-attest",
    "guard-attest-v1", "dtmig-guard-launch", "guard-launch-v1",
    "guardPurposeMigrationSealed:true",
]:
    if required not in guard_migration_e2e:
        fail(f"0.16.1 Guard challenge-purpose PostgreSQL E2E missing: {required}")

guard_attestation_backend_0161 = read("services/api/internal/httpapi/guard_attestation_0134.go")
for required in [
    "canonicalGuardAttestationTime0134",
    "Truncate(time.Microsecond)",
    "expires := canonicalGuardAttestationTime0134",
    "ticketExpires := canonicalGuardAttestationTime0134",
]:
    if required not in guard_attestation_backend_0161:
        fail(f"0.16.1 Guard Attestation timestamp canonicalization missing: {required}")

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
    crypto_migration_e2e_0142 = read("e2e/scripts/run-serverbridge-crypto-identity-migration-e2e.sh")
    for forbidden in ['identity-enrollment-required||||||0||||t|t', 'invalidated|t"']:
        if forbidden in crypto_migration_e2e_0142:
            fail(f"0.14.2 migration E2E compares PostgreSQL ::text boolean with obsolete token: {forbidden}")
    for required in ['identity-enrollment-required||||||0||||true|true', 'invalidated|true']:
        if required not in crypto_migration_e2e_0142:
            fail(f"0.14.2 migration E2E PostgreSQL boolean assertion missing: {required}")
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
    ticket_migration_e2e_0143 = read("e2e/scripts/run-one-time-join-ticket-migration-e2e.sh")
    for forbidden in ['invalidated|t|', '|t|64']:
        if forbidden in ticket_migration_e2e_0143:
            fail(f"0.14.3 migration E2E compares PostgreSQL ::text boolean with obsolete token: {forbidden}")
    for required in ['invalidated|true|', '|true|64']:
        if required not in ticket_migration_e2e_0143:
            fail(f"0.14.3 migration E2E PostgreSQL boolean assertion missing: {required}")
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
    for required in ["linux-production:", "ubuntu-24.04-arm", "build-linux-production.sh"]:
        if required not in ci:
            fail(f"0.15.3 Linux native CI matrix incomplete: {required}")
    if "NEVERLAUNCHER_LINUX_PRODUCTION_ARTIFACTS_DIR" not in production_release_workflow:
        fail("0.15.3 Linux production release staging is not wired")
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
        "managed-jre-production:",
        "Managed Java II Java 8/16/17/21/25 production E2E + Temurin 21 delivery",
        "Upload exact-commit Managed JRE production assets",
        'name: neverlauncher-managed-jre-${{ github.sha }}',
    ]:
        if required not in ci:
            fail(f"0.15.5 Managed JRE main certification is incomplete: {required}")
    for required in [
        "Download Managed JRE six-target production assets",
        "path: managed-jre-artifacts",
        'NEVERLAUNCHER_MANAGED_JRE_ARTIFACTS_DIR: ${{ github.workspace }}/managed-jre-artifacts',
    ]:
        if required not in production_release_workflow:
            fail(f"0.15.5 Managed JRE production release staging is incomplete: {required}")
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


# 0.16.5 Managed Java II must be an executable resolver/install/cache path for
# Java 8/16/17/21/25. Java 16 must use historical GA fallback instead of a
# current-release declaration, and the exact runtime path is exercised in CI.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 5):
    managed_java_0165 = read("runtime/neverruntime/src/managed_java.rs")
    managed_java_cli_0165 = read("runtime/neverruntime/src/bin/neverruntime.rs")
    managed_java_e2e_0165 = read("e2e/scripts/run-managed-java-II-e2e.sh")
    managed_java_gate_0165 = read("scripts/smoke/offline/managed-java-II-0165.py")
    release_commands_0165 = read("cli/cmd/neverlauncher/release_commands.go")
    release_builder_0165 = read("scripts/release/build-release.sh")
    release_bundle_0165 = read("scripts/smoke/release-required/release-bundle.sh")
    for required in [
        "MANAGED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
        "assets/latest/{major}/hotspot", "assets/feature_releases/{major}/ga",
        'for image_type in ["jre", "jdk"]', "validate_managed_java_major",
        "ensure_archive", "validate_installed_runtime",
    ]:
        if required not in managed_java_0165:
            fail(f"0.16.5 Managed Java II runtime incomplete: {required}")
    if "--major <8|16|17|21|25>" not in managed_java_cli_0165:
        fail("0.16.5 Managed Java II CLI does not expose all certified majors")
    for required in ["for major in 8 16 17 21 25", "java ensure", "MANAGED_JAVA_II_EVIDENCE.json"]:
        if required not in managed_java_e2e_0165:
            fail(f"0.16.5 Managed Java II E2E incomplete: {required}")
    for required in [
        "Managed Java II Java 8/16/17/21/25 production E2E",
        "run-managed-java-II-e2e.sh", "MANAGED_JAVA_II_EVIDENCE.json",
    ]:
        if required not in ci:
            fail(f"0.16.5 Managed Java II CI wiring incomplete: {required}")
    if "managed-java-II-0165.py" not in preflight or "managed-java-II-0165.py" not in ci:
        fail("0.16.5 Managed Java II gate is not wired into preflight/CI")
    if "managed-java-II-8-16-17-21-25" not in release_commands_0165:
        fail("0.16.5 release certification does not require Managed Java II")
    if "MANAGED_JAVA_II_EVIDENCE.json" not in release_builder_0165:
        fail("0.16.5 release bundle does not stage Managed Java II evidence")
    if "MANAGED_JAVA_II_EVIDENCE.json" not in release_bundle_0165:
        fail("0.16.5 release bundle required-artifact gate does not require Managed Java II evidence")
    if "Managed Java II gate: OK" not in managed_java_gate_0165:
        fail("0.16.5 mandatory Managed Java II gate is incomplete")


# 0.16.6 Java 16/17 Vanilla must be enforced by the real materializer/runtime
# and by actual-client release-line certification, not only by compatibility labels.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 6):
    vanilla_0166 = read("cli/cmd/neverlauncher/vanilla_runtime.go")
    vanilla_tests_0166 = read("cli/cmd/neverlauncher/vanilla_runtime_test.go")
    runtime_0166 = read("runtime/neverruntime/src/compatibility.rs")
    matrix_0166 = read("scripts/compatibility/matrix.py")
    matrix_tests_0166 = read("scripts/compatibility/test_matrix.py")
    targets_0166 = read("compatibility/targets.json")
    release_0166 = read("cli/cmd/neverlauncher/compatibility_release.go")
    release_tests_0166 = read("cli/cmd/neverlauncher/compatibility_release_test.go")
    for required in [
        "expectedJavaMajorForVanilla0166",
        "Mojang metadata не содержит javaVersion.majorVersion",
        "Mojang metadata Java mismatch",
        "javaMajorFromVersion(selectedID",
    ]:
        if required not in vanilla_0166:
            fail(f"0.16.6 Vanilla materializer exact-Java path incomplete: {required}")
    for required in [
        "expected_java_major_for_vanilla_0166",
        "resolved_java_major_version(&merged)?",
        "Mojang metadata Java mismatch",
        "0.16.6 requires exact Java",
    ]:
        if required not in runtime_0166:
            fail(f"0.16.6 NeverRuntime exact-Java path incomplete: {required}")
    for target in [
        "vanilla-1.17.1-linux-x64", "vanilla-1.18.2-linux-x64",
        "vanilla-1.19.4-linux-x64", "vanilla-1.20.1-linux-x64",
        "vanilla-1.20.2-linux-x64", "vanilla-1.20.4-linux-x64",
    ]:
        if target not in targets_0166:
            fail(f"0.16.6 Java 16/17 actual-client target missing: {target}")
    for required in [
        "JAVA16_17_VANILLA_0166", "Java 16/17 Vanilla 0.16.6",
        "java16_17_vanilla_required",
    ]:
        if required not in matrix_0166:
            fail(f"0.16.6 compatibility matrix Java 16/17 gate incomplete: {required}")
    if "vanilla-1.17.1-1.20.4-java16-17-exact" not in release_0166:
        fail("0.16.6 release certification does not bind exact Java 16/17 Vanilla policy")
    for required in [
        "TestJavaMajorFromVersionEnforcesJava16And17VanillaRange",
        "TestCompatibilityCertificationJava16_17Vanilla0166",
        "test_validate_rejects_missing_java16_17_release_line_0166",
    ]:
        corpus = vanilla_tests_0166 + release_tests_0166 + matrix_tests_0166
        if required not in corpus:
            fail(f"0.16.6 Java 16/17 Vanilla regression coverage missing: {required}")



# 0.16.7 Java 21 Vanilla must be enforced by materializer/runtime and by
# actual-client certification for the complete 1.20.5/1.20.6 -> 1.21.10 release line.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 7):
    vanilla_0167 = read("cli/cmd/neverlauncher/vanilla_runtime.go")
    vanilla_tests_0167 = read("cli/cmd/neverlauncher/vanilla_runtime_test.go")
    runtime_0167 = read("runtime/neverruntime/src/compatibility.rs")
    matrix_0167 = read("scripts/compatibility/matrix.py")
    matrix_tests_0167 = read("scripts/compatibility/test_matrix.py")
    targets_0167 = read("compatibility/targets.json")
    release_0167 = read("cli/cmd/neverlauncher/compatibility_release.go")
    release_tests_0167 = read("cli/cmd/neverlauncher/compatibility_release_test.go")
    for required in [
        "expectedJavaMajorForVanilla0167",
        "0.16.7 требует exact Java",
        "Mojang metadata Java mismatch",
    ]:
        if required not in vanilla_0167:
            fail(f"0.16.7 Vanilla materializer exact-Java 21 path incomplete: {required}")
    for required in [
        "expected_java_major_for_vanilla_0167",
        "0.16.7 requires exact Java",
        "resolved_java_major_version(&merged)?",
    ]:
        if required not in runtime_0167:
            fail(f"0.16.7 NeverRuntime exact-Java 21 path incomplete: {required}")
    for version in [
        "1.20.5", "1.20.6", "1.21", "1.21.1", "1.21.2", "1.21.3", "1.21.4",
        "1.21.5", "1.21.6", "1.21.7", "1.21.8", "1.21.9", "1.21.10",
    ]:
        target = f"vanilla-{version}-linux-x64"
        if target not in targets_0167:
            fail(f"0.16.7 Java 21 actual-client target missing: {target}")
    for required in [
        "JAVA21_VANILLA_0167", "Java 21 Vanilla 0.16.7", "java21_vanilla_required",
    ]:
        if required not in matrix_0167:
            fail(f"0.16.7 compatibility matrix Java 21 gate incomplete: {required}")
    if "vanilla-1.20.5-1.21.10-java21-exact" not in release_0167:
        fail("0.16.7 release certification does not bind exact Java 21 Vanilla policy")
    for required in [
        "TestJavaMajorFromVersionEnforcesJava21VanillaRange",
        "TestInstallVanilla0167RejectsWrongJavaBeforeArtifactDownload",
        "TestCompatibilityCertificationJava21Vanilla0167",
        "test_validate_rejects_missing_java21_release_line_0167",
    ]:
        corpus = vanilla_tests_0167 + release_tests_0167 + matrix_tests_0167
        if required not in corpus:
            fail(f"0.16.7 Java 21 Vanilla regression coverage missing: {required}")


# 0.16.8 Java 25 Vanilla must be an executable exact-Java path for the released
# 26.1 hotfix line and the 26.3 game drop, backed by actual-client certification.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 8):
    vanilla_0168 = read("cli/cmd/neverlauncher/vanilla_runtime.go")
    vanilla_tests_0168 = read("cli/cmd/neverlauncher/vanilla_runtime_test.go")
    runtime_0168 = read("runtime/neverruntime/src/compatibility.rs")
    matrix_0168 = read("scripts/compatibility/matrix.py")
    matrix_tests_0168 = read("scripts/compatibility/test_matrix.py")
    targets_0168 = read("compatibility/targets.json")
    release_0168 = read("cli/cmd/neverlauncher/compatibility_release.go")
    release_tests_0168 = read("cli/cmd/neverlauncher/compatibility_release_test.go")
    for required in [
        "expectedJavaMajorForVanilla0168",
        "0.16.8 требует exact Java",
        "Mojang metadata Java mismatch",
    ]:
        if required not in vanilla_0168:
            fail(f"0.16.8 Vanilla materializer exact-Java 25 path incomplete: {required}")
    for required in [
        "expected_java_major_for_vanilla_0168",
        "0.16.8 requires exact Java",
        "resolved_java_major_version(&merged)?",
    ]:
        if required not in runtime_0168:
            fail(f"0.16.8 NeverRuntime exact-Java 25 path incomplete: {required}")
    for version in ["26.1", "26.1.1", "26.1.2", "26.3"]:
        target = f"vanilla-{version}-linux-x64"
        if target not in targets_0168:
            fail(f"0.16.8 Java 25 actual-client target missing: {target}")
    for required in [
        "JAVA25_VANILLA_0168", "Java 25 Vanilla 0.16.8", "java25_vanilla_required",
    ]:
        if required not in matrix_0168:
            fail(f"0.16.8 compatibility matrix Java 25 gate incomplete: {required}")
    if "vanilla-26.1.x-26.3-java25-exact" not in release_0168:
        fail("0.16.8 release certification does not bind exact Java 25 Vanilla policy")
    for required in [
        "TestJavaMajorFromVersionEnforcesJava25VanillaRange",
        "TestInstallVanilla0168RejectsWrongJavaBeforeArtifactDownload",
        "TestCompatibilityCertificationJava25Vanilla0168",
        "test_validate_rejects_missing_java25_release_line_0168",
    ]:
        corpus = vanilla_tests_0168 + release_tests_0168 + matrix_tests_0168
        if required not in corpus:
            fail(f"0.16.8 Java 25 Vanilla regression coverage missing: {required}")


# 0.16.9 Cross-platform Vanilla must execute on matching native hosts and keep
# OS/architecture native libraries isolated instead of merely expanding labels.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 9):
    vanilla_0169 = read("cli/cmd/neverlauncher/vanilla_runtime.go")
    vanilla_tests_0169 = read("cli/cmd/neverlauncher/vanilla_runtime_test.go")
    runtime_compat_0169 = read("runtime/neverruntime/src/compatibility.rs")
    runtime_core_0169 = read("runtime/neverruntime/src/lib.rs")
    matrix_0169 = read("scripts/compatibility/matrix.py")
    matrix_tests_0169 = read("scripts/compatibility/test_matrix.py")
    targets_0169 = read("compatibility/targets.json")
    workflow_0169 = read(".github/workflows/compatibility.yml")
    compat_case_0169 = read("e2e/scripts/run-compatibility-case.sh")
    vanilla_case_0169 = read("e2e/scripts/run-vanilla-certification-case.sh")
    release_0169 = read("cli/cmd/neverlauncher/compatibility_release.go")
    release_tests_0169 = read("cli/cmd/neverlauncher/compatibility_release_test.go")
    for target in [
        "vanilla-26.3-linux-x64", "vanilla-26.3-linux-arm64",
        "vanilla-26.3-windows-x64", "vanilla-26.3-windows-arm64",
        "vanilla-26.3-macos-x64", "vanilla-26.3-macos-arm64",
    ]:
        if target not in targets_0169:
            fail(f"0.16.9 cross-platform Vanilla target missing: {target}")
    for required in [
        "CROSS_PLATFORM_VANILLA_0169", "ubuntu-24.04-arm", "windows-11-arm",
        "macos-15-intel", '"macos-15"', "javaDistribution",
    ]:
        if required not in matrix_0169:
            fail(f"0.16.9 compatibility host plan incomplete: {required}")
    for required in ["runs-on: ${{ matrix.runner }}", "matrix.javaDistribution", "platform-runtime.json"]:
        if required not in workflow_0169:
            fail(f"0.16.9 compatibility workflow is not host-bound: {required}")
    for required in ["platform-runtime.json", "platformMatched", "runner mismatch"]:
        if required not in compat_case_0169:
            fail(f"0.16.9 platform evidence incomplete: {required}")
    for required in ['--target "$TARGET_OS/$TARGET_ARCH"', "xvfb-run", '[[ "$TARGET_OS" == "linux" ]]']:
        if required not in vanilla_case_0169:
            fail(f"0.16.9 Vanilla native-host certification incomplete: {required}")
    for required in ["target.OS, target.Arch", "libraryArtifactAppliesToTarget", "vanillaOSRuleMatches"]:
        if required not in vanilla_0169:
            fail(f"0.16.9 Vanilla materializer architecture isolation incomplete: {required}")
    for required in ["library_artifact_matches_environment", "os_name_matches_environment"]:
        if required not in runtime_compat_0169:
            fail(f"0.16.9 NeverRuntime native filtering incomplete: {required}")
    if "base.join(platform).join(arch)" not in runtime_core_0169:
        fail("0.16.9 NeverRuntime does not isolate natives by OS/architecture")
    if "cross-platform-vanilla-windows-linux-macos-x64-arm64" not in release_0169:
        fail("0.16.9 release certification does not bind cross-platform Vanilla policy")
    for required in [
        "TestVanillaRuleAndNativeClassifierMatchTargetArchitecture",
        "cross_platform_native_classifier_is_architecture_bound",
        "test_validate_rejects_missing_cross_platform_0169",
        "TestCompatibilityCertificationCrossPlatformVanilla0169",
    ]:
        corpus = vanilla_tests_0169 + runtime_compat_0169 + matrix_tests_0169 + release_tests_0169
        if required not in corpus:
            fail(f"0.16.9 cross-platform regression coverage missing: {required}")


# 0.16.10 Actual Client E2E II must prove that representative real Mojang
# clients join verified Mojang servers for the exact same Minecraft version.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 10):
    vanilla_01610 = read("cli/cmd/neverlauncher/vanilla_runtime.go")
    vanilla_tests_01610 = read("cli/cmd/neverlauncher/vanilla_runtime_test.go")
    runtime_01610 = read("runtime/neverruntime/src/lib.rs") + read("runtime/neverruntime/src/bin/neverruntime.rs")
    matching_case_01610 = read("e2e/scripts/run-vanilla-matching-e2e.sh")
    compat_case_01610 = read("e2e/scripts/run-compatibility-case.sh")
    matrix_01610 = read("scripts/compatibility/matrix.py")
    matrix_tests_01610 = read("scripts/compatibility/test_matrix.py")
    targets_01610 = read("compatibility/targets.json")
    workflow_01610 = read(".github/workflows/compatibility.yml")
    release_01610 = read("cli/cmd/neverlauncher/compatibility_release.go")
    release_tests_01610 = read("cli/cmd/neverlauncher/compatibility_release_test.go")
    for required in ["handleRuntimeVanillaServer", "installVanillaServer", 'metadata.Downloads["server"]', "installed-and-verified"]:
        if required not in vanilla_01610:
            fail(f"0.16.10 verified Mojang server materializer incomplete: {required}")
    for target in [
        "vanilla-1.7.10-linux-x64", "vanilla-1.17.1-linux-x64", "vanilla-1.20.4-linux-x64",
        "vanilla-1.21.10-linux-x64", "vanilla-26.3-linux-x64",
    ]:
        if target not in targets_01610:
            fail(f"0.16.10 matching-server target missing: {target}")
    if targets_01610.count('"matchingServer": true') < 5:
        fail("0.16.10 targets do not bind five representative matching-server pairs")
    for required in ["--server", "--server-port", "matching_server", "matching_server_port"]:
        if required not in runtime_01610:
            fail(f"0.16.10 NeverRuntime direct matching-server launch incomplete: {required}")
    for required in [
        "runtime vanilla-server", "server.jar", "online-mode=false", "clientJoinedServer", "serverVersionMatched",
        "joined the game|logged in with entity id", "vanilla-server-install.json", "matching-server.json",
    ]:
        if required not in matching_case_01610:
            fail(f"0.16.10 real client/matching server E2E incomplete: {required}")
    for required in ["NEVERLAUNCHER_COMPAT_MATCHING_SERVER", "run-vanilla-matching-e2e.sh", "matchingServer"]:
        if required not in compat_case_01610:
            fail(f"0.16.10 compatibility dispatcher incomplete: {required}")
    for required in ["ACTUAL_CLIENT_E2E_II_01610", "Actual Client E2E II 0.16.10", "clientJoinedServer", "serverVersionMatched"]:
        if required not in matrix_01610:
            fail(f"0.16.10 matrix matching-server gate incomplete: {required}")
    for required in ["matrix.matchingServer", "vanilla-server-install.json", "matching-server.json", "matching-server.log"]:
        if required not in workflow_01610:
            fail(f"0.16.10 workflow matching-server evidence incomplete: {required}")
    if "actual-client-e2e-II-real-clients-matching-mojang-servers" not in release_01610:
        fail("0.16.10 release certification does not bind matching-server policy")
    for required in [
        "TestInstallVanillaServerMaterializesVerifiedMatchingServer",
        "test_validate_rejects_missing_matching_server_target_01610",
        "test_aggregate_rejects_matching_server_without_real_join_01610",
        "TestCompatibilityCertificationActualClientE2EII01610",
    ]:
        corpus = vanilla_tests_01610 + matrix_tests_01610 + release_tests_01610
        if required not in corpus:
            fail(f"0.16.10 matching-server regression coverage missing: {required}")


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


# 0.15.8 Release Verification v2 must bind release signatures to a root-signed
# trust policy, enforce key lifecycle states, and persist anti-rollback state.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 8):
    rv2_0158 = read("cli/cmd/neverlauncher/release_verification_v2.go")
    keyring_0158 = read("cli/cmd/neverlauncher/security_keyring.go")
    release_0158 = read("cli/cmd/neverlauncher/release_commands.go")
    build_release_0158 = read("scripts/release/build-release.sh")
    gate_0158 = read("scripts/smoke/offline/release-verification-v2-trust-lifecycle-0158.py")
    tests_0158 = read("cli/cmd/neverlauncher/release_verification_v2_test.go")
    for required in [
        "RELEASE_TRUST_POLICY.json", "neverlauncher.release.v2", "verifyReleaseTrustPolicy0158",
        "signReleaseBundleV20158", "verifyReleaseSignatureV20158", "verify-only", "revoked",
        "trust epoch rollback", "release rollback blocked", "NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE",
    ]:
        if required not in rv2_0158:
            fail(f"0.15.8 Release Verification v2 incomplete: {required}")
    for required in ["TrustEpoch", "reg.TrustEpoch++", 'Status: "active"']:
        if required not in keyring_0158:
            fail(f"0.15.8 trust/key lifecycle registry incomplete: {required}")
    for required in ["verifyReleaseBundleWithTrustState", "release-verification-v2-trust-lifecycle-anti-rollback"]:
        if required not in release_0158:
            fail(f"0.15.8 release integration incomplete: {required}")
    for required in ["NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE", "NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE", "NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE"]:
        if required not in build_release_0158:
            fail(f"0.15.8 production release trust input missing: {required}")
    for required in ["TestReleaseVerificationV2TrustLifecycleAndAntiRollback", "TestReleaseTrustPolicyRejectsTampering"]:
        if required not in tests_0158:
            fail(f"0.15.8 verification regression tests missing: {required}")
    if "Release Verification v2 + trust/key lifecycle gate: OK" not in gate_0158:
        fail("0.15.8 mandatory verification gate incomplete")
    if "release-verification-v2-trust-lifecycle-0158.py" not in preflight or "release-verification-v2-trust-lifecycle-0158.py" not in ci:
        fail("0.15.8 verification gate is not wired into preflight/CI")


# 0.15.9 Public Production Delivery Matrix must expose the complete six-target
# public inventory and the post-publish E2E must download the real public bytes
# before repeating Release Verification v2 with external trust material.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 9):
    public_delivery_0159 = read("cli/cmd/neverlauncher/public_delivery_matrix.go")
    delivery_cmd_0159 = read("cli/cmd/neverlauncher/delivery_manifest.go")
    release_0159 = read("cli/cmd/neverlauncher/release_commands.go")
    build_release_0159 = read("scripts/release/build-release.sh")
    workflow_0159 = read(".github/workflows/public-production-delivery.yml")
    gate_0159 = read("scripts/smoke/offline/public-production-delivery-matrix-e2e-0159.py")
    tests_0159 = read("cli/cmd/neverlauncher/public_delivery_matrix_test.go")
    for required in [
        "PUBLIC_PRODUCTION_DELIVERY_MATRIX.json", "buildPublicProductionDeliveryMatrix0159",
        "validatePublicProductionDeliveryMatrix0159", "runPublicProductionDeliveryE2E0159",
        "downloadPublicAsset0159", "verifyReleaseBundleWithTrust", "github.com",
        "release-assets.githubusercontent.com", "public delivery base URL must use HTTPS",
    ]:
        if required not in public_delivery_0159:
            fail(f"0.15.9 public delivery implementation incomplete: {required}")
    for required in ['case "public-matrix":', 'case "verify-public-matrix":', 'case "public-e2e":']:
        if required not in delivery_cmd_0159:
            fail(f"0.15.9 public delivery CLI incomplete: {required}")
    for required in ["publicProductionDeliveryRequired0159", "public-production-delivery-matrix-six-target-e2e"]:
        if required not in release_0159:
            fail(f"0.15.9 release integration incomplete: {required}")
    for required in ["NEVERLAUNCHER_PUBLIC_RELEASE_BASE_URL", "neverruntime-windows-x64.exe", "neverruntime-windows-arm64.exe"]:
        if required not in build_release_0159:
            fail(f"0.15.9 aggregate release staging incomplete: {required}")
    for required in ["types: [published]", "delivery public-e2e", "PUBLIC_DELIVERY_E2E_REPORT.json", "NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE", "NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE"]:
        if required not in workflow_0159:
            fail(f"0.15.9 post-publish workflow incomplete: {required}")
    for required in ["TestPublicProductionDeliveryMatrix0159CoversSixTargets", "TestPublicProductionDeliveryMatrix0159RejectsMissingRuntime", "TestFetchPublicMatrix0159LoopbackHTTP"]:
        if required not in tests_0159:
            fail(f"0.15.9 public delivery regression tests missing: {required}")
    if "Public Production Delivery Matrix + E2E gate: OK" not in gate_0159:
        fail("0.15.9 mandatory public delivery gate incomplete")
    if "public-production-delivery-matrix-e2e-0159.py" not in preflight or "public-production-delivery-matrix-e2e-0159.py" not in ci:
        fail("0.15.9 public delivery gate is not wired into preflight/CI")


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

# 0.15.10 Migration + stabilization seals local-state migration and recovery:
# serialized trust-state verification, state 2.0 -> 2.1, same-version manifest
# binding, canonical component state and cleanup of terminal updater payloads.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 10):
    stabilization_01510 = read("cli/cmd/neverlauncher/migration_stabilization_01510.go")
    stabilization_tests_01510 = read("cli/cmd/neverlauncher/migration_stabilization_01510_test.go")
    rv2_01510 = read("cli/cmd/neverlauncher/release_verification_v2.go")
    update_01510 = read("cli/cmd/neverlauncher/transactional_updater.go") + read("cli/cmd/neverlauncher/component_update.go")
    release_01510 = read("cli/cmd/neverlauncher/release_commands.go")
    gate_01510 = read("scripts/smoke/offline/migration-stabilization-01510.py")
    for required in [
        "withReleaseTrustStateLock01510", "releaseTrustStateSchema01510",
        "migrateComponentUpdateState01510", "stabilizeTerminalPayloads01510",
        "same-version release manifest mismatch", "migration-stabilization-0.15.10",
    ]:
        if required not in stabilization_01510 and required not in rv2_01510:
            fail(f"0.15.10 migration stabilization implementation incomplete: {required}")
    for required in [
        "HighestReleaseManifestSHA256", "StateRevision", "releaseTrustStateSchema01510",
        "precheckTrustState0158",
    ]:
        if required not in rv2_01510:
            fail(f"0.15.10 trust-state migration incomplete: {required}")
    for required in ["removeUpdaterTerminalPayload01510", "removeSafeComponentTreePayload01510", "migrateComponentUpdateState01510"]:
        if required not in update_01510:
            fail(f"0.15.10 updater stabilization integration incomplete: {required}")
    for required in ["migrationStabilizationRequired01510", "runMigrationStabilizationSelfTest01510"]:
        if required not in release_01510:
            fail(f"0.15.10 release integration incomplete: {required}")
    for required in [
        "TestMigrationStabilization01510MigratesLegacyComponentState",
        "TestReleaseTrustState01510MigratesAndBindsSameVersionManifest",
        "TestReleaseTrustStateLock01510RejectsConcurrentVerifier",
        "TestTransactionalUpdater01510CleansRollbackPayload",
    ]:
        if required not in stabilization_tests_01510:
            fail(f"0.15.10 stabilization regression tests missing: {required}")
    if "Migration + stabilization 0.15.10 gate: OK" not in gate_01510:
        fail("0.15.10 mandatory migration stabilization gate incomplete")
    if "migration-stabilization-01510.py" not in preflight or "migration-stabilization-01510.py" not in ci:
        fail("0.15.10 stabilization gate is not wired into preflight/CI")


# 0.15.11 Production Release Candidate seals the complete release cohort before
# Ed25519 signing. It must be built from one exact Git commit with all public
# certification inputs present and production-only Windows/macOS evidence.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 15, 11):
    rc_01511 = read("cli/cmd/neverlauncher/production_release_candidate_01511.go")
    rc_tests_01511 = read("cli/cmd/neverlauncher/production_release_candidate_01511_test.go")
    release_01511 = read("cli/cmd/neverlauncher/release_commands.go")
    build_01511 = read("scripts/release/build-release.sh")
    artifact_layout_01511 = read("scripts/release/resolve-artifact-payload.sh")
    bundle_gate_01511 = read("scripts/smoke/release-required/release-bundle.sh")
    gate_01511 = read("scripts/smoke/offline/production-release-candidate-01511.py")
    for required in [
        "PRODUCTION_RELEASE_CANDIDATE.json", "production-release-candidate",
        "exact-source-commit-cohort", "productionReleaseCandidateCohortDigest01511",
        "verifyProductionReleaseCandidatePrerequisites01511", "PROVENANCE.json sourceCommit mismatch",
        "verifyWindowsSigningEvidence0152", "verifyMacOSNotarizationEvidence0154",
        "verifyManagedJREDistribution0155", "verifyPublicProductionDeliveryMatrix0159",
    ]:
        if required not in rc_01511:
            fail(f"0.15.11 Production Release Candidate implementation incomplete: {required}")
    for required in [
        'case "candidate-verify":', "writeProductionReleaseCandidate01511",
        "production-release-candidate-exact-source-cohort", "productionReleaseCandidateRequired01511",
    ]:
        if required not in release_01511:
            fail(f"0.15.11 release integration incomplete: {required}")
    for required in [
        "PRODUCTION_RC_REQUIRED", "Production Release Candidate требует полный Compatibility + Device Trust + Guard CI certification cohort",
        'git -C "${ROOT_DIR}" diff --quiet HEAD --', "release candidate-verify", "PRODUCTION_RELEASE_CANDIDATE.json",
        "resolve-artifact-payload.sh", "windows_delivery_source", "linux_delivery_source", "macos_delivery_source",
    ]:
        if required not in build_01511:
            fail(f"0.15.11 production build fail-closed integration incomplete: {required}")
    for required in [
        "release-${VERSION}", "неоднозначный mixed artifact layout", "ожидался ровно один release-${VERSION}",
        "artifact payload относится не к ${VERSION}", "nested artifact layout содержит неожиданные top-level files/symlinks",
        "release-${VERSION} payload содержит symlink", "flat artifact payload содержит symlink",
    ]:
        if required not in artifact_layout_01511:
            fail(f"0.15.11 exact artifact layout resolver incomplete: {required}")
    if "PRODUCTION_RELEASE_CANDIDATE.json" not in bundle_gate_01511:
        fail("0.15.11 release-bundle gate does not require candidate certification")
    for required in [
        "TestProductionReleaseCandidate01511BindsExactCohort",
        "TestProductionReleaseCandidate01511RejectsInjectedFile",
        "TestSLSAProvenance01511CarriesExactSourceCommit",
        "TestNormalizeSourceCommit01511RejectsPlaceholders",
    ]:
        if required not in rc_tests_01511:
            fail(f"0.15.11 production candidate regression tests missing: {required}")
    if "Production release candidate 0.15.11 gate: OK" not in gate_01511:
        fail("0.15.11 mandatory Production Release Candidate gate incomplete")
    if "production-release-candidate-01511.py" not in preflight or "production-release-candidate-01511.py" not in ci:
        fail("0.15.11 Production Release Candidate gate is not wired into preflight/CI")


# 0.16.0 Production Delivery Release promotes the exact-commit candidate into
# a stable six-target GA boundary with an immutable versioned public origin.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 16, 0):
    pdr_0160 = read("cli/cmd/neverlauncher/production_delivery_release_0160.go")
    pdr_tests_0160 = read("cli/cmd/neverlauncher/production_delivery_release_0160_test.go")
    release_0160 = read("cli/cmd/neverlauncher/release_commands.go")
    build_0160 = read("scripts/release/build-release.sh")
    bundle_0160 = read("scripts/smoke/release-required/release-bundle.sh")
    public_0160 = read("cli/cmd/neverlauncher/public_delivery_matrix.go")
    public_workflow_0160 = read(".github/workflows/public-production-delivery.yml")
    gate_0160 = read("scripts/smoke/offline/production-delivery-release-0160.py")
    for required in [
        "PRODUCTION_DELIVERY_RELEASE.json", "production-delivery-release",
        "stable-versioned-public-origin", "productionDeliveryReleaseBoundaryDigest0160",
        "versionedPublicBaseURL0160", "verifyProductionDeliveryRelease0160",
        "productionReleaseCandidateFile01511", "publicProductionDeliveryMatrixFile0159",
        "PostPublishE2E",
    ]:
        if required not in pdr_0160:
            fail(f"0.16.0 Production Delivery Release implementation incomplete: {required}")
    for required in [
        'case "production-verify":', "writeProductionDeliveryRelease0160",
        "production-delivery-release-stable-six-target-ga",
        "productionDeliveryReleaseSha256", 'manifest["channel"] = productionDeliveryReleaseChannel0160',
    ]:
        if required not in release_0160:
            fail(f"0.16.0 release integration incomplete: {required}")
    for required in [
        "PRODUCTION_DELIVERY_RELEASE_REQUIRED", "PRODUCTION_DELIVERY_RELEASE.json",
        "release production-verify", "immutable version segment",
    ]:
        if required not in build_0160:
            fail(f"0.16.0 production build integration incomplete: {required}")
    if "PRODUCTION_DELIVERY_RELEASE.json" not in bundle_0160:
        fail("0.16.0 release-bundle gate does not require Production Delivery Release certification")
    for required in ["production-delivery-release", "ProductionDeliveryReleaseVerified", "verifyProductionDeliveryRelease0160"]:
        if required not in public_0160:
            fail(f"0.16.0 public E2E integration incomplete: {required}")
    for required in ["PRODUCTION_DELIVERY_RELEASE.json", "release production-verify", "productionDeliveryReleaseVerified"]:
        if required not in public_workflow_0160:
            fail(f"0.16.0 post-publish GA verification incomplete: {required}")
    for required in [
        "TestProductionDeliveryRelease0160BindsCandidateAndAnchors",
        "TestProductionDeliveryRelease0160RejectsUnversionedPublicOrigin",
        "TestProductionDeliveryRelease0160RejectsPrereleaseSemver",
    ]:
        if required not in pdr_tests_0160:
            fail(f"0.16.0 Production Delivery Release regression tests missing: {required}")
    if "Production Delivery Release 0.16.0 gate: OK" not in gate_0160:
        fail("0.16.0 mandatory Production Delivery Release gate incomplete")
    if "production-delivery-release-0160.py" not in preflight or "production-delivery-release-0160.py" not in ci:
        fail("0.16.0 Production Delivery Release gate is not wired into preflight/CI")

# 0.17.0 Minecraft Compatibility II GA binds every compatibility PASS to a
# concrete JRE binary identity. Maintenance revisions keep the complete v1
# Legacy grid, the v2 Java 16/17 grid, and v3 closes the 1.21.11/26.2
# Java 21/25 release gaps with independent materializer/runtime enforcement.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 0):
    ga_matrix_0170 = read("scripts/compatibility/matrix.py")
    ga_jre_0170 = read("scripts/compatibility/certify-jre.py")
    ga_case_0170 = read("e2e/scripts/run-compatibility-case.sh")
    ga_release_0170 = read("cli/cmd/neverlauncher/compatibility_release.go")
    ga_vanilla_runtime_0170 = read("cli/cmd/neverlauncher/vanilla_runtime.go")
    ga_neverruntime_0170 = read("runtime/neverruntime/src/compatibility.rs")
    ga_targets_0170 = json.loads(read("compatibility/targets.json"))["targets"]
    ga_tests_0170 = read("scripts/compatibility/test_matrix.py") + read("scripts/compatibility/test_certify_jre.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go")
    ga_gate_0170 = read("scripts/smoke/offline/minecraft-compatibility-II-ga-0170.py")
    for required in ["LEGACY_VANILLA_0170V1", "JAVA16_17_VANILLA_0170V2", "JAVA21_25_VANILLA_0170V3", "COMPATIBILITY_II_GA_MIN_UNIQUE_VANILLA", "COMPATIBILITY_II_GA_MIN_REQUIRED_VANILLA_TARGETS", "build_ga_jre_base", "jreCertified", '"jreBase"']:
        if required not in ga_matrix_0170:
            fail(f"0.17.0 GA compatibility matrix incomplete: {required}")
    for required in ["executableSha256", "java.runtime.version", "java.vendor", "java.home", "detectedOS", "detectedArch", "certified"]:
        if required not in ga_jre_0170:
            fail(f"0.17.0 JRE attestation incomplete: {required}")
    for required in ["certify-jre.py", '"jreCertified"', '"jreExecutableSha256"']:
        if required not in ga_case_0170:
            fail(f"0.17.0 compatibility target JRE binding incomplete: {required}")
    for required in ["compatibilityIIGa0170Required", "compatibilityLegacyVanilla0170v1Required", "compatibilityJava16_17Vanilla0170v2Required", "compatibilityJava21_25Vanilla0170v3Required", "JREBuilds", "JREExecutableSHA256", "legacy-vanilla-0.17.0v1-complete-53-release-grid-java8", "java16-17-vanilla-0.17.0v2-complete-9-release-grid-exact", "java21-25-vanilla-0.17.0v3-complete-2-release-grid-exact", "minecraft-compatibility-II-GA-wide-certified-vanilla-jre-base"]:
        if required not in ga_release_0170:
            fail(f"0.17.0 GA release certification incomplete: {required}")
    for required in ["test_ga_matrix_contains_certified_jre_base", "test_certify_binds_binary_hash_and_runtime_identity", "test_validate_rejects_missing_complete_legacy_grid_0170v1", "test_validate_rejects_missing_java16_17_grid_0170v2", "test_validate_rejects_missing_java21_25_grid_0170v3", "test_validate_rejects_wrong_java21_25_grid_0170v3", "TestCompatibilityCertificationGA0170BindsJREBase", "TestCompatibilityCertificationGA0170v1RejectsMissingLegacyRelease", "TestCompatibilityCertificationGA0170v2RequiresCompleteJava16_17Grid", "TestCompatibilityCertificationGA0170v2RejectsMissingJavaTransitionRelease", "TestCompatibilityCertificationGA0170v3RequiresJava21And25Grid", "TestCompatibilityCertificationGA0170v3RejectsMissingRelease", "TestCompatibilityCertificationGA0170v3RejectsWrongJavaMajor"]:
        if required not in ga_tests_0170:
            fail(f"0.17.0 GA regression test missing: {required}")
    if "Minecraft Compatibility II GA 0.17.0 gate: OK" not in ga_gate_0170:
        fail("0.17.0 mandatory Minecraft Compatibility II GA gate incomplete")
    if "java16_17_0170v2" not in ga_gate_0170:
        fail("0.17.0v2 complete Java 16/17 Vanilla gate is missing")
    if "0.17.0v3 Java 21/25 grid" not in ga_gate_0170:
        fail("0.17.0v3 complete Java 21/25 Vanilla gate is missing")
    for required in ["java21_25Vanilla0170v3Releases", "expectedJavaMajorForVanilla0170v3", "0.17.0v3 требует exact Java"]:
        if required not in ga_vanilla_runtime_0170:
            fail(f"0.17.0v3 Vanilla materializer exact-Java path incomplete: {required}")
    for required in ["expected_java_major_for_vanilla_0170v3", "0.17.0v3 requires exact Java"]:
        if required not in ga_neverruntime_0170:
            fail(f"0.17.0v3 NeverRuntime exact-Java path incomplete: {required}")
    v3_targets = {
        row["minecraft"]: row for row in ga_targets_0170
        if row.get("required") and row.get("loader") == "vanilla" and row.get("minecraft") in {"1.21.11", "26.2"}
        and row.get("os") == "linux" and row.get("arch") == "x86_64"
    }
    for minecraft, java_major in {"1.21.11": 21, "26.2": 25}.items():
        row = v3_targets.get(minecraft)
        if row is None or row.get("javaMajor") != java_major or row.get("scope") != "client":
            fail(f"0.17.0v3 required target invalid or missing: {minecraft} / Java {java_major}")
    if "minecraft-compatibility-II-ga-0170.py" not in preflight or "minecraft-compatibility-II-ga-0170.py" not in ci:
        fail("0.17.0 Minecraft Compatibility II GA gate is not wired into preflight/CI")

# 0.17.1 Fabric Compatibility II requires the full stable 1.14+ line to use
# executable materialization and actual-client evidence, not declaration-only targets.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 1):
    fabric_matrix_0171 = read("scripts/compatibility/matrix.py")
    fabric_case_0171 = read("e2e/scripts/run-fabric-certification-case.sh")
    compat_case_0171 = read("e2e/scripts/run-compatibility-case.sh")
    fabric_release_0171 = read("cli/cmd/neverlauncher/compatibility_release.go")
    fabric_targets_0171 = json.loads(read("compatibility/targets.json"))["targets"]
    fabric_tests_0171 = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go")
    fabric_gate_0171 = read("scripts/smoke/offline/fabric-compatibility-II-0171.py")
    compat_workflow_0171 = read(".github/workflows/compatibility.yml")
    for required in ["FABRIC_COMPATIBILITY_II_0171", "fabric_compatibility_ii_0171_required", "Fabric Compatibility II 0.17.1", 'target["loader"] in {"fabric", "quilt", "forge", "neoforge"}', 'install_file = f"{target[\'loader\']}-install.json"', 'certification_file = f"{target[\'loader\']}-certification.json"']:
        if required not in fabric_matrix_0171:
            fail(f"0.17.1 Fabric compatibility matrix incomplete: {required}")
    for required in ["runtime fabric-package", "client verify", "fabric-install.json", "fabric-certification.json", "certify-vanilla", "mutable loader selector leaked", "actual-mojang-client"]:
        if required not in fabric_case_0171:
            fail(f"0.17.1 Fabric actual-client execution incomplete: {required}")
    for required in ["run-fabric-certification-case.sh", 'loader in ("fabric", "quilt", "forge", "neoforge")', 'install_name = f"{loader}-install.json"', 'probe_name = f"{loader}-certification.json"', "resolvedLoaderVersion"]:
        if required not in compat_case_0171:
            fail(f"0.17.1 Fabric compatibility routing incomplete: {required}")
    for required in ["fabricCompatibilityII0171", "compatibilityFabricII0171Required", "FabricVersions", "fabric-compatibility-II-0.17.1-stable-1.14-through-current-actual-client"]:
        if required not in fabric_release_0171:
            fail(f"0.17.1 Fabric release certification incomplete: {required}")
    fabric_rows = [row for row in fabric_targets_0171 if row.get("required") and row.get("loader") == "fabric" and row.get("os") == "linux" and row.get("arch") == "x86_64"]
    if len(fabric_rows) != 48 or len({row.get("minecraft") for row in fabric_rows}) != 48:
        fail("0.17.1 Fabric target grid must contain exactly 48 unique stable releases")
    if {8, 16, 17, 21, 25} - {row.get("javaMajor") for row in fabric_rows}:
        fail("0.17.1 Fabric target grid does not cover Java 8/16/17/21/25")
    for required in [
        "test_validate_accepts_fabric_compatibility_ii_0171_grid",
        "test_validate_rejects_missing_fabric_release_0171",
        "test_validate_rejects_wrong_fabric_java_0171",
        "TestCompatibilityCertificationFabricII0171",
        "TestCompatibilityCertificationFabricII0171RejectsMutableResolvedLoader",
    ]:
        if required not in fabric_tests_0171:
            fail(f"0.17.1 Fabric regression test missing: {required}")
    for required in ["fabric-install.json", "fabric-certification.json"]:
        if required not in compat_workflow_0171:
            fail(f"0.17.1 Fabric raw CI evidence upload missing: {required}")
    if "Fabric Compatibility II 0.17.1 gate: OK" not in fabric_gate_0171:
        fail("0.17.1 mandatory Fabric Compatibility II gate incomplete")
    if "fabric-compatibility-II-0171.py" not in preflight or "fabric-compatibility-II-0171.py" not in ci:
        fail("0.17.1 Fabric Compatibility II gate is not wired into preflight/CI")

# 0.17.2 Quilt Compatibility II extends executable client certification to the
# broad stable Quilt line and requires concrete stable Quilt Loader resolution.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 2):
    quilt_matrix_0172 = read("scripts/compatibility/matrix.py")
    quilt_runtime_0172 = read("cli/cmd/neverlauncher/loader_runtime.go")
    quilt_case_0172 = read("e2e/scripts/run-quilt-certification-case.sh")
    compat_case_0172 = read("e2e/scripts/run-compatibility-case.sh")
    quilt_release_0172 = read("cli/cmd/neverlauncher/compatibility_release.go")
    quilt_targets_0172 = json.loads(read("compatibility/targets.json"))["targets"]
    quilt_tests_0172 = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/loader_runtime_test.go")
    quilt_gate_0172 = read("scripts/smoke/offline/quilt-compatibility-II-0172.py")
    compat_workflow_0172 = read(".github/workflows/compatibility.yml")
    for required in ["QUILT_COMPATIBILITY_II_0172", "quilt_compatibility_ii_0172_required", "Quilt Compatibility II 0.17.2"]:
        if required not in quilt_matrix_0172:
            fail(f"0.17.2 Quilt compatibility matrix incomplete: {required}")
    for required in ["isStableQuiltLoaderVersion", "Meta API не вернул стабильную %s loader version", "materializeLoaderLibraries", "installed-and-verified"]:
        if required not in quilt_runtime_0172:
            fail(f"0.17.2 Quilt runtime/materializer incomplete: {required}")
    for required in ["runtime quilt-package", "client verify", "quilt-install.json", "quilt-certification.json", "certify-vanilla", "mutable loader selector leaked", "actual-mojang-client"]:
        if required not in quilt_case_0172:
            fail(f"0.17.2 Quilt actual-client execution incomplete: {required}")
    for required in ["run-quilt-certification-case.sh", 'loader in ("fabric", "quilt", "forge", "neoforge")', 'install_name = f"{loader}-install.json"', 'probe_name = f"{loader}-certification.json"', "resolvedLoaderVersion"]:
        if required not in compat_case_0172:
            fail(f"0.17.2 Quilt compatibility routing incomplete: {required}")
    for required in ["quiltCompatibilityII0172", "compatibilityQuiltII0172Required", "QuiltVersions", "quilt-compatibility-II-0.17.2-stable-1.14-through-current-actual-client"]:
        if required not in quilt_release_0172:
            fail(f"0.17.2 Quilt release certification incomplete: {required}")
    quilt_rows = [row for row in quilt_targets_0172 if row.get("required") and row.get("loader") == "quilt" and row.get("os") == "linux" and row.get("arch") == "x86_64"]
    if len(quilt_rows) != 48 or len({row.get("minecraft") for row in quilt_rows}) != 48:
        fail("0.17.2 Quilt target grid must contain exactly 48 unique stable releases")
    if {8, 16, 17, 21, 25} - {row.get("javaMajor") for row in quilt_rows}:
        fail("0.17.2 Quilt target grid does not cover Java 8/16/17/21/25")
    for required in [
        "test_validate_accepts_quilt_compatibility_ii_0172_grid",
        "test_validate_rejects_missing_quilt_release_0172",
        "test_validate_rejects_wrong_quilt_java_0172",
        "TestCompatibilityCertificationQuiltII0172",
        "TestCompatibilityCertificationQuiltII0172RejectsMutableResolvedLoader",
        "TestQuiltLatestStableSelectionUsesStableSemVerWhenMetaOmitsStableFlag",
        "TestQuiltLatestStableFailsClosedWhenMetaContainsOnlyPrereleases",
    ]:
        if required not in quilt_tests_0172:
            fail(f"0.17.2 Quilt regression test missing: {required}")
    for required in ["quilt-install.json", "quilt-certification.json"]:
        if required not in compat_workflow_0172:
            fail(f"0.17.2 Quilt raw CI evidence upload missing: {required}")
    if "Quilt Compatibility II 0.17.2 gate: OK" not in quilt_gate_0172:
        fail("0.17.2 mandatory Quilt Compatibility II gate incomplete")
    if "quilt-compatibility-II-0172.py" not in preflight or "quilt-compatibility-II-0172.py" not in ci:
        fail("0.17.2 Quilt Compatibility II gate is not wired into preflight/CI")

# 0.17.3 Forge Modern makes processor-based Forge 1.13.2+ an executable
# compatibility line: installer processors must run, produce a verified profile,
# resolve a concrete Forge version and launch that profile through NeverRuntime.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 3):
    forge_matrix_0173 = read("scripts/compatibility/matrix.py")
    forge_runtime_0173 = read("cli/cmd/neverlauncher/forge_runtime.go")
    forge_case_0173 = read("e2e/scripts/run-forge-certification-case.sh")
    forge_api_0173 = read("services/api/internal/httpapi/server.go")
    compat_case_0173 = read("e2e/scripts/run-compatibility-case.sh")
    forge_release_0173 = read("cli/cmd/neverlauncher/compatibility_release.go")
    forge_targets_0173 = json.loads(read("compatibility/targets.json"))["targets"]
    forge_tests_0173 = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go")
    forge_gate_0173 = read("scripts/smoke/offline/forge-modern-0173.py")
    compat_workflow_0173 = read(".github/workflows/compatibility.yml")
    for required in ["FORGE_MODERN_0173", "forge_modern_0173_required", "Forge Modern 0.17.3"]:
        if required not in forge_matrix_0173:
            fail(f"0.17.3 Forge compatibility matrix incomplete: {required}")
    if '"id": "forge"' not in forge_api_0173 or '"installer": "neverlauncher-forge-materializer"' not in forge_api_0173 or '"adapter": "compatibility-engine"' not in forge_api_0173:
        fail("0.17.3 Forge loader catalog still advertises a planned adapter")
    for required in ["runForgeProcessors", "clientProcessorCount", "processor-based modern installer format", "MINECRAFT_VERSION", "resolveProcessorNamedToken", "extractInstallerData", "installed-and-verified"]:
        if required not in forge_runtime_0173:
            fail(f"0.17.3 Forge processor materializer incomplete: {required}")
    for required in ["runtime forge-package", "--java", "client verify", "forge-install.json", "forge-certification.json", "clientProcessorCount", "processorRan", "processorSkipped", "certify-vanilla", "mutable loader selector leaked", "actual-mojang-client"]:
        if required not in forge_case_0173:
            fail(f"0.17.3 Forge actual-client execution incomplete: {required}")
    for required in ["run-forge-certification-case.sh", 'loader in ("fabric", "quilt", "forge", "neoforge")', 'install_name = f"{loader}-install.json"', 'probe_name = f"{loader}-certification.json"', "resolvedLoaderVersion"]:
        if required not in compat_case_0173:
            fail(f"0.17.3 Forge compatibility routing incomplete: {required}")
    for required in ["forgeModern0173", "compatibilityForgeModern0173Required", "ForgeVersions", "forge-modern-0.17.3-processor-based-1.13.2-through-current-actual-client"]:
        if required not in forge_release_0173:
            fail(f"0.17.3 Forge release certification incomplete: {required}")
    forge_rows = [row for row in forge_targets_0173 if row.get("required") and row.get("loader") == "forge" and row.get("minecraft") not in {"1.7.10", "1.12.2"} and row.get("os") == "linux" and row.get("arch") == "x86_64"]
    if len(forge_rows) != 43 or len({row.get("minecraft") for row in forge_rows}) != 43:
        fail("0.17.3 Forge target grid must contain exactly 43 unique processor-based releases")
    if {8, 16, 17, 21, 25} - {row.get("javaMajor") for row in forge_rows}:
        fail("0.17.3 Forge target grid does not cover Java 8/16/17/21/25")
    if {row.get("minecraft") for row in forge_rows}.intersection({"1.13", "1.13.1"}):
        fail("0.17.3 Forge Modern must not certify pre-processor Forge 1.13/1.13.1")
    for required in [
        "test_validate_accepts_forge_modern_0173_grid",
        "test_validate_rejects_missing_forge_release_0173",
        "test_validate_rejects_wrong_forge_java_0173",
        "test_validate_rejects_duplicate_forge_release_0173",
        "TestCompatibilityCertificationForgeModern0173",
        "TestCompatibilityCertificationForgeModern0173RejectsMutableResolvedLoader",
        "TestForgeInstallV1ProcessorTokens",
    ]:
        if required not in forge_tests_0173:
            fail(f"0.17.3 Forge regression test missing: {required}")
    for required in ["forge-install.json", "forge-certification.json"]:
        if required not in compat_workflow_0173:
            fail(f"0.17.3 Forge raw CI evidence upload missing: {required}")
    if "Forge Modern 0.17.3 gate: OK" not in forge_gate_0173:
        fail("0.17.3 mandatory Forge Modern gate incomplete")
    if "forge-modern-0173.py" not in preflight or "forge-modern-0173.py" not in ci:
        fail("0.17.3 Forge Modern gate is not wired into preflight/CI")


# 0.17.4 Forge Legacy makes the real 1.12.2 V1 universal-installer path
# release-bound. It must remain distinct from the processor-based 1.13.2+ path.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 4):
    legacy_runtime_0174 = read("cli/cmd/neverlauncher/forge_runtime.go")
    legacy_commands_0174 = read("cli/cmd/neverlauncher/runtime_commands.go")
    legacy_neverruntime_0174 = read("runtime/neverruntime/src/compatibility.rs")
    legacy_case_0174 = read("e2e/scripts/run-forge-certification-case.sh")
    legacy_matrix_0174 = read("scripts/compatibility/matrix.py")
    legacy_release_0174 = read("cli/cmd/neverlauncher/compatibility_release.go")
    legacy_targets_0174 = json.loads(read("compatibility/targets.json"))["targets"]
    legacy_tests_0174 = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go")
    legacy_gate_0174 = read("scripts/smoke/offline/forge-legacy-1122-0174.py")
    for required in ["forgeLegacyInstallerProfile", "legacy-v1-universal", "legacy-v2-empty-processors", "installForgeLegacy", "extractInstallerEntry", "verifyForgeLegacyUniversal", "net.minecraft.launchwrapper.Launch", "net.minecraftforge.fml.common.launcher.FMLTweaker"]:
        if required not in legacy_runtime_0174:
            fail(f"0.17.4 Forge legacy materializer incomplete: {required}")
    for required in ['"forge-legacy-1.12.2"', "legacy V1 universal installer"]:
        if required not in legacy_commands_0174:
            fail(f"0.17.4 runtime capability status incomplete: {required}")
    for required in ['alias = "clientreq"', "library.client_req == Some(false)"]:
        if required not in legacy_neverruntime_0174:
            fail(f"0.17.4 NeverRuntime legacy client library semantics incomplete: {required}")
    for required in ["mc in ('1.7.10', '1.12.2')", "legacy-v1-universal", "legacy-v2-empty-processors", "legacyUniversalSha1", "legacyUniversalSha256", "certify-vanilla"]:
        if required not in legacy_case_0174:
            fail(f"0.17.4 Forge legacy actual-client certification incomplete: {required}")
    for required in ["FORGE_LEGACY_1122_0174", "forge_legacy_1122_0174_required", "Forge Legacy 1.12.2 0.17.4"]:
        if required not in legacy_matrix_0174:
            fail(f"0.17.4 Forge legacy matrix incomplete: {required}")
    for required in ["forgeLegacy1122_0174", "compatibilityForgeLegacy1122_0174Required", "forge-legacy-0.17.4-real-1.12.2-universal-fmltweaker-actual-client"]:
        if required not in legacy_release_0174:
            fail(f"0.17.4 Forge legacy release certification incomplete: {required}")
    legacy_rows = [row for row in legacy_targets_0174 if row.get("required") and row.get("loader") == "forge" and row.get("minecraft") == "1.12.2"]
    if len(legacy_rows) != 1:
        fail("0.17.4 Forge legacy target grid must contain exactly one 1.12.2 row")
    elif legacy_rows[0].get("javaMajor") != 8 or legacy_rows[0].get("scope") != "client" or legacy_rows[0].get("os") != "linux" or legacy_rows[0].get("arch") != "x86_64" or legacy_rows[0].get("loaderVersion") != "latest-stable":
        fail("0.17.4 Forge 1.12.2 target must be latest-stable Java 8 client linux/x86_64")
    for required in ["TestForgeLegacy1122V1UniversalInstaller", "TestForgeLegacy1122RepackedEmptyProcessorInstaller", "TestCompatibilityCertificationForgeLegacy1122_0174", "test_validate_accepts_forge_legacy_1122_0174"]:
        if required not in legacy_tests_0174:
            fail(f"0.17.4 Forge legacy regression test missing: {required}")
    if "Forge Legacy 1.12.2 0.17.4 gate: OK" not in legacy_gate_0174:
        fail("0.17.4 mandatory Forge Legacy gate incomplete")
    if "forge-legacy-1122-0174.py" not in preflight or "forge-legacy-1122-0174.py" not in ci:
        fail("0.17.4 Forge Legacy gate is not wired into preflight/CI")

# 0.17.5 Forge Legacy 1.7.10 makes the real V1 universal + LaunchWrapper/cpw FML
# execution path release-bound and keeps it separate from 1.12.2/modern processors.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 5):
    legacy_runtime_0175 = read("cli/cmd/neverlauncher/forge_runtime.go")
    legacy_commands_0175 = read("cli/cmd/neverlauncher/runtime_commands.go")
    legacy_neverruntime_0175 = read("runtime/neverruntime/src/compatibility.rs")
    legacy_case_0175 = read("e2e/scripts/run-forge-certification-case.sh")
    legacy_matrix_0175 = read("scripts/compatibility/matrix.py")
    legacy_release_0175 = read("cli/cmd/neverlauncher/compatibility_release.go")
    legacy_targets_0175 = json.loads(read("compatibility/targets.json"))["targets"]
    legacy_tests_0175 = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go")
    legacy_gate_0175 = read("scripts/smoke/offline/forge-legacy-1710-0175.py")
    for required in ["cpw.mods.fml.common.launcher.FMLTweaker", "legacy-v1-universal", "normalizeForgeLegacyRuntimeProfile", "canonicalLegacyForgeURL", "legacyProfileNormalized", "net.minecraft.launchwrapper.Launch"]:
        if required not in legacy_runtime_0175:
            fail(f"0.17.5 Forge 1.7.10 materializer incomplete: {required}")
    for required in ['"forge-legacy-1.7.10"', '"forge-legacy-pre-1.7.10"', "legacy V1 universal installer"]:
        if required not in legacy_commands_0175:
            fail(f"0.17.5 runtime capability status incomplete: {required}")
    for required in ["metadata predates downloads.classifiers", "library.downloads.classifiers.is_empty()", "legacy_forge_native_classifier_without_downloads_is_resolved_from_maven_coordinate"]:
        if required not in legacy_neverruntime_0175:
            fail(f"0.17.5 NeverRuntime legacy native resolution incomplete: {required}")
    for required in ["mc in ('1.7.10', '1.12.2')", "cpw.mods.fml.common.launcher.FMLTweaker", "legacyProfileNormalized", "certify-vanilla"]:
        if required not in legacy_case_0175:
            fail(f"0.17.5 Forge 1.7.10 actual-client certification incomplete: {required}")
    for required in ["FORGE_LEGACY_1710_0175", "forge_legacy_1710_0175_required", "Forge Legacy 1.7.10 0.17.5"]:
        if required not in legacy_matrix_0175:
            fail(f"0.17.5 Forge 1.7.10 matrix incomplete: {required}")
    for required in ["forgeLegacy1710_0175", "compatibilityForgeLegacy1710_0175Required", "forge-legacy-0.17.5-real-1.7.10-launchwrapper-cpw-fml-actual-client"]:
        if required not in legacy_release_0175:
            fail(f"0.17.5 Forge 1.7.10 release certification incomplete: {required}")
    legacy_rows = [row for row in legacy_targets_0175 if row.get("required") and row.get("loader") == "forge" and row.get("minecraft") == "1.7.10"]
    if len(legacy_rows) != 1:
        fail("0.17.5 Forge legacy target grid must contain exactly one 1.7.10 row")
    elif legacy_rows[0].get("javaMajor") != 8 or legacy_rows[0].get("scope") != "client" or legacy_rows[0].get("os") != "linux" or legacy_rows[0].get("arch") != "x86_64" or legacy_rows[0].get("loaderVersion") != "latest-stable":
        fail("0.17.5 Forge 1.7.10 target must be latest-stable Java 8 client linux/x86_64")
    for required in ["TestForgeLegacy1710V1LaunchWrapperInstaller", "TestCanonicalLegacyForgeRepositoryURL", "TestCompatibilityCertificationForgeLegacy1710_0175", "test_validate_accepts_forge_legacy_1710_0175"]:
        if required not in legacy_tests_0175:
            fail(f"0.17.5 Forge 1.7.10 regression test missing: {required}")
    if "Forge Legacy 1.7.10 0.17.5 gate: OK" not in legacy_gate_0175:
        fail("0.17.5 mandatory Forge Legacy gate incomplete")
    if "forge-legacy-1710-0175.py" not in preflight or "forge-legacy-1710-0175.py" not in ci:
        fail("0.17.5 Forge Legacy gate is not wired into preflight/CI")


# 0.17.6 NeoForge Compatibility II binds the real NeoForge processor installer
# line, including the separate 1.20.1 net.neoforged:forge publication and the
# post-26.1 full Minecraft version mapping, to actual-client release evidence.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 6):
    neo_runtime_0176 = read("cli/cmd/neverlauncher/forge_runtime.go")
    neo_case_0176 = read("e2e/scripts/run-neoforge-certification-case.sh")
    neo_compat_0176 = read("e2e/scripts/run-compatibility-case.sh")
    neo_matrix_0176 = read("scripts/compatibility/matrix.py")
    neo_release_0176 = read("cli/cmd/neverlauncher/compatibility_release.go")
    neo_api_0176 = read("services/api/internal/httpapi/server.go")
    neo_workflow_0176 = read(".github/workflows/compatibility.yml")
    neo_targets_0176 = json.loads(read("compatibility/targets.json"))["targets"]
    neo_tests_0176 = read("scripts/compatibility/test_matrix.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go")
    neo_gate_0176 = read("scripts/smoke/offline/neoforge-compatibility-II-0176.py")
    for required in ["legacyNeoForge1201", "/net/neoforged/forge/maven-metadata.xml", "/net/neoforged/neoforge/maven-metadata.xml", "neoForgeVersionMatchesMinecraft", "26.1 -> 26.1.0.x", "runForgeProcessors"]:
        if required not in neo_runtime_0176:
            fail(f"0.17.6 NeoForge production materializer incomplete: {required}")
    for required in ["runtime neoforge-package", "neoforge-install.json", "neoforge-certification.json", "mode != 'processors'", "certify-vanilla", "mutable loader selector leaked"]:
        if required not in neo_case_0176:
            fail(f"0.17.6 NeoForge actual-client certification incomplete: {required}")
    for required in ['"$LOADER" == "neoforge"', "run-neoforge-certification-case.sh", 'loader in ("fabric", "quilt", "forge", "neoforge")']:
        if required not in neo_compat_0176:
            fail(f"0.17.6 NeoForge compatibility routing incomplete: {required}")
    for required in ["NEOFORGE_COMPATIBILITY_II_0176", "neoforge_compatibility_ii_0176_required", "NeoForge Compatibility II 0.17.6"]:
        if required not in neo_matrix_0176:
            fail(f"0.17.6 NeoForge matrix incomplete: {required}")
    for required in ["neoForgeCompatibilityII0176", "compatibilityNeoForgeII0176Required", "NeoForgeVersions", "neoforge-compatibility-II-0.17.6-stable-1.20.1-through-26.2-processor-actual-client"]:
        if required not in neo_release_0176:
            fail(f"0.17.6 NeoForge release certification incomplete: {required}")
    expected_neo = {"1.20.1": 17, "1.20.2": 17, "1.20.3": 17, "1.20.4": 17, "1.20.5": 21, "1.20.6": 21,
                    "1.21": 21, "1.21.1": 21, "1.21.2": 21, "1.21.3": 21, "1.21.4": 21, "1.21.5": 21,
                    "1.21.6": 21, "1.21.7": 21, "1.21.8": 21, "1.21.9": 21, "1.21.10": 21, "1.21.11": 21,
                    "26.1": 25, "26.1.1": 25, "26.1.2": 25, "26.2": 25}
    rows = [row for row in neo_targets_0176 if row.get("required") and row.get("loader") == "neoforge" and row.get("os") == "linux" and row.get("arch") == "x86_64"]
    if len(rows) != len(expected_neo):
        fail(f"0.17.6 NeoForge grid requires exactly {len(expected_neo)} targets, got {len(rows)}")
    else:
        by_mc = {row.get("minecraft"): row for row in rows}
        if set(by_mc) != set(expected_neo):
            fail("0.17.6 NeoForge required release set mismatch")
        else:
            for mc, java in expected_neo.items():
                row = by_mc[mc]
                scope = "integration" if mc == "1.21.1" else "client"
                if row.get("javaMajor") != java or row.get("scope") != scope or row.get("os") != "linux" or row.get("arch") != "x86_64" or row.get("loaderVersion") != "latest-stable":
                    fail(f"0.17.6 NeoForge {mc} target binding mismatch")
    if '"adapter": "compatibility-engine", "installer": "neverlauncher-neoforge-materializer", "managedJava": true' not in neo_api_0176:
        fail("0.17.6 NeoForge public loader catalog still advertises a placeholder")
    for required in ["neoforge-install.json", "neoforge-certification.json"]:
        if required not in neo_workflow_0176:
            fail(f"0.17.6 NeoForge CI raw evidence missing: {required}")
    for required in ["TestCompatibilityCertificationNeoForgeII0176", "TestCompatibilityCertificationNeoForgeII0176BundleRejectsTamperedCoverage", "test_validate_accepts_neoforge_compatibility_ii_0176", "1.20.1-47.1.79", "26.2.0.75"]:
        if required not in neo_tests_0176:
            fail(f"0.17.6 NeoForge regression coverage missing: {required}")
    if "NeoForge Compatibility II 0.17.6 gate: OK" not in neo_gate_0176:
        fail("0.17.6 mandatory NeoForge gate incomplete")
    if "neoforge-compatibility-II-0176.py" not in preflight or "neoforge-compatibility-II-0176.py" not in ci:
        fail("0.17.6 NeoForge gate is not wired into preflight/CI")


# 0.17.7 Loader Resolution & Pinning makes every non-Vanilla loader resolution
# replayable from an immutable cryptographic lock and release-binds the lock.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 7):
    pin_lock_0177 = read("cli/cmd/neverlauncher/loader_resolution.go")
    pin_meta_0177 = read("cli/cmd/neverlauncher/loader_runtime.go")
    pin_forge_0177 = read("cli/cmd/neverlauncher/forge_runtime.go")
    pin_compat_0177 = read("e2e/scripts/run-compatibility-case.sh")
    pin_integration_0177 = read("e2e/scripts/run-minecraft-e2e.sh")
    pin_matrix_0177 = read("scripts/compatibility/matrix.py")
    pin_release_0177 = read("cli/cmd/neverlauncher/compatibility_release.go")
    pin_workflow_0177 = read(".github/workflows/compatibility.yml")
    pin_tests_0177 = read("cli/cmd/neverlauncher/loader_resolution_test.go") + read("cli/cmd/neverlauncher/loader_runtime_test.go") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("scripts/compatibility/test_matrix.py")
    pin_gate_0177 = read("scripts/smoke/offline/loader-resolution-pinning-0177.py")
    for required in ["ReproducibilitySHA256", "ResolutionSourceSHA256", "PayloadSHA256", "RuntimeProfileSHA256", "persistLoaderResolutionLock", "readLoaderResolutionLock"]:
        if required not in pin_lock_0177:
            fail(f"0.17.7 loader resolution lock incomplete: {required}")
    for required in ["resolveMetaLoaderVersionWithEvidence", "ResolutionPinned", "assertPinnedPayload", "assertPinnedRuntimeProfile"]:
        if required not in pin_meta_0177:
            fail(f"0.17.7 Fabric/Quilt pinning incomplete: {required}")
    for required in ["resolveForgeLikeVersionWithEvidence", "sha256HexBytes(data)", "ResolutionPinned", "assertPinnedPayloadSHA256", "assertPinnedRuntimeProfile"]:
        if required not in pin_forge_0177:
            fail(f"0.17.7 Forge/NeoForge pinning incomplete: {required}")
    for required in ["resolutionLockSha256", "resolutionSourceSha256", "reproducibilitySha256", "loaderPinned", "reproducibleResolution"]:
        if required not in pin_compat_0177:
            fail(f"0.17.7 compatibility pin evidence incomplete: {required}")
    for required in ["FIRST_LOCK_SHA256", "resolutionPinned", "loaderResolution"]:
        if required not in pin_integration_0177:
            fail(f"0.17.7 integration replay incomplete: {required}")
    for required in ["loader_resolution_pinning_0177_required", "resolutionLockSha256", "reproducibleResolution"]:
        if required not in pin_matrix_0177:
            fail(f"0.17.7 matrix pin enforcement incomplete: {required}")
    for required in ["releaseCompatibilityLoaderPin", "LoaderPins", "compatibilityLoaderResolution0177Required", "loader-resolution-pinning-0.17.7-immutable-lock-upstream-sha256-profile-sha256-replay"]:
        if required not in pin_release_0177:
            fail(f"0.17.7 release certification pinning incomplete: {required}")
    for loader in ["fabric", "quilt", "forge", "neoforge"]:
        if f"e2e/runtime/{loader}-resolution-lock.json" not in pin_workflow_0177:
            fail(f"0.17.7 compatibility workflow does not retain {loader} resolution lock")
    for required in ["TestLoaderResolutionLockRoundTripAndTamperDetection", "TestCompatibilityCertificationLoaderResolutionPinning0177", "test_0177_aggregate_rejects_missing_loader_resolution_pin"]:
        if required not in pin_tests_0177:
            fail(f"0.17.7 pinning regression test missing: {required}")
    if "Loader Resolution & Pinning 0.17.7 gate: OK" not in pin_gate_0177:
        fail("0.17.7 mandatory loader resolution pinning gate incomplete")
    if "loader-resolution-pinning-0177.py" not in preflight or "loader-resolution-pinning-0177.py" not in ci:
        fail("0.17.7 loader resolution pinning gate is not wired into preflight/CI")


# 0.17.8 Loader-native E2E proves a real materialized loader client can join a
# dedicated server running the same loader family and the exact pinned version.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 8):
    native_compose_0178 = read("e2e/docker-compose.minecraft-e2e.yml")
    native_runner_0178 = read("e2e/scripts/run-loader-native-e2e.sh")
    native_integration_0178 = read("e2e/scripts/run-minecraft-e2e.sh")
    native_compat_0178 = read("e2e/scripts/run-compatibility-case.sh")
    native_matrix_0178 = read("scripts/compatibility/matrix.py")
    native_release_0178 = read("cli/cmd/neverlauncher/compatibility_release.go")
    native_workflow_0178 = read(".github/workflows/compatibility.yml")
    native_tests_0178 = read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("scripts/compatibility/test_matrix.py")
    native_gate_0178 = read("scripts/smoke/offline/loader-native-e2e-0178.py")
    for required in ["loader-native:", "FABRIC_LOADER_VERSION", "QUILT_LOADER_VERSION", "FORGE_VERSION", "NEOFORGE_VERSION", '"25580:25565"']:
        if required not in native_compose_0178:
            fail(f"0.17.8 loader-native dedicated server incomplete: {required}")
    for required in ["RESOLVED_LOADER_VERSION", "certify-vanilla", "NeverLauncherCertification joined the game", "loader-native-server-artifacts.txt", "actual-client-joined-dedicated-loader-server"]:
        if required not in native_runner_0178:
            fail(f"0.17.8 loader-native runtime incomplete: {required}")
    for required in ["run-loader-native-e2e.sh", "NEVERLAUNCHER_E2E_RESOLVED_LOADER_VERSION", "loaderNativeClientJoin"]:
        if required not in native_integration_0178:
            fail(f"0.17.8 integration loader-native routing incomplete: {required}")
    for required in ["loaderNativeServer", "loaderVersionMatched", "loaderServerHealthy", "loaderNativeClientJoin", "loader-native-server.json"]:
        if required not in native_compat_0178:
            fail(f"0.17.8 compatibility native evidence incomplete: {required}")
    for required in ["loader_native_e2e_0178_required", "Loader-native E2E 0.17.8 requires exactly one", "loaderNativeClientJoin"]:
        if required not in native_matrix_0178:
            fail(f"0.17.8 matrix native enforcement incomplete: {required}")
    for required in ["LoaderNativeTargets", "compatibilityLoaderNativeE2E0178Required", "loader-native-e2e-0.17.8-fabric-quilt-forge-neoforge-client-server-exact-loader-join"]:
        if required not in native_release_0178:
            fail(f"0.17.8 release certification native enforcement incomplete: {required}")
    for required in ["TestCompatibilityCertificationLoaderNativeE2E0178", "test_0178_aggregate_rejects_missing_loader_native_join"]:
        if required not in native_tests_0178:
            fail(f"0.17.8 loader-native regression test missing: {required}")
    for evidence in ["loader-native-server.json", "loader-native-client.json", "loader-native-server.log", "loader-native-server-artifacts.txt", "loader-native-server-process.txt", "health-loader-native.json"]:
        if f"e2e/runtime/{evidence}" not in native_workflow_0178:
            fail(f"0.17.8 compatibility workflow does not retain {evidence}")
    if "Loader-native E2E 0.17.8 gate: OK" not in native_gate_0178:
        fail("0.17.8 mandatory loader-native E2E gate incomplete")
    if "loader-native-e2e-0178.py" not in preflight or "loader-native-e2e-0178.py" not in ci:
        fail("0.17.8 loader-native E2E gate is not wired into preflight/CI")


# 0.17.9 Cross-platform Loaders certifies real loader clients and native trees
# on every supported desktop OS/architecture pair, not just runner metadata.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 9):
    platform_helper_0179 = read("e2e/scripts/lib/certification-platform.sh")
    platform_verifier_0179 = read("scripts/compatibility/verify-loader-platform.py")
    platform_compat_0179 = read("e2e/scripts/run-compatibility-case.sh")
    platform_matrix_0179 = read("scripts/compatibility/matrix.py")
    platform_release_0179 = read("cli/cmd/neverlauncher/compatibility_release.go")
    platform_workflow_0179 = read(".github/workflows/compatibility.yml")
    platform_runtime_0179 = read("runtime/neverruntime/src/lib.rs")
    platform_tests_0179 = read("scripts/compatibility/test_matrix.py") + read("scripts/compatibility/test_verify_loader_platform.py") + read("cli/cmd/neverlauncher/compatibility_release_test.go")
    platform_gate_0179 = read("scripts/smoke/offline/cross-platform-loaders-0179.py")
    for required in ["linux|windows|macos", "x86_64|aarch64", "certification_exe_suffix", "certification_run_client"]:
        if required not in platform_helper_0179:
            fail(f"0.17.9 platform-native certification helper incomplete: {required}")
    for required in ["materializerTargets", "nativeDirectory", "nativeTreeSha256", "natives/{internal_os}/{arch}"]:
        if required not in platform_verifier_0179:
            fail(f"0.17.9 loader native verifier incomplete: {required}")
    for required in ["cross_platform_loader_anchors", "loaderPlatformMaterialized", "loaderNativesResolved", "loaderPlatformLaunch", "loader-platform.json"]:
        if required not in platform_compat_0179:
            fail(f"0.17.9 compatibility platform evidence incomplete: {required}")
    for required in ["CROSS_PLATFORM_LOADERS_0179", "Cross-platform Loaders 0.17.9", "loaderPlatformMaterialized", "loader-platform.json"]:
        if required not in platform_matrix_0179:
            fail(f"0.17.9 matrix platform enforcement incomplete: {required}")
    for required in ["CrossPlatformLoaderTargets", "compatibilityCrossPlatformLoaders0179Required", "loaderNativesResolved", "cross-platform-loaders-0.17.9-windows-linux-macos-x64-arm64-native-client"]:
        if required not in platform_release_0179:
            fail(f"0.17.9 release certification platform enforcement incomplete: {required}")
    for required in ["natives_directory: String", "natives_dir.to_string_lossy().to_string()"]:
        if required not in platform_runtime_0179:
            fail(f"0.17.9 NeverRuntime native-directory evidence incomplete: {required}")
    for required in ["architecture: ${{ matrix.arch == 'x86_64' && 'x64' || 'aarch64' }}", "e2e/runtime/loader-platform.json"]:
        if required not in platform_workflow_0179:
            fail(f"0.17.9 compatibility workflow platform wiring incomplete: {required}")
    for required in ["test_validate_0179_requires_all_loader_platforms", "test_rejects_foreign_arch_native", "TestCompatibilityCertificationCrossPlatformLoaders0179RejectsTamperedCoverage"]:
        if required not in platform_tests_0179:
            fail(f"0.17.9 cross-platform loader regression test missing: {required}")
    if "Cross-platform Loaders 0.17.9 gate: OK" not in platform_gate_0179:
        fail("0.17.9 mandatory cross-platform loader gate incomplete")
    if "cross-platform-loaders-0179.py" not in preflight or "cross-platform-loaders-0179.py" not in ci:
        fail("0.17.9 cross-platform loader gate is not wired into preflight/CI")


# 0.17.10 Loader Hardening proves immutable loader replay survives mutable/upstream
# failures and interrupted Forge/NeoForge processor installation.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 10):
    hardening_cache_01710 = read("cli/cmd/neverlauncher/loader_hardening.go")
    hardening_processors_01710 = read("cli/cmd/neverlauncher/forge_processor_recovery.go")
    hardening_compat_01710 = read("e2e/scripts/run-compatibility-case.sh")
    hardening_matrix_01710 = read("scripts/compatibility/matrix.py")
    hardening_release_01710 = read("cli/cmd/neverlauncher/compatibility_release.go")
    hardening_workflow_01710 = read(".github/workflows/compatibility.yml")
    hardening_tests_01710 = read("cli/cmd/neverlauncher/loader_runtime_test.go") + read("cli/cmd/neverlauncher/forge_runtime_test.go") + read("cli/cmd/neverlauncher/compatibility_release_test.go") + read("scripts/compatibility/test_matrix.py")
    hardening_gate_01710 = read("scripts/smoke/offline/loader-hardening-01710.py")
    for required in ["loaderPayloadCacheRecord", "loader-cache", "fetchLoaderProfileWithCache", "restorePinnedInstallerFromCache", "downloadPinnedSHA256Artifact"]:
        if required not in hardening_cache_01710:
            fail(f"0.17.10 content-addressed loader cache incomplete: {required}")
    for required in ["processor-journal.json", 'state == "running"', "markProcessorJournal", "InstallerSHA256", "quarantineProcessorOutputs"]:
        if required not in hardening_processors_01710:
            fail(f"0.17.10 processor crash recovery incomplete: {required}")
    for required in ["loaderCacheVerified", "loaderUpstreamRecovery", "loaderInstallerRecovery", "loaderProcessorRecovery", "loader-hardening.json"]:
        if required not in hardening_compat_01710:
            fail(f"0.17.10 compatibility recovery evidence incomplete: {required}")
    for required in ["LOADER_HARDENING_01710", "loader_hardening_01710_required", "loaderCacheVerified", "loader-hardening.json"]:
        if required not in hardening_matrix_01710:
            fail(f"0.17.10 matrix hardening enforcement incomplete: {required}")
    for required in ["LoaderHardeningTargets", "compatibilityLoaderHardening01710Required", "loaderProcessorRecovery", "loader-hardening-0.17.10-content-addressed-cache-pinned-upstream-installer-processor-crash-recovery"]:
        if required not in hardening_release_01710:
            fail(f"0.17.10 release hardening certification incomplete: {required}")
    for required in ["e2e/runtime/loader-hardening.json", "e2e/runtime/loader-hardening-package.json", "processor-journal.json"]:
        if required not in hardening_workflow_01710:
            fail(f"0.17.10 hardening workflow evidence incomplete: {required}")
    for required in ["LoaderCacheOnly", "ProcessorRecovered", "TestCompatibilityCertificationLoaderHardening01710RejectsTamperedCoverage", "test_01710_aggregate_rejects_missing_processor_recovery"]:
        if required not in hardening_tests_01710:
            fail(f"0.17.10 loader hardening regression test missing: {required}")
    if "Loader Hardening 0.17.10 gate: OK" not in hardening_gate_01710:
        fail("0.17.10 mandatory Loader Hardening gate incomplete")
    if "loader-hardening-01710.py" not in preflight or "loader-hardening-01710.py" not in ci:
        fail("0.17.10 Loader Hardening gate is not wired into preflight/CI")


# 0.17.11 Loader Compatibility RC produces one complete release certificate
# derived from the exact compatibility cohort and signed as part of the release bundle.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 17, 11):
    rc_cert_01711 = read("cli/cmd/neverlauncher/compatibility_release_certificate.go")
    rc_compat_01711 = read("cli/cmd/neverlauncher/compatibility_release.go")
    rc_release_01711 = read("cli/cmd/neverlauncher/release_commands.go")
    rc_production_workflow_01711 = read(".github/workflows/production-release-candidate.yml")
    rc_tests_01711 = read("cli/cmd/neverlauncher/compatibility_release_certificate_test.go")
    rc_gate_01711 = read("scripts/smoke/offline/loader-compatibility-rc-01711.py")
    rc_targets_01711 = json.loads(read("compatibility/targets.json"))["targets"]
    for required in ["LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json", "CompatibilityCertificationSHA256", "EvidenceRootSHA256", "CertificateID", "RequiredTargetCount", "PassedTargetCount", "LoaderFamilies", "Platforms", "immutableLoaderPins", "loaderNativeE2E", "crossPlatformLoaders", "loaderHardeningRecovery", "verifyLoaderCompatibilityReleaseCertificate01711"]:
        if required not in rc_cert_01711:
            fail(f"0.17.11 full loader release certificate incomplete: {required}")
    for required in ["compatibilityReleaseCertificate01711Required", "writeLoaderCompatibilityReleaseCertificate01711", "verifyLoaderCompatibilityReleaseCertificate01711"]:
        if required not in rc_compat_01711:
            fail(f"0.17.11 compatibility RC integration incomplete: {required}")
    for required in ["loaderCompatibilityReleaseCertificateFile01711", "loader-compatibility-rc-full-release-certificate", "loaderCompatibilityReleaseCertified", "loaderCompatibilityReleaseCertificateSha256"]:
        if required not in rc_release_01711:
            fail(f"0.17.11 signed release-bundle RC integration incomplete: {required}")
    for required in ["LOADER_COMPATIBILITY_RELEASE_CERTIFICATE.json", "requiredTargetCount == 292", "loaderCompatibilityReleaseCertified == true", "loaderCompatibilityReleaseCertificateSha256"]:
        if required not in rc_production_workflow_01711:
            fail(f"0.17.11 production candidate RC assertion incomplete: {required}")
    required_rows = [row for row in rc_targets_01711 if row.get("required")]
    if len(required_rows) != 292:
        fail(f"0.17.11 full RC requires exactly 292 required compatibility targets, got {len(required_rows)}")
    expected_family_counts = {"vanilla": 109, "fabric": 53, "quilt": 53, "forge": 50, "neoforge": 27}
    actual_family_counts = {loader: sum(1 for row in required_rows if row.get("loader") == loader) for loader in expected_family_counts}
    if actual_family_counts != expected_family_counts:
        fail(f"0.17.11 loader family coverage mismatch: {actual_family_counts}")
    for required in ["TestLoaderCompatibilityReleaseCertificate01711Complete", "TestLoaderCompatibilityReleaseCertificate01711RejectsTamperedRoot", "TestLoaderCompatibilityReleaseCertificate01711RejectsMissingCertificate", "TestLoaderCompatibilityReleaseCertificate01711EvidenceRootChanges"]:
        if required not in rc_tests_01711:
            fail(f"0.17.11 RC regression test missing: {required}")
    if "Loader Compatibility RC 0.17.11 gate: OK" not in rc_gate_01711:
        fail("0.17.11 mandatory Loader Compatibility RC gate incomplete")
    if "loader-compatibility-rc-01711.py" not in preflight or "loader-compatibility-rc-01711.py" not in ci:
        fail("0.17.11 Loader Compatibility RC gate is not wired into preflight/CI")


# 0.18.0 Loader Compatibility GA turns the RC evidence into an executable,
# fail-closed runtime support surface and binds that exact policy into publish-check.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 18, 0):
    ga_runtime_0180 = read("cli/cmd/neverlauncher/loader_ga.go")
    ga_meta_0180 = read("cli/cmd/neverlauncher/loader_runtime.go")
    ga_forge_0180 = read("cli/cmd/neverlauncher/forge_runtime.go")
    ga_cert_0180 = read("cli/cmd/neverlauncher/compatibility_release_certificate.go")
    ga_release_0180 = read("cli/cmd/neverlauncher/release_commands.go")
    ga_ops_0180 = read("cli/cmd/neverlauncher/operations_commands.go")
    ga_workflow_0180 = read(".github/workflows/production-release-candidate.yml")
    ga_tests_0180 = read("cli/cmd/neverlauncher/loader_ga_test.go") + read("cli/cmd/neverlauncher/compatibility_release_certificate_test.go")
    ga_gate_0180 = read("scripts/smoke/offline/loader-compatibility-ga-0180.py")
    for required in ["loaderGASupport0180", "enforceLoaderGASupport0180", "validateLoaderGASupportPolicy0180", "loaderGASupportSHA2560180", "forgeLegacy1710_0175", "forgeLegacy1122_0174"]:
        if required not in ga_runtime_0180:
            fail(f"0.18.0 executable loader GA support incomplete: {required}")
    for name, body in [("Fabric/Quilt", ga_meta_0180), ("Forge/NeoForge", ga_forge_0180)]:
        for required in ["EnforceGASupport", "enforceLoaderGASupport0180", "compatibilityLoaderGA0180Required(version)"]:
            if required not in body:
                fail(f"0.18.0 {name} runtime GA enforcement incomplete: {required}")
    for required in ["ga-certified", "RuntimeSupportSHA256", "RuntimeSupportEntries", "LegacyForgeVersions", "gaRuntimeSupportEnforced", "legacyForgeGA", "loader-compatibility-ga-0.18.0-runtime-enforced-fabric-quilt-forge-neoforge-legacy-all-292-targets-signed-bundle"]:
        if required not in ga_cert_0180:
            fail(f"0.18.0 GA release certificate incomplete: {required}")
    for required in ["loaderCompatibilityGA", "loaderCompatibilityGASupportSha256", "Loader Compatibility GA 0.18.0", "loaderGASupportSHA2560180"]:
        if required not in ga_release_0180:
            fail(f"0.18.0 GA publish enforcement incomplete: {required}")
    for required in ["ga-certified", "runtimeEnforced", "supportSha256", "legacyMinecraftVersions"]:
        if required not in ga_ops_0180:
            fail(f"0.18.0 public loader GA capability incomplete: {required}")
    for required in ['status == "ga-certified"', "loaderCompatibilityGA == true", "loaderCompatibilityGASupportSha256"]:
        if required not in ga_workflow_0180:
            fail(f"0.18.0 production GA assertion incomplete: {required}")
    for required in ["TestLoaderGASupport0180ExactCertifiedSurface", "TestLoaderGASupport0180RejectsJavaDrift", "TestLoaderGA0180ProductionParsersEnableRuntimeGuard", "TestLoaderCompatibilityGA0180CertificateBindsRuntimeSupport", "TestLoaderCompatibilityGA0180RejectsCertifiedRuntimeSurfaceDrift"]:
        if required not in ga_tests_0180:
            fail(f"0.18.0 GA regression test missing: {required}")
    if "Loader Compatibility GA 0.18.0 gate: OK" not in ga_gate_0180:
        fail("0.18.0 mandatory Loader Compatibility GA gate incomplete")
    if "loader-compatibility-ga-0180.py" not in preflight or "loader-compatibility-ga-0180.py" not in ci:
        fail("0.18.0 Loader Compatibility GA gate is not wired into preflight/CI")


# 0.18.1 Windows Protection Core II makes the Windows Guard profile and host
# capability model executable and authenticated instead of declarative.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 18, 1):
    windows_core_0181 = read("runtime/neverruntime/src/windows_protection.rs")
    windows_policy_0181 = read("runtime/neverruntime/src/windows_policy.rs")
    windows_ipc_0181 = read("runtime/neverruntime/src/guard_ipc.rs")
    windows_test_0181 = read("runtime/neverruntime/tests/neverguard_windows.rs")
    windows_gate_0181 = read("scripts/smoke/offline/windows-protection-core-II-0181.py")
    for required in [
        "WindowsProtectionProfile",
        "WindowsProtectionCapabilities",
        "NEVERGUARD_WINDOWS_PROTECTION_CORE_VERSION: u32 = 2",
        "NEVERGUARD_WINDOWS_CAPABILITY_MODEL_VERSION: u32 = 1",
    ]:
        if required not in windows_core_0181:
            fail(f"0.18.1 Windows Protection Core II model incomplete: {required}")
    for required in [
        "SetProcessMitigationPolicy",
        "GetProcessMitigationPolicy",
        "IsProcessInJob",
        "ensure_windows_protection_core_with_profile",
        "validate_windows_guard_policy_report",
    ]:
        if required not in windows_policy_0181:
            fail(f"0.18.1 Windows Protection Core II enforcement incomplete: {required}")
    for required in [
        '.arg("--protection-profile")',
        'send_command(&mut handle, "process-policy")',
        "remote attestation requires aggressive Windows protection profile",
        "validate_status_profile",
    ]:
        if required not in windows_ipc_0181:
            fail(f"0.18.1 Windows Protection Core II authenticated IPC integration incomplete: {required}")
    for required in [
        "neverguard_compat_profile_enforces_its_runtime_capabilities",
        "neverguard_audit_profile_measures_without_claiming_remote_trust",
        "guard_lifetime_job_bound",
    ]:
        if required not in windows_test_0181:
            fail(f"0.18.1 Windows Protection Core II integration regression missing: {required}")
    if "Windows Protection Core II 0.18.1 gate: OK" not in windows_gate_0181:
        fail("0.18.1 mandatory Windows Protection Core II gate incomplete")
    if "windows-protection-core-II-0181.py" not in preflight or "windows-protection-core-II-0181.py" not in ci:
        fail("0.18.1 Windows Protection Core II gate is not wired into preflight/CI")
    if "--test neverguard_windows" not in ci or "-D warnings" not in ci:
        fail("0.18.1 Windows Protection Core II lacks Windows compile/integration/clippy CI")


# 0.18.2 NeverGuard Sensor must be a real signed JVM native agent loaded through
# -agentpath before Minecraft main, with authenticated fail-closed startup proof.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 18, 2):
    sensor_native_0182 = read("runtime/neverguard-sensor/src/lib.rs")
    sensor_bootstrap_0182 = read("runtime/neverruntime/src/windows_sensor.rs")
    sensor_runtime_0182 = read("runtime/neverruntime/src/lib.rs")
    sensor_supervisor_0182 = read("runtime/neverruntime/src/supervisor.rs")
    sensor_ipc_0182 = read("runtime/neverruntime/src/guard_ipc.rs")
    sensor_build_0182 = read("scripts/release/build-windows-desktop.ps1")
    sensor_test_0182 = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
    sensor_gate_0182 = read("scripts/smoke/offline/neverguard-sensor-0182.py")
    sensor_updater_0182 = read("cli/cmd/neverlauncher/component_update.go")
    sensor_signing_0182 = read("cli/cmd/neverlauncher/windows_signing.go")
    for required in ["Agent_OnLoad", "JNI_ERR", "NGSENS03", "neverguard-sensor-startup-v2", "HmacSha256::new_from_slice", ".write_all(&packet)"]:
        if required not in sensor_native_0182:
            fail(f"0.18.2 NeverGuard Sensor native JVM agent incomplete: {required}")
    for required in ["-agentpath:", "create_secure_pipe_server", "verify_windows_authenticode_trust", "authenticate_sensor_or_kill", "child.start_kill()", "loaded_before_main: true", "arm_module_guard"]:
        if required not in sensor_bootstrap_0182:
            fail(f"0.18.2 NeverGuard Sensor fail-closed bootstrap incomplete: {required}")
    if sensor_runtime_0182.count("prepare_sensor_command(&mut command)") < 2 or sensor_runtime_0182.count("authenticate_sensor_or_kill(sensor_bootstrap, &mut child)") < 2:
        fail("0.18.2 NeverGuard Sensor is not enforced in both direct JVM launch paths")
    for required in ["prepare_sensor_command(&mut command)", "authenticate_sensor_or_kill(sensor_bootstrap, &mut child)", "windows_sensor: Option<crate::WindowsSensorReport>"]:
        if required not in sensor_supervisor_0182:
            fail(f"0.18.2 NeverGuard Sensor supervised launch integration incomplete: {required}")
    for required in ["NEVERGUARD_SENSOR_FILE_NAME", "verify_package_artifact(&manifest, &sensor_path)", "verify_windows_authenticode_trust(&sensor_path)"]:
        if required not in sensor_ipc_0182:
            fail(f"0.18.2 NeverGuard Sensor package trust boundary incomplete: {required}")
    for required in ["neverguard_sensor.dll", "Sign-And-VerifyAuthenticode $SensorPackagePath", 'sensorVerification = "sha256+pe-machine+authenticode-before-agentpath"', "neverguard-sensor-windows-$Arch.dll"]:
        if required not in sensor_build_0182:
            fail(f"0.18.2 NeverGuard Sensor signed delivery incomplete: {required}")
    for required in ["expected[\"sensor\"] = false"]:
        if required not in sensor_updater_0182:
            fail(f"0.18.2 NeverGuard Sensor updater integration incomplete: {required}")
    for required in ["neverguardSensorRequired0182", 'packageEntries["sensor"] = "neverguard-sensor.dll"', "expectedComponentCount = 4"]:
        if required not in sensor_signing_0182:
            fail(f"0.18.2 NeverGuard Sensor delivery verifier incomplete: {required}")
    for required in ["neverguard_sensor_agentpath_loads_before_jvm_startup", "authenticate_sensor_or_kill(bootstrap, &mut child)", "let report = session.report()", "assert!(report.loaded_before_main)"]:
        if required not in sensor_test_0182:
            fail(f"0.18.2 NeverGuard Sensor Java integration regression missing: {required}")
    if "NeverGuard Sensor 0.18.2 gate: OK" not in sensor_gate_0182:
        fail("0.18.2 mandatory NeverGuard Sensor gate incomplete")
    if "neverguard-sensor-0182.py" not in preflight or "neverguard-sensor-0182.py" not in ci:
        fail("0.18.2 NeverGuard Sensor gate is not wired into preflight/CI")
    for required in [
        "cargo build --manifest-path runtime/neverguard-sensor/Cargo.toml",
        "--test neverguard_sensor_windows",
        "cargo clippy --manifest-path runtime/neverguard-sensor/Cargo.toml --all-targets -- -D warnings",
    ]:
        if required not in ci:
            fail(f"0.18.2 NeverGuard Sensor lacks Windows build/integration/clippy CI: {required}")



# 0.18.3 Module Guard must continuously observe native module lifecycle in the
# JVM, authenticate the ordered event stream and fail closed on policy/snapshot
# drift instead of relying on point-in-time module snapshots alone.
if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) >= (0, 18, 3):
    module_sensor_0183 = read("runtime/neverguard-sensor/src/lib.rs")
    module_parent_0183 = read("runtime/neverruntime/src/windows_module_guard.rs")
    module_bootstrap_0183 = read("runtime/neverruntime/src/windows_sensor.rs")
    module_supervisor_0183 = read("runtime/neverruntime/src/supervisor.rs")
    module_test_0183 = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
    module_gate_0183 = read("scripts/smoke/offline/neverguard-module-guard-0183.py")
    for required in [
        "LdrRegisterDllNotification",
        "LdrUnregisterDllNotification",
        "MODULE_RING_CAPACITY",
        "MODULE_DROPPED_EVENTS",
        "NGMOD003",
        "neverguard-module-event-v1",
        "wait_for_module_guard_arm",
        "MODULE_WORKER_HANDLE",
        "handle.join()",
    ]:
        if required not in module_sensor_0183:
            fail(f"0.18.3 Module Guard sensor event stream incomplete: {required}")
    for required in [
        "WindowsModuleGuardReport",
        "arm_module_guard",
        "expected_sequence",
        "ct_eq",
        "MODULE_STREAM_TIMEOUT",
        "reconcile_snapshot",
        "external snapshot drift",
        "verify_windows_authenticode_trust",
        "advance_event_chain",
        "TerminateProcess",
        "fail_closed",
    ]:
        if required not in module_parent_0183:
            fail(f"0.18.3 Module Guard parent enforcement incomplete: {required}")
    for required in ["NEVERGUARD_SENSOR_PROTOCOL_VERSION: u32 = 2", "NGSENS03", "policy_for_command", "arm_module_guard", "WindowsSensorSession"]:
        if required not in module_bootstrap_0183:
            fail(f"0.18.3 Module Guard startup binding incomplete: {required}")
    for required in ["sensor_session: Option<crate::WindowsSensorSession>", "process_status_snapshot", "session.report()"]:
        if required not in module_supervisor_0183:
            fail(f"0.18.3 Module Guard live status evidence incomplete: {required}")
    for required in [
        "neverguard_module_guard_tracks_real_jvm_dll_load_and_heartbeat",
        "report.load_events >= 1",
        "report.heartbeat_count >= 1",
        "neverguard_module_guard_fail_closed_on_unsigned_dll_outside_trusted_roots",
        "unsigned module outside trusted roots must be fail-closed",
        "report.violation_count >= 1",
    ]:
        if required not in module_test_0183:
            fail(f"0.18.3 Module Guard Windows integration regression missing: {required}")
    if "Module Guard 0.18.3 gate: OK" not in module_gate_0183:
        fail("0.18.3 mandatory Module Guard gate incomplete")
    if "neverguard-module-guard-0183.py" not in preflight or "neverguard-module-guard-0183.py" not in ci:
        fail("0.18.3 Module Guard gate is not wired into preflight/CI")
    if "--test neverguard_sensor_windows" not in ci or "-D warnings" not in ci:
        fail("0.18.3 Module Guard lacks real Windows integration/clippy CI")

if errors:
    print("[NeverLauncher] repository policy: FAILED", file=sys.stderr)
    for item in errors:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)

print(f"[NeverLauncher] repository policy OK: {VERSION}; immutable releases/client/desktop/key lifecycle/SBOM/provenance production gates активны")

