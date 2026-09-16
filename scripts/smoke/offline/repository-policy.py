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
    "plugins/velocity-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/paper-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
    "plugins/purpur-bridge/build.gradle.kts": "archiveVersion.set(project.version.toString())",
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
    "plugins/paper-bridge/src/main/resources/plugin.yml",
    "plugins/purpur-bridge/src/main/resources/plugin.yml",
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
    "release publish-check", "CI release candidate",
]:
    if required not in build_release:
        fail(f"build-release compatibility certification incomplete: {required}")
if not (ROOT / "cli/cmd/neverlauncher/compatibility_release_test.go").is_file():
    fail("compatibility release certification regression tests are missing")

if errors:
    print("[NeverLauncher] repository policy: FAILED", file=sys.stderr)
    for item in errors:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)

print(f"[NeverLauncher] repository policy OK: {VERSION}; immutable releases/client/desktop/key lifecycle/SBOM/provenance production gates активны")
