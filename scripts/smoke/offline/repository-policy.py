#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# 1. Все фактические носители версии должны совпадать с VERSION.
version_expectations = {
    ".env.example": VERSION,
    "cli/cmd/neverlauncher/main.go": f'var version = "{VERSION}"',
    "services/api/cmd/neverlauncher-api/main.go": f'var version = "{VERSION}"',
    "apps/admin/package.json": f'"version": "{VERSION}"',
    "apps/admin/package-lock.json": f'"version": "{VERSION}"',
    "apps/desktop/package.json": f'"version": "{VERSION}"',
    "apps/desktop/package-lock.json": f'"version": "{VERSION}"',
    "apps/desktop/src-tauri/Cargo.toml": f'version = "{VERSION}"',
    "apps/desktop/src-tauri/tauri.conf.json": f'"version": "{VERSION}"',
    "runtime/neverruntime/Cargo.toml": f'version = "{VERSION}"',
    "plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeDefaults.java": f'VERSION = "{VERSION}"',
    "plugins/velocity-bridge/src/main/resources/velocity-plugin.json": f'"version": "{VERSION}"',
    "plugins/paper-bridge/src/main/resources/plugin.yml": f'version: {VERSION}',
    "plugins/purpur-bridge/src/main/resources/plugin.yml": f'version: {VERSION}',
    "plugins/velocity-bridge/build.gradle.kts": f'archiveVersion.set("{VERSION}")',
    "plugins/paper-bridge/build.gradle.kts": f'archiveVersion.set("{VERSION}")',
    "plugins/purpur-bridge/build.gradle.kts": f'archiveVersion.set("{VERSION}")',
    "deploy/production/env.production.example": f'NEVERLAUNCHER_IMAGE_TAG={VERSION}',
    "deploy/production/docker-compose.yml": f'NEVERLAUNCHER_IMAGE_TAG:-{VERSION}',
    "e2e/scripts/run-minecraft-e2e.sh": f'VERSION="{VERSION}"',
    "schemas/openapi.yaml": VERSION,
    "scripts/contracts/generate_openapi.py": VERSION,
}
for rel, expected in version_expectations.items():
    path = ROOT / rel
    if not path.is_file():
        fail(f"отсутствует обязательный носитель версии: {rel}")
        continue
    if expected not in read(rel):
        fail(f"{rel}: версия не согласована с VERSION={VERSION}")

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
    "scripts/smoke/README.md",
]
for rel in current_docs:
    text = read(rel)
    if VERSION not in text:
        fail(f"{rel}: текущая версия {VERSION} не указана")
    for match in re.finditer(r"0\.10\.0-P3\.2(?:v\d+)?", text):
        if match.group(0) != VERSION:
            fail(f"{rel}: найдено устаревшее упоминание {match.group(0)} вместо {VERSION}")

ui_files = ["apps/admin/src/main.tsx", "apps/desktop/src/main.tsx"]
for rel in ui_files:
    text = read(rel)
    if VERSION not in text:
        fail(f"{rel}: UI не содержит текущую версию {VERSION}")
    for match in re.finditer(r"0\.10\.0(?:-[A-Za-z0-9.]+)?", text):
        candidate = match.group(0)
        if candidate not in {VERSION, VERSION + "-client"}:
            line = text.count("\n", 0, match.start()) + 1
            fail(f"{rel}:{line}: UI содержит устаревшую продуктовую версию {candidate}")

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

# 9. 0.10.5 real Minecraft client E2E: the release gate must materialize and
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
        fail(f"0.10.5 actual Minecraft E2E отсутствует обязательный primitive: {required}")
for forbidden in ["LaunchFixture", "NEVERLAUNCHER_E2E_FIXTURE_OK", "launch-fixture"]:
    if forbidden in e2e_script:
        fail(f"production Minecraft E2E снова использует synthetic fixture: {forbidden}")
for required in ["hashlib.sha256", "backend checksum mismatch after upload", "local package file changed before upload", "manifestSettings"]:
    if required not in e2e_publish:
        fail(f"E2E package publisher не проверяет реальный artifact lifecycle: {required}")
if "actual-mojang-client" not in ci or "xvfb" not in ci or "Minecraft Client E2E" not in ci:
    fail("CI не содержит блокирующий actual Minecraft Client E2E gate")

if errors:
    print("[NeverLauncher] repository policy: FAILED", file=sys.stderr)
    for item in errors:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)

print(f"[NeverLauncher] repository policy OK: {VERSION}; immutable releases/client/desktop/key lifecycle/SBOM/provenance production gates активны")
