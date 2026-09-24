#!/usr/bin/env python3
from pathlib import Path
import json

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 13, 10):
    raise SystemExit("VERSION is older than 0.13.10")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


api_migration = read("services/api/internal/dbmigrate/sql/0020_guard_migration_compatibility_stabilization_01310.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0020_guard_migration_compatibility_stabilization_01310.sql")
if api_migration != cli_migration:
    raise SystemExit("0.13.10 API/CLI migration copies differ")
require(api_migration, [
    "minecraft_sessions_guard_snapshot_shape_01310",
    "minecraft_sessions_guard_snapshot_freshness_01310",
    "integrity_verified = FALSE",
    "integrity_verified = TRUE",
    "trusted_device_id IS NOT NULL",
    "105 seconds",
    "partial Guard snapshot",
], "0.13.10 Guard stabilization migration")

integrity = read("services/api/internal/httpapi/minecraft_serverbridge_integrity_0135.go")
require(integrity, [
    "isWindowsDevicePlatform0134(device.Platform)",
    "isLinuxDevicePlatform0137(device.Platform)",
    "isMacOSDevicePlatform0138(device.Platform)",
], "Minecraft/ServerBridge Guard platform compatibility")

tests = read("services/api/internal/httpapi/minecraft_serverbridge_integrity_0135_test.go")
require(tests, ["TestGuardIntegrityRequirementIncludesMacOS01310", "darwin-arm64"], "macOS Guard regression test")

matrix = read("scripts/guard_ci/matrix.py")
require(matrix, [
    '"repository": repository',
    '"repository": args.repository',
    "repository=args.repository",
], "Guard CI repository binding")

go_release = read("cli/cmd/neverlauncher/guard_ci_release.go")
require(go_release, [
    'Repository     string',
    'result.Repository != matrix.Repository',
], "CLI Guard evidence repository binding")

go_tests = read("cli/cmd/neverlauncher/guard_ci_release_test.go")
require(go_tests, ["TestGuardCICertificationRejectsRepositoryMismatch01310", "fork/neverlauncher"], "CLI repository mismatch regression")

migration_e2e = read("e2e/scripts/run-guard-migration-e2e.sh")
require(migration_e2e, [
    "(( 10#$ordinal > 19 )) && continue",
    "0019_minecraft_serverbridge_integrity_0135",
    "0020_guard_migration_compatibility_stabilization_01310",
    "partial Guard snapshot",
    "snapshot freshness constraint",
], "Guard migration E2E")

legacy_migration_e2e = read("e2e/scripts/run-device-trust-migration-e2e.sh")
require(legacy_migration_e2e, [
    "(( 10#$ordinal > 17 )) && continue",
    "0017_device_key_recovery_rotation_0128",
], "legacy device-trust migration E2E compatibility")

preflight = read("scripts/release/preflight.sh")
require(preflight, [
    "guard-migration-compatibility-stabilization-01310.py",
    "run-guard-migration-e2e.sh",
], "release preflight")
ci = read(".github/workflows/ci.yml")
require(ci, [
    "guard-migration-compatibility-stabilization-01310.py",
    "run-guard-migration-e2e.sh",
    "neverlauncher-guard-migration-e2e-evidence",
], "CI gate")
if "neverguard-macos:\n    name: NeverGuard macOS production implementation\n    runs-on: macos-14\n    timeout-minutes: 45\n    steps:\n    steps:" in ci:
    raise SystemExit("macOS CI job still contains duplicate steps key")

migration_tests = read("services/api/internal/dbmigrate/migrate_test.go")
require(migration_tests, [
    'st.Current != "0029_serverbridge_public_matrix_ha_hardening_0149"',
    "TestGuardMigrationCompatibilityStabilization01310",
], "Backend migration catalog tests")
cli_migration_tests = read("cli/internal/dbmigrate/migrate_test.go")
require(cli_migration_tests, ["0020_guard_migration_compatibility_stabilization_01310", "0021_serverbridge_protocol_v2_0141", "0022_serverbridge_crypto_node_identities_0142", "0023_one_time_join_tickets_0143", "0024_bukkit_family_0144", "0025_proxy_family_0145", "0026_fabric_server_bridge_0146", "0027_forge_neoforge_server_bridge_0147", "0028_zero_patch_topology_handoff_0148", "0029_serverbridge_public_matrix_ha_hardening_0149"], "CLI migration catalog tests")

# Version manager must have propagated 0.13.10 to Guard policy metadata.
targets = json.loads(read("guard-ci/targets.json"))
if targets.get("productVersion") != version:
    raise SystemExit("Guard CI targets are not aligned with VERSION")

print(f"NeverLauncher 0.13.10 Guard migration + compatibility + stabilization gate: OK ({version})")
