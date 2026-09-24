package dbmigrate

import (
	"strings"
	"testing"
)

func TestMigrationApplyAndVerifyScriptsAreFailClosed(t *testing.T) {
	apply, err := BuildApplyScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"0012_device_trust_core_0121",
		"0013_hardware_bound_identities_0123",
		"0015_session_device_risk_0126",
		"0016_minecraft_serverbridge_trust_0127",
		"0017_device_key_recovery_rotation_0128",
		"0018_device_trust_stabilization_01210",
		"0019_minecraft_serverbridge_integrity_0135",
		"0020_guard_migration_compatibility_stabilization_01310",
		"0021_serverbridge_protocol_v2_0141",
		"0022_serverbridge_crypto_node_identities_0142",
		"0023_one_time_join_tickets_0143",
		"0024_bukkit_family_0144",
		"0025_proxy_family_0145",
		"0026_fabric_server_bridge_0146",
		"0027_forge_neoforge_server_bridge_0147",
		"0028_zero_patch_topology_handoff_0148",
		"0029_serverbridge_public_matrix_ha_hardening_0149",
		"database contains migrations unknown to this binary",
		"UPDATE schema_migrations SET checksum=",
		"pg_advisory_lock(718033100100)",
	} {
		if !strings.Contains(apply, required) {
			t.Fatalf("apply script missing %q", required)
		}
	}

	verify, err := BuildVerifyScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"unknown to this binary",
		"pending migration",
		"without sealed checksum",
		"checksum mismatch",
		"nl_expected_migrations",
	} {
		if !strings.Contains(verify, required) {
			t.Fatalf("verify script missing %q", required)
		}
	}
}
