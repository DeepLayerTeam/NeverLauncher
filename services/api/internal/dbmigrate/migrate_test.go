package dbmigrate

import (
	"os"
	"strings"
	"testing"
)

func catalogChecksums(t *testing.T) map[string]string {
	t.Helper()
	ms, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string, len(ms))
	for _, m := range ms {
		out[m.Version] = m.Checksum
	}
	return out
}

func TestEvaluateAppliedSealedCatalog(t *testing.T) {
	applied := catalogChecksums(t)
	st, err := EvaluateApplied(applied)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Compatible || len(st.Pending) != 0 || len(st.Unknown) != 0 || len(st.Unverified) != 0 || st.Applied != st.Total {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Current != "0027_forge_neoforge_server_bridge_0147" {
		t.Fatalf("unexpected current migration %q", st.Current)
	}
}

func TestEvaluateAppliedDetectsPendingUnknownUnverifiedAndDrift(t *testing.T) {
	base := catalogChecksums(t)

	pending := make(map[string]string, len(base))
	for k, v := range base {
		if k != "0027_forge_neoforge_server_bridge_0147" {
			pending[k] = v
		}
	}
	st, err := EvaluateApplied(pending)
	if err != nil || !st.Compatible || len(st.Pending) != 1 {
		t.Fatalf("pending should be compatible but incomplete: status=%+v err=%v", st, err)
	}

	unknown := catalogChecksums(t)
	unknown["9999_future"] = "deadbeef"
	st, err = EvaluateApplied(unknown)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "unknown to this binary") {
		t.Fatalf("future migration was not rejected: status=%+v err=%v", st, err)
	}

	unverified := catalogChecksums(t)
	unverified["0009_minecraft_auth_compat_2_0119"] = ""
	st, err = EvaluateApplied(unverified)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "without sealed checksum") {
		t.Fatalf("unsealed checksum was not rejected: status=%+v err=%v", st, err)
	}

	drift := catalogChecksums(t)
	drift["0008_session_management_2_0118"] = strings.Repeat("0", 64)
	st, err = EvaluateApplied(drift)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "checksum migration") {
		t.Fatalf("checksum drift was not rejected: status=%+v err=%v", st, err)
	}
}

func TestDeviceTrustStabilizationMigration01210(t *testing.T) {
	b, err := os.ReadFile("sql/0018_device_trust_stabilization_01210.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"key-rotate",
		"key-recover",
		"trusted_devices_replacement_owner_fk",
		"auth_sessions_trusted_device_owner_fk",
		"minecraft_sessions_never_session_owner_fk",
		"minecraft_sessions_device_owner_fk",
		"minecraft_sessions_profile_owner_fk",
		"trusted_devices_replacement_shape_check",
		"auth_sessions_device_binding_shape_check",
		"legacy-device-revoked",
		"UPDATE minecraft_sessions SET trusted_device_id=NULL",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.12.10 stabilization migration missing %q", required)
		}
	}
}

func TestGuardMigrationCompatibilityStabilization01310(t *testing.T) {
	b, err := os.ReadFile("sql/0020_guard_migration_compatibility_stabilization_01310.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"minecraft_sessions_guard_snapshot_shape_01310",
		"minecraft_sessions_guard_snapshot_freshness_01310",
		"integrity_verified = FALSE",
		"integrity_verified = TRUE",
		"trusted_device_id IS NOT NULL",
		"105 seconds",
		"idx_minecraft_sessions_guard_verified_device_01310",
		"partial Guard snapshot",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.13.10 Guard stabilization migration missing %q", required)
		}
	}
}

func TestServerBridgeProtocolV2Migration0141(t *testing.T) {
	b, err := os.ReadFile("sql/0021_serverbridge_protocol_v2_0141.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"server_bridge_nodes_v2",
		"server_bridge_join_tickets_v2",
		"server_bridge_textures_v2",
		"protocol_version = 2",
		"uq_server_bridge_join_v2_active_player",
		"status='consumed'",
		"credential-rotation-required",
		"neverlauncher_persistence_snapshots_950",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.1 ServerBridge v2 migration missing %q", required)
		}
	}
}

func TestServerBridgeCryptoNodeIdentitiesMigration0142(t *testing.T) {
	b, err := os.ReadFile("sql/0022_serverbridge_crypto_node_identities_0142.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"server_bridge_node_nonces_v2",
		"identity-enrollment-required",
		"key_algorithm",
		"public_key",
		"key_fingerprint",
		"identity_epoch",
		"ed25519",
		"token_hash=''",
		"uq_server_bridge_nodes_v2_key_fingerprint",
		"status='invalidated'",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.2 cryptographic node identity migration missing %q", required)
		}
	}
}

func TestOneTimeJoinTicketsMigration0143(t *testing.T) {
	b, err := os.ReadFile("sql/0023_one_time_join_tickets_0143.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"ticket_version",
		"issued_identity_epoch",
		"issued_key_fingerprint",
		"redeemed_identity_epoch",
		"redeemed_nonce_hash",
		"uq_server_bridge_join_v2_redemption_nonce_0143",
		"DELETE FROM minecraft_joins",
		"status IN ('active','consumed')",
		"consumed_at",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.3 one-time join ticket migration missing %q", required)
		}
	}
}

func TestBukkitFamilyMigration0144(t *testing.T) {
	b, err := os.ReadFile("sql/0024_bukkit_family_0144.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"server_bridge_nodes_v2_kind_check",
		"'bukkit'",
		"'spigot'",
		"'paper'",
		"'purpur'",
		"'folia'",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.4 Bukkit family migration missing %q", required)
		}
	}
}

func TestProxyFamilyMigration0145(t *testing.T) {
	b, err := os.ReadFile("sql/0025_proxy_family_0145.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"server_bridge_nodes_v2_kind_check",
		"'velocity'",
		"'bungeecord'",
		"'waterfall'",
		"'bukkit'",
		"'folia'",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.5 proxy family migration missing %q", required)
		}
	}
}

func TestFabricServerBridgeMigration0146(t *testing.T) {
	b, err := os.ReadFile("sql/0026_fabric_server_bridge_0146.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"server_bridge_nodes_v2_kind_check",
		"'fabric'",
		"'velocity'",
		"'folia'",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.6 Fabric Server Bridge migration missing %q", required)
		}
	}
}

func TestForgeNeoForgeServerBridgeMigration0147(t *testing.T) {
	b, err := os.ReadFile("sql/0027_forge_neoforge_server_bridge_0147.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"server_bridge_nodes_v2_kind_check",
		"'forge'",
		"'neoforge'",
		"'fabric'",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.7 Forge/NeoForge Server Bridge migration missing %q", required)
		}
	}
}

func TestApplyUsesSessionAdvisoryLock(t *testing.T) {
	src, err := os.ReadFile("migrate.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, required := range []string{"pg_advisory_lock(718033100100)", "pg_advisory_unlock(718033100100)", "validateExistingBeforeApply"} {
		if !strings.Contains(text, required) {
			t.Fatalf("migration apply missing serialized gate %q", required)
		}
	}
}
