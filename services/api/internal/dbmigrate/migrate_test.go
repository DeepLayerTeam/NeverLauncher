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
	if st.Current != "0052_durable_boundaries_0213" {
		t.Fatalf("unexpected current migration %q", st.Current)
	}
}

func TestEvaluateAppliedDetectsPendingUnknownUnverifiedAndDrift(t *testing.T) {
	base := catalogChecksums(t)

	pending := make(map[string]string, len(base))
	for k, v := range base {
		if k != "0052_durable_boundaries_0213" {
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

func TestZeroPatchTopologyHandoffMigration0148(t *testing.T) {
	b, err := os.ReadFile("sql/0028_zero_patch_topology_handoff_0148.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"server_bridge_topology_edges_v2",
		"server_bridge_handoffs_v2",
		"source_identity_epoch",
		"target_identity_epoch",
		"server_bridge_handoffs_active_target_player_uq",
		"runtime-learned ServerBridge topology",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.8 zero-patch topology/handoff migration missing %q", required)
		}
	}
}

func TestApplyUsesSessionAdvisoryLock(t *testing.T) {
	src, err := os.ReadFile("migrate.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, required := range []string{"pg_advisory_lock(718033100100)", "pg_advisory_unlock(718033100100)", "validateExistingBeforeApply", "lockConn.BeginTx(ctx, nil)"} {
		if !strings.Contains(text, required) {
			t.Fatalf("migration apply missing serialized gate %q", required)
		}
	}
	if strings.Contains(text, "tx, err := db.BeginTx(ctx, nil)") {
		t.Fatal("migration apply must start transactions on the advisory-lock connection")
	}
}

func TestServerBridgePublicMatrixHAHardeningMigration0149(t *testing.T) {
	b, err := os.ReadFile("sql/0029_serverbridge_public_matrix_ha_hardening_0149.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"idx_server_bridge_nodes_active_heartbeat_0149",
		"idx_server_bridge_topology_active_freshness_0149",
		"idx_server_bridge_handoffs_active_expiry_0149",
		"idx_server_bridge_join_active_expiry_0149",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.14.9 migration missing %q", required)
		}
	}
}

func TestGuardAttestationChallengePurposeMigration0161(t *testing.T) {
	b, err := os.ReadFile("sql/0031_guard_attestation_challenge_purposes_0161.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"device_challenges_purpose_check",
		"guard-attest-v1",
		"guard-launch-v1",
		"key-rotate",
		"key-recover",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.16.1 Guard challenge-purpose migration missing %q", required)
		}
	}
}

func TestGuardAttestationV2Migration01810(t *testing.T) {
	b, err := os.ReadFile("sql/0032_guard_attestation_v2_01810.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"device_challenges_purpose_check",
		"guard-attest-v1",
		"guard-launch-v1",
		"guard-attest-v2",
		"guard-continuous-join-v2",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.18.10 Guard Attestation v2 migration missing %q", required)
		}
	}
}

func TestServerBridgeMigrationStabilization01410(t *testing.T) {
	b, err := os.ReadFile("sql/0030_serverbridge_migration_stabilization_01410.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"idx_server_bridge_join_consumed_source_01410",
		"idx_server_bridge_nodes_name_folded_01410",
		"idx_server_bridge_join_terminal_retention_01410",
		"idx_server_bridge_handoff_terminal_retention_01410",
		"status='invalidated'",
		"status='expired'",
		"DELETE FROM server_bridge_node_nonces_v2",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.14.10 migration missing %q", required)
		}
	}
}

func TestServerBridgeRuntimeIdentityMigration0192(t *testing.T) {
	b, err := os.ReadFile("sql/0033_serverbridge_runtime_identity_0192.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"runtime_id",
		"runtime_epoch",
		"runtime_identity_signature",
		"runtime_process_id",
		"minecraft_version",
		"runtime_capabilities",
		"server_bridge_runtime_instances_v3",
		"replacement_detected",
		"node_key_fingerprint",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.19.2 ServerBridge runtime identity migration missing %q", required)
		}
	}
}

func TestServerBridgeTelemetryMigration0193(t *testing.T) {
	b, err := os.ReadFile("sql/0034_serverbridge_telemetry_0193.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"telemetry_latest",
		"telemetry_sampled_at",
		"server_bridge_telemetry_samples_v3",
		"sample_id",
		"sample_sequence",
		"runtime_epoch",
		"payload JSONB",
		"idx_server_bridge_telemetry_server_sampled",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.19.3 ServerBridge telemetry migration missing %q", required)
		}
	}
}

func TestServerBridgeEventStreamMigration0194(t *testing.T) {
	b, err := os.ReadFile("sql/0035_serverbridge_event_stream_0194.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"server_bridge_event_cursors_v3",
		"server_bridge_events_v3",
		"ack_sequence",
		"runtime_epoch",
		"payload_sha256",
		"signature",
		"UNIQUE (server_id, runtime_epoch, event_id)",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.19.4 ServerBridge event stream migration missing %q", required)
		}
	}
}

func TestServerBridgeControlAPIMigration0195(t *testing.T) {
	b, err := os.ReadFile("sql/0036_serverbridge_control_api_0195.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{
		"server_bridge_control_commands_v3",
		"idempotency_key",
		"request_digest",
		"runtime_epoch",
		"lease_until",
		"serverbridge:control",
		"serverbridge:console",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("0.19.5 ServerBridge control migration missing %q", required)
		}
	}
}

func TestServerBridgeTopologyRouting2Migration0196(t *testing.T) {
	b, err := os.ReadFile("sql/0037_serverbridge_topology_routing2_0196.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"routing_state",
		"routing_accepting",
		"routing_capacity_max",
		"routing_health",
		"routing_revision",
		"source_runtime_id",
		"source_routing_digest",
		"target_runtime_id",
		"target_routing_digest",
		"server_bridge_nodes_routing_admission_shape_0196",
		"server_bridge_nodes_routing_proof_shape_0196",
		"server_bridge_handoff_routing_proofs_check",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.19.6 topology/routing migration missing %q", required)
		}
	}
}

func TestServerBridgePlayerSessionIntegration3Migration0197(t *testing.T) {
	b, err := os.ReadFile("sql/0038_serverbridge_player_session_integration3_0197.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"session_correlation_id",
		"transfer_sequence",
		"server_bridge_player_sessions_v3",
		"server_bridge_player_transfers_v3",
		"uq_server_bridge_player_never_session_active_0197",
		"uq_server_bridge_player_minecraft_session_active_0197",
		"recheck_required",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.19.7 player-session migration missing %q", required)
		}
	}
}

func TestUniversalServerAdaptersMigration0198(t *testing.T) {
	b, err := os.ReadFile("sql/0039_universal_server_adapters_0198.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"server_bridge_nodes_v2_kind_check", "'quilt'", "'sponge'", "'vanilla'", "separate certification"} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.19.8 migration missing %q", required)
		}
	}
	for _, hybrid := range []string{"'mohist'", "'arclight'", "'magma'", "'catserver'", "'banner'", "'cardboard'"} {
		if strings.Contains(text, hybrid) {
			t.Fatalf("hybrid core leaked into canonical kind constraint: %s", hybrid)
		}
	}
}

func TestServerBridgeHAControlPlaneMigration01911(t *testing.T) {
	b, err := os.ReadFile("sql/0040_serverbridge_ha_control_plane_01911.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"delivery_sequence", "lease_owner", "lease_token", "uq_server_bridge_control_delivery_sequence_01911", "idx_server_bridge_control_resume_01911", "idx_server_bridge_control_owner_01911"} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.19.11 HA migration missing %q", required)
		}
	}
}

func TestServerBridge3GAMigration0200(t *testing.T) {
	b, err := os.ReadFile("sql/0041_serverbridge3_ga_0200.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"protocol_version=2", "compatibility/deprecation-only", "nl server-bridge migrate-v3", "idx_server_bridge_nodes_protocol_migration_0200"} {
		if !strings.Contains(text, required) {
			t.Fatalf("GA migration missing %q", required)
		}
	}
}

func TestNeverExtensionsRegistryMigration0203(t *testing.T) {
	b, err := os.ReadFile("sql/0043_neverextensions_registry_0203.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"extension_registry_publishers",
		"extension_registry_publisher_keys",
		"extension_registry_versions",
		"extension_registry_compatibility",
		"extension_registry_artifacts",
		"extension_registry_channels",
		"package_identity",
		"signature_key_fingerprint",
		"neverlauncher_registry_version_guard_0203",
		"neverlauncher_registry_immutable_guard_0203",
		"neverlauncher_registry_channel_guard_0203",
		"yank state is irreversible",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.3 registry migration missing %q", required)
		}
	}
}

func TestNeverExtensionsInstallLifecycleMigration0204(t *testing.T) {
	b, err := os.ReadFile("sql/0044_neverextensions_install_lifecycle_0204.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"desired_version", "current_version", "desired_state", "current_state",
		"package_identity", "current_package_identity", "generation", "extension_install_revisions",
		"neverlauncher_extension_install_state_guard_0204", "activated_at",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.4 lifecycle migration missing %q", required)
		}
	}
}

func TestNeverExtensionsEventsHooksMigration0206(t *testing.T) {
	b, err := os.ReadFile("sql/0045_neverextensions_events_hooks_0206.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"extension_event_log", "extension_event_subscriptions", "extension_event_deliveries", "extension_event_dead_letters",
		"UNIQUE (event_type, idempotency_key)", "ON DELETE CASCADE", "payload_sha256", "next_attempt_at", "lease_until", "lease_token", "extension_event_delivery_lease_state",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.6 events migration missing %q", required)
		}
	}
	dead := text[strings.Index(text, "CREATE TABLE IF NOT EXISTS extension_event_dead_letters"):]
	if strings.Contains(dead, "REFERENCES extension_event_subscriptions") || strings.Contains(dead, "REFERENCES extension_event_deliveries") {
		t.Fatal("DLQ must survive subscription/delivery deletion")
	}
}

func TestNeverExtensionsCapabilitySecurityMigration0207(t *testing.T) {
	b, err := os.ReadFile("sql/0046_neverextensions_capability_security_0207.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"extension_permission_grants", "extension_secrets", "BYTEA", "octet_length(nonce) = 12",
		"PRIMARY KEY", "scope IN ('global','project')", "key_version", "updated_by",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.7 capability security migration missing %q", required)
		}
	}
}

func TestNeverExtensionsDependenciesUpdatesMigration02011(t *testing.T) {
	b, err := os.ReadFile("sql/0047_neverextensions_dependencies_updates_02011.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"min_api", "max_api", "extension_update_pins", "extension_update_leases", "extension_update_transactions",
		"rolled_back", "rollback_failed", "expires_at",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.11 dependency/update migration missing %q", required)
		}
	}
}

func TestNeverExtensionsTrustRecoveryCertificationMigration02012(t *testing.T) {
	b, err := os.ReadFile("sql/0048_neverextensions_trust_recovery_certification_02012.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"extension_trust_policy", "allowed_publishers", "extension_quarantine", "extension_emergency_disables",
		"revoked_at", "released_at", "source", "neverlauncher_revoke_extension_key_02012",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.12 trust/recovery migration missing %q", required)
		}
	}
}

func TestNeverExtensionsGAMigration0210(t *testing.T) {
	b, err := os.ReadFile("sql/0049_neverextensions_ga_0210.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"extension_ga_contract", "package_format_version", "manifest_schema_version", "host_protocol_version", "extension_api_version", "legacy_api_aliases", "3.7"} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.21.0 GA migration missing %q", required)
		}
	}
}

func TestHonestValidationTrustMigration0212(t *testing.T) {
	b, err := os.ReadFile("sql/0051_honest_validation_trust_0212.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"package_integrity_checks", "package_runtime_validations", "project_validation_policies",
		"remote_hardware_provenance", "not-verified", "smoke-passed", "integrity", "runtime",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.21.2 honest validation/trust migration missing %q", required)
		}
	}
}

func TestAuthorizationFoundationMigration0211(t *testing.T) {
	b, err := os.ReadFile("sql/0050_authorization_scopes_identity_0211.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"project_user_roles_project_fk", "project_user_roles_user_fk", "project_user_roles_role_fk",
		"users_global_role_fk", "project_user_roles_project_not_wildcard", "nl_sync_user_project_roles_0211",
		"identity_version", "issuer", "realm", "subject", "legacy-user-derived-v2",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.21.1 authorization migration missing %q", required)
		}
	}
}

func TestDurableBoundariesMigration0213(t *testing.T) {
	b, err := os.ReadFile("sql/0052_durable_boundaries_0213.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"durable_jobs",
		"durable_job_attempts",
		"durable_scope_leases",
		"event_outbox",
		"used_nonces",
		"idempotency_records",
		"recovered expired lease",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.21.3 durable boundaries migration missing %q", required)
		}
	}
}
