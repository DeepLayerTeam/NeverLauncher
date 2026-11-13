package dbmigrate

import (
	"crypto/sha256"
	"encoding/hex"
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
		t.Fatalf("Неожиданный статус: %+v", st)
	}
	if st.Current != "0116_server_bound_guard_sessions_0507" {
		t.Fatalf("Неожиданная текущая миграция %q", st.Current)
	}
}

func TestEvaluateAppliedDetectsPendingUnknownUnverifiedAndDrift(t *testing.T) {
	base := catalogChecksums(t)

	pending := make(map[string]string, len(base))
	for k, v := range base {
		if k != "0055_config_audit_02111" {
			pending[k] = v
		}
	}
	st, err := EvaluateApplied(pending)
	if err != nil || !st.Compatible || len(st.Pending) != 1 {
		t.Fatalf("Ожидающая миграция должна быть совместимой, но незавершённой: статус=%+v ошибка=%v", st, err)
	}

	unknown := catalogChecksums(t)
	unknown["9999_future"] = "deadbeef"
	st, err = EvaluateApplied(unknown)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "неизвестные этому исполняемому файлу") {
		t.Fatalf("Миграция из будущей версии не была отклонена: статус=%+v ошибка=%v", st, err)
	}

	unverified := catalogChecksums(t)
	unverified["0009_minecraft_auth_compat_2_0119"] = ""
	st, err = EvaluateApplied(unverified)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "без зафиксированной контрольной суммы") {
		t.Fatalf("Незафиксированная контрольная сумма не отклонена: статус=%+v ошибка=%v", st, err)
	}

	drift := catalogChecksums(t)
	drift["0008_session_management_2_0118"] = strings.Repeat("0", 64)
	st, err = EvaluateApplied(drift)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "Контрольная сумма миграции") {
		t.Fatalf("Изменение контрольной суммы не отклонено: статус=%+v ошибка=%v", st, err)
	}
}

func TestDeviceTrustStabilizationMigration01210(t *testing.T) {
	b, err := os.ReadFile("sql/0018_device_trust_stabilization.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"key-rotate",
		"key-recover",
		"trusted_devices_replacement_owner_fk",
		"auth_sessions_trusted_device_owner_fk",
		"minecraft_sessions_session_owner_fk",
		"minecraft_sessions_device_owner_fk",
		"minecraft_sessions_profile_owner_fk",
		"trusted_devices_replacement_shape_check",
		"auth_sessions_device_binding_shape_check",
		"legacy-device-revoked",
		"UPDATE minecraft_sessions SET trusted_device_id=NULL",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.12.10 stabilization — отсутствует миграция %q", required)
		}
	}
}

func TestGuardMigrationCompatibilityStabilization01310(t *testing.T) {
	b, err := os.ReadFile("sql/0020_guard_migration_compatibility_stabilization.sql")
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
			t.Fatalf("0.13.10 Guard stabilization — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeProtocolV2Migration0141(t *testing.T) {
	b, err := os.ReadFile("sql/0021_serverbridge_protocol_v2_.sql")
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
		"launcher_persistence_snapshots_950",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.14.1 ServerBridge v2 — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeCryptoNodeIdentitiesMigration0142(t *testing.T) {
	b, err := os.ReadFile("sql/0022_serverbridge_crypto_node_identities.sql")
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
			t.Fatalf("0.14.2 cryptographic node identity — отсутствует миграция %q", required)
		}
	}
}

func TestOneTimeJoinTicketsMigration0143(t *testing.T) {
	b, err := os.ReadFile("sql/0023_one_time_join_tickets.sql")
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
			t.Fatalf("0.14.3 one-time join ticket — отсутствует миграция %q", required)
		}
	}
}

func TestBukkitFamilyMigration0144(t *testing.T) {
	b, err := os.ReadFile("sql/0024_bukkit_family.sql")
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
			t.Fatalf("0.14.4 Bukkit family — отсутствует миграция %q", required)
		}
	}
}

func TestProxyFamilyMigration0145(t *testing.T) {
	b, err := os.ReadFile("sql/0025_proxy_family.sql")
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
			t.Fatalf("0.14.5 proxy family — отсутствует миграция %q", required)
		}
	}
}

func TestFabricServerBridgeMigration0146(t *testing.T) {
	b, err := os.ReadFile("sql/0026_fabric_server_bridge.sql")
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
			t.Fatalf("0.14.6 Fabric Server Bridge — отсутствует миграция %q", required)
		}
	}
}

func TestForgeNeoForgeServerBridgeMigration0147(t *testing.T) {
	b, err := os.ReadFile("sql/0027_forge_neoforge_server_bridge.sql")
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
			t.Fatalf("0.14.7 Forge/NeoForge Server Bridge — отсутствует миграция %q", required)
		}
	}
}

func TestZeroPatchTopologyHandoffMigration0148(t *testing.T) {
	b, err := os.ReadFile("sql/0028_zero_patch_topology_handoff.sql")
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
			t.Fatalf("0.14.8 zero-patch topology/handoff — отсутствует миграция %q", required)
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
			t.Fatalf("При применении миграций отсутствует последовательный барьер %q", required)
		}
	}
	if strings.Contains(text, "tx, err := db.BeginTx(ctx, nil)") {
		t.Fatal("Миграция должна начинать транзакции в соединении с рекомендательной блокировкой")
	}
}

func TestServerBridgePublicMatrixHAHardeningMigration0149(t *testing.T) {
	b, err := os.ReadFile("sql/0029_serverbridge_public_matrix_ha_hardening.sql")
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
			t.Fatalf("0.14.9 — отсутствует миграция %q", required)
		}
	}
}

func TestGuardAttestationChallengePurposeMigration0161(t *testing.T) {
	b, err := os.ReadFile("sql/0031_guard_attestation_challenge_purposes.sql")
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
			t.Fatalf("0.16.1 Guard challenge-purpose — отсутствует миграция %q", required)
		}
	}
}

func TestGuardAttestationV2Migration01810(t *testing.T) {
	b, err := os.ReadFile("sql/0032_guard_attestation_v2_.sql")
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
			t.Fatalf("0.18.10 Guard Attestation v2 — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeMigrationStabilization01410(t *testing.T) {
	b, err := os.ReadFile("sql/0030_serverbridge_migration_stabilization.sql")
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
			t.Fatalf("0.14.10 — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeRuntimeIdentityMigration0192(t *testing.T) {
	b, err := os.ReadFile("sql/0033_serverbridge_runtime_identity.sql")
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
			t.Fatalf("0.19.2 ServerBridge runtime identity — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeTelemetryMigration0193(t *testing.T) {
	b, err := os.ReadFile("sql/0034_serverbridge_telemetry.sql")
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
			t.Fatalf("0.19.3 ServerBridge telemetry — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeEventStreamMigration0194(t *testing.T) {
	b, err := os.ReadFile("sql/0035_serverbridge_event_stream.sql")
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
			t.Fatalf("0.19.4 ServerBridge event stream — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeControlAPIMigration0195(t *testing.T) {
	b, err := os.ReadFile("sql/0036_serverbridge_control_api.sql")
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
			t.Fatalf("0.19.5 ServerBridge control — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgeTopologyRouting2Migration0196(t *testing.T) {
	b, err := os.ReadFile("sql/0037_serverbridge_topology_routing2_.sql")
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
			t.Fatalf("0.19.6 topology/routing — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridgePlayerSessionIntegration3Migration0197(t *testing.T) {
	b, err := os.ReadFile("sql/0038_serverbridge_player_session_integration3_.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"session_correlation_id",
		"transfer_sequence",
		"server_bridge_player_sessions_v3",
		"server_bridge_player_transfers_v3",
		"uq_server_bridge_player_session_active_0197",
		"uq_server_bridge_player_minecraft_session_active_0197",
		"recheck_required",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.19.7 player-session — отсутствует миграция %q", required)
		}
	}
}

func TestUniversalServerAdaptersMigration0198(t *testing.T) {
	b, err := os.ReadFile("sql/0039_universal_server_adapters.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"server_bridge_nodes_v2_kind_check", "'quilt'", "'sponge'", "'vanilla'", "separate certification"} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.19.8 — отсутствует миграция %q", required)
		}
	}
	for _, hybrid := range []string{"'mohist'", "'arclight'", "'magma'", "'catserver'", "'banner'", "'cardboard'"} {
		if strings.Contains(text, hybrid) {
			t.Fatalf("Гибридное ядро попало в ограничение допустимых типов: %s", hybrid)
		}
	}
}

func TestServerBridgeHAControlPlaneMigration01911(t *testing.T) {
	b, err := os.ReadFile("sql/0040_serverbridge_ha_control_plane.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"delivery_sequence", "lease_owner", "lease_token", "uq_server_bridge_control_delivery_sequence_01911", "idx_server_bridge_control_resume_01911", "idx_server_bridge_control_owner_01911"} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.19.11 HA — отсутствует миграция %q", required)
		}
	}
}

func TestServerBridge3GAMigration0200(t *testing.T) {
	b, err := os.ReadFile("sql/0041_serverbridge3_ga.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"protocol_version=2", "compatibility/deprecation-only", "nl server-bridge migrate-v3", "idx_server_bridge_nodes_protocol_migration_0200"} {
		if !strings.Contains(text, required) {
			t.Fatalf("GA — отсутствует миграция %q", required)
		}
	}
}

func TestExtensionsRegistryMigration0203(t *testing.T) {
	b, err := os.ReadFile("sql/0043_extensions_registry.sql")
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
		"launcher_registry_version_guard_0203",
		"launcher_registry_immutable_guard_0203",
		"launcher_registry_channel_guard_0203",
		"yank state is irreversible",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.3 registry — отсутствует миграция %q", required)
		}
	}
}

func TestExtensionsInstallLifecycleMigration0204(t *testing.T) {
	b, err := os.ReadFile("sql/0044_extensions_install_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"desired_version", "current_version", "desired_state", "current_state",
		"package_identity", "current_package_identity", "generation", "extension_install_revisions",
		"launcher_extension_install_state_guard_0204", "activated_at",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.4 lifecycle — отсутствует миграция %q", required)
		}
	}
}

func TestExtensionsEventsHooksMigration0206(t *testing.T) {
	b, err := os.ReadFile("sql/0045_extensions_events_hooks.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"extension_event_log", "extension_event_subscriptions", "extension_event_deliveries", "extension_event_dead_letters",
		"UNIQUE (event_type, idempotency_key)", "ON DELETE CASCADE", "payload_sha256", "next_attempt_at", "lease_until", "lease_token", "extension_event_delivery_lease_state",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.6 events — отсутствует миграция %q", required)
		}
	}
	dead := text[strings.Index(text, "CREATE TABLE IF NOT EXISTS extension_event_dead_letters"):]
	if strings.Contains(dead, "REFERENCES extension_event_subscriptions") || strings.Contains(dead, "REFERENCES extension_event_deliveries") {
		t.Fatal("Очередь необработанных сообщений должна сохраняться при удалении подписки или доставки")
	}
}

func TestExtensionsCapabilitySecurityMigration0207(t *testing.T) {
	b, err := os.ReadFile("sql/0046_extensions_capability_security.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"extension_permission_grants", "extension_secrets", "BYTEA", "octet_length(nonce) = 12",
		"PRIMARY KEY", "scope IN ('global','project')", "key_version", "updated_by",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.7 capability security — отсутствует миграция %q", required)
		}
	}
}

func TestExtensionsDependenciesUpdatesMigration02011(t *testing.T) {
	b, err := os.ReadFile("sql/0047_extensions_dependencies_updates.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"min_api", "max_api", "extension_update_pins", "extension_update_leases", "extension_update_transactions",
		"rolled_back", "rollback_failed", "expires_at",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.11 dependency/update — отсутствует миграция %q", required)
		}
	}
}

func TestExtensionsTrustRecoveryCertificationMigration02012(t *testing.T) {
	b, err := os.ReadFile("sql/0048_extensions_trust_recovery_certification.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"extension_trust_policy", "allowed_publishers", "extension_quarantine", "extension_emergency_disables",
		"revoked_at", "released_at", "source", "launcher_revoke_extension_key_02012",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.20.12 trust/recovery — отсутствует миграция %q", required)
		}
	}
}

func TestExtensionsGAMigration0210(t *testing.T) {
	b, err := os.ReadFile("sql/0049_extensions_ga.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{"extension_ga_contract", "package_format_version", "manifest_schema_version", "host_protocol_version", "extension_api_version", "legacy_api_aliases", "3.7"} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.21.0 GA — отсутствует миграция %q", required)
		}
	}
}

func TestHonestValidationTrustMigration0212(t *testing.T) {
	b, err := os.ReadFile("sql/0051_honest_validation_trust.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, required := range []string{
		"package_integrity_checks", "package_runtime_validations", "project_validation_policies",
		"remote_hardware_provenance", "not-verified", "smoke-passed", "integrity", "runtime",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("0.21.2 honest validation/trust — отсутствует миграция %q", required)
		}
	}
}

func TestAuthorizationFoundationMigration0211(t *testing.T) {
	b, err := os.ReadFile("sql/0050_authorization_scopes_identity.sql")
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
			t.Fatalf("0.21.1 authorization — отсутствует миграция %q", required)
		}
	}
}

func TestDurableBoundariesMigration0213(t *testing.T) {
	b, err := os.ReadFile("sql/0052_durable_boundaries.sql")
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
			t.Fatalf("0.21.3 durable boundaries — отсутствует миграция %q", required)
		}
	}
}

func TestComponentTopologyDatabaseGuard0242(t *testing.T) {
	b, err := os.ReadFile("sql/0062_component_topology_presets.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, term := range []string{"('1.0','2.0')", "published release cannot be rewritten", "release profileSnapshot is pinned", "release snapshot not found in immutable history", "invalid v3 component catalog snapshot"} {
		if !strings.Contains(string(b), term) {
			t.Fatalf("Отсутствует защита базы данных %s", term)
		}
	}
}

func TestDependencyConflictMigrationGuard0243(t *testing.T) {
	b, err := os.ReadFile("sql/0063_dependency_conflict_resolver.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"('1.0','2.0','3.0')", "published release cannot be rewritten", "release profileSnapshot is pinned", "release snapshot not found in immutable history"} {
		if !strings.Contains(string(b), phrase) {
			t.Fatalf("в миграции 0063 отсутствует защита %q", phrase)
		}
	}
}

// Обслуживание 0.25.11 развёртывается только вместе с разграничением по арендам в
// БД.
func TestTextureLifecycleMigration02511(t *testing.T) {
	b, err := os.ReadFile("sql/0074_texture_lifecycle_recovery.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{"texture_backup_pins", "gc_lease_token", "expires_at", "ON DELETE CASCADE"} {
		if !strings.Contains(string(b), word) {
			t.Errorf("В миграции жизненного цикла отсутствует %q", word)
		}
	}
}

// Текущий выпуск намеренно не добавляет DDL. Неизвестная миграция в смешанном
// развёртывании 0.51.5/0.51.6 привела бы к ошибке прежнего /ready.
func TestNN1MigrationCatalogFrozen0516(t *testing.T) {
	ms, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	for _, m := range ms {
		_, _ = h.Write([]byte(m.Description + "\x00" + m.Checksum + "\n"))
	}
	const baseline0515 = "12247e5cb196efb8a77d52c64dd55e4b4956703100a928c65d8be0c978c723ce"
	if got := hex.EncodeToString(h.Sum(nil)); got != baseline0515 {
		t.Fatalf("Версии N и N-1 не могут работать после изменения каталога PostgreSQL: %s", got)
	}
}
