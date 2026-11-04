package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gaJSON0330(t *testing.T, dir, name string, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSingleNodeGA0330SignedAttestationAndFallbacks(t *testing.T) {
	dir := t.TempDir()
	trusted := t.TempDir()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(trusted, "operator.pub")
	if err := os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	commit := "c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9"
	required := map[string]int{
		"auth-replay-mfa-and-minecraft": 8, "jobs-lease-fencing-and-outbox": 5,
		"sqlite-real-crash-and-backup": 4, "single-node-coordinator": 5,
		"postgres-transfer-invariants": 1, "actual-postgres-redis-and-s3": 4,
		"http-security-and-minecraft": 4, "measured-load-safety": 3,
	}
	suites := []map[string]any{}
	for name, count := range required {
		passed := []string{}
		for i := 0; i < count; i++ {
			passed = append(passed, name+"_test_"+string(rune('A'+i)))
		}
		suites = append(suites, map[string]any{"suite": name, "count": count, "passed": passed})
	}
	rcRaw := gaJSON0330(t, dir, "SINGLE_NODE_GA_RC.json", map[string]any{
		"format": "launcher-03216-rc-test-evidence-v1", "version": "0.33.0", "commit": commit, "toolchain": "go version go1.27.3 linux/amd64", "suites": suites,
	})
	checks := map[string]string{}
	for _, c := range []string{
		"signed_installer_and_release_bom", "fresh_install_and_owner_bootstrap", "admin_login_and_permissions",
		"minecraft_uuid_login_and_join", "one_time_ticket_and_replay_after_restart", "mfa_and_token_revocation",
		"sqlite_durable_jobs_outbox_and_fencing", "sqlite_wal_crash_and_restore", "upgrade_backup_restore_and_rollback",
		"second_backend_denied_same_storage", "negative_security_and_signature_tests", "bounded_capacity_measurement", "operator_runbook_smoke",
	} {
		checks[c] = "pass"
	}
	report := map[string]any{
		"schema": "launcher-single-node-ga-attestation-v1", "version": "0.33.0", "source_commit": commit,
		"rc_receipt_sha256": singleNodeSHA0330(rcRaw), "operator": "independent synthetic test fixture",
		"environment": map[string]any{
			"backend_repository": "sqlite", "coordinator": "sqlite", "journal_mode": "wal",
			"backend_processes": 1, "database_on_local_supported_filesystem": true,
			"postgres_required": false, "redis_required": false, "durable_data_after_restart": true,
		}, "checks": checks,
		"tested_artifacts": map[string]string{
			"launcher-api-linux-x64":           strings.Repeat("a", 64),
			"launcher-cli-linux-x64":           strings.Repeat("b", 64),
			"launcher-linux-x64-0.33.0.tar.gz": strings.Repeat("c", 64),
		},
	}
	writeSigned := func() {
		raw := gaJSON0330(t, dir, "SINGLE_NODE_GA_ATTESTATION.json", report)
		sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)))
		if err := os.WriteFile(filepath.Join(dir, "SINGLE_NODE_GA_ATTESTATION.sig"), sig, 0o600); err != nil {
			t.Fatal(err)
		}
		gaJSON0330(t, dir, "SINGLE_NODE_GA_CERTIFICATION.json", map[string]any{
			"schema": "launcher-single-node-ga-verification-v1", "version": "0.33.0", "source_commit": commit,
			"status": "independently-attested", "rc_receipt_sha256": singleNodeSHA0330(rcRaw),
			"attestation_sha256": singleNodeSHA0330(raw), "attestation_signature_sha256": singleNodeSHA0330(sig),
			"verification_key_fingerprint": singleNodeSHA0330(pub), "checks": len(checks),
		})
	}
	// Bind approval to the exact installed Linux binary/package bytes.
	for _, file := range []string{"launcher-api-linux-x64", "launcher-cli-linux-x64", "launcher-linux-x64-0.33.0.tar.gz"} {
		payload := []byte("tested release bytes:" + file)
		if err := os.WriteFile(filepath.Join(dir, file), payload, 0o600); err != nil {
			t.Fatal(err)
		}
		report["tested_artifacts"].(map[string]string)[file] = singleNodeSHA0330(payload)
	}
	writeSigned()
	if err := verifySingleNodeGATestedArtifacts0330(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "launcher-api-linux-x64"), []byte("tampered binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySingleNodeGATestedArtifacts0330(dir); err == nil {
		t.Fatal("untested binary substitution accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "launcher-api-linux-x64"), []byte("tested release bytes:launcher-api-linux-x64"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSigned()
	if err := verifySingleNodeGA0330(dir, "0.33.0", commit, pubFile); err != nil {
		t.Fatal(err)
	}
	if err := verifySingleNodeGA0330(dir, "0.33.0", "different-commit", pubFile); err == nil {
		t.Fatal("cross-commit certificate accepted")
	}
	report["environment"].(map[string]any)["backend_repository"] = "postgres"
	writeSigned()
	if err := verifySingleNodeGA0330(dir, "0.33.0", commit, pubFile); err == nil {
		t.Fatal("PostgreSQL fallback accepted as SQLite-only GA")
	}
	report["environment"].(map[string]any)["backend_repository"] = "sqlite"
	writeSigned()
	rcRaw[5] ^= 0xff
	if err := os.WriteFile(filepath.Join(dir, "SINGLE_NODE_GA_RC.json"), rcRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySingleNodeGA0330(dir, "0.33.0", commit, pubFile); err == nil {
		t.Fatal("RC tampering was accepted")
	}
}
