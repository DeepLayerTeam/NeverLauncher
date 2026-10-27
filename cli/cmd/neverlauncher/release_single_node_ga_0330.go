package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The independent GA signing key is an externally pinned trust anchor, never
// read from a release bundle. Release-signing Ed25519 keys cannot substitute.
var singleNodeGAFiles0330 = []string{
	"SINGLE_NODE_GA_ATTESTATION.json",
	"SINGLE_NODE_GA_ATTESTATION.sig",
	"SINGLE_NODE_GA_RC.json",
	"SINGLE_NODE_GA_CERTIFICATION.json",
}

func singleNodeGARequired0330(v string) bool {
	triple, ok := parseVersionTriple0158(v)
	return ok && compareVersionTriple0158(triple, [3]int{0, 33, 0}) >= 0
}

func singleNodeReadBounded0330(dir, name string) ([]byte, error) {
	path := filepath.Join(dir, name)
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 2*1024*1024 {
		return nil, fmt.Errorf("GA evidence %s must be a nonempty ordinary file <= 2 MiB", name)
	}
	return os.ReadFile(path)
}

func singleNodeSHA0330(buf []byte) string {
	s := sha256.Sum256(buf)
	return hex.EncodeToString(s[:])
}

func verifySingleNodeGA0330(dir, ver, commit, publicKeyFile string) error {
	if !singleNodeGARequired0330(ver) {
		return nil
	}
	if publicKeyFile == "" {
		publicKeyFile = os.Getenv("NEVERLAUNCHER_SINGLE_NODE_GA_PUBLIC_KEY_FILE")
	}
	if strings.TrimSpace(publicKeyFile) == "" {
		return errors.New("0.33.0 GA requires independent NEVERLAUNCHER_SINGLE_NODE_GA_PUBLIC_KEY_FILE")
	}
	if err := ensureKeyOutsideReleaseBundle(dir, publicKeyFile); err != nil {
		return err
	}
	pub, err := loadEd25519PublicKey(publicKeyFile)
	if err != nil {
		return fmt.Errorf("GA trust anchor: %w", err)
	}
	reportRaw, err := singleNodeReadBounded0330(dir, singleNodeGAFiles0330[0])
	if err != nil {
		return err
	}
	sigRaw, err := singleNodeReadBounded0330(dir, singleNodeGAFiles0330[1])
	if err != nil {
		return err
	}
	rcRaw, err := singleNodeReadBounded0330(dir, singleNodeGAFiles0330[2])
	if err != nil {
		return err
	}
	certRaw, err := singleNodeReadBounded0330(dir, singleNodeGAFiles0330[3])
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(pub, reportRaw, signature) {
		return errors.New("independent operator Ed25519 GA signature invalid")
	}
	var report struct {
		Schema      string `json:"schema"`
		Version     string `json:"version"`
		Commit      string `json:"source_commit"`
		RCSHA       string `json:"rc_receipt_sha256"`
		Environment struct {
			Backend          string `json:"backend_repository"`
			Coordinator      string `json:"coordinator"`
			WAL              string `json:"journal_mode"`
			Processes        int    `json:"backend_processes"`
			LocalFS          bool   `json:"database_on_local_supported_filesystem"`
			PostgresRequired bool   `json:"postgres_required"`
			RedisRequired    bool   `json:"redis_required"`
			Durable          bool   `json:"durable_data_after_restart"`
		} `json:"environment"`
		Checks          map[string]string `json:"checks"`
		Operator        string            `json:"operator"`
		TestedArtifacts map[string]string `json:"tested_artifacts"`
	}
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		return err
	}
	expectedChecks := []string{
		"signed_installer_and_release_bom", "fresh_install_and_owner_bootstrap", "admin_login_and_permissions",
		"minecraft_uuid_login_and_join", "one_time_ticket_and_replay_after_restart", "mfa_and_token_revocation",
		"sqlite_durable_jobs_outbox_and_fencing", "sqlite_wal_crash_and_restore", "upgrade_backup_restore_and_rollback",
		"second_backend_denied_same_storage", "negative_security_and_signature_tests", "bounded_capacity_measurement",
		"operator_runbook_smoke",
	}
	if report.Schema != "neverlauncher-single-node-ga-attestation-v1" || report.Version != ver || report.Commit != commit ||
		report.RCSHA != singleNodeSHA0330(rcRaw) || report.Operator == "" || report.Environment.Backend != "sqlite" ||
		report.Environment.Coordinator != "sqlite" || report.Environment.WAL != "wal" || report.Environment.Processes != 1 ||
		!report.Environment.LocalFS || report.Environment.PostgresRequired || report.Environment.RedisRequired || !report.Environment.Durable ||
		len(report.Checks) != len(expectedChecks) {
		return errors.New("incomplete GA acceptance evidence or PostgreSQL/Redis fallback detected")
	}
	for _, c := range expectedChecks {
		if report.Checks[c] != "pass" {
			return fmt.Errorf("missing passing GA scenario: %s", c)
		}
	}
	if len(report.TestedArtifacts) != 3 {
		return errors.New("GA report must pin all tested API, CLI and distribution package bytes")
	}
	for _, name := range []string{"neverlauncher-api-linux-x64", "neverlauncher-cli-linux-x64", "neverlauncher-linux-x64-0.33.0.tar.gz"} {
		digest, ok := report.TestedArtifacts[name]
		if !ok || !bomSHA03214(digest) {
			return fmt.Errorf("missing SHA-256 of tested artifact %s", name)
		}
	}
	var rc struct {
		Format    string `json:"format"`
		Toolchain string `json:"toolchain"`
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		Suites    []struct {
			Name   string   `json:"suite"`
			Count  int      `json:"count"`
			Passed []string `json:"passed"`
		} `json:"suites"`
	}
	if err := json.Unmarshal(rcRaw, &rc); err != nil {
		return err
	}
	required := map[string]int{
		"auth-replay-mfa-and-minecraft": 8, "jobs-lease-fencing-and-outbox": 5, "sqlite-real-crash-and-backup": 4,
		"single-node-coordinator": 5, "postgres-transfer-invariants": 1, "actual-postgres-redis-and-s3": 4,
		"http-security-and-minecraft": 4, "measured-load-safety": 3,
	}
	if rc.Format != "neverlauncher-03216-rc-test-evidence-v1" || rc.Version != ver || rc.Commit != commit || len(rc.Suites) != len(required) || !regexp.MustCompile(`go1\.(?:2[7-9]|[3-9]\d)\.`).MatchString(rc.Toolchain) {
		return errors.New("RC exact-commit evidence incomplete")
	}
	for _, suite := range rc.Suites {
		count, ok := required[suite.Name]
		if !ok || suite.Count != count || len(suite.Passed) != count {
			return errors.New("missing/duplicated RC test suite")
		}
		delete(required, suite.Name)
		seen := map[string]bool{}
		for _, name := range suite.Passed {
			if name == "" || seen[name] {
				return errors.New("duplicate RC test result")
			}
			seen[name] = true
		}
	}
	if len(required) != 0 {
		return errors.New("required RC tests not completed")
	}
	var cert struct {
		Schema         string `json:"schema"`
		Version        string `json:"version"`
		Commit         string `json:"source_commit"`
		Status         string `json:"status"`
		RCSHA          string `json:"rc_receipt_sha256"`
		AttestationSHA string `json:"attestation_sha256"`
		SignatureSHA   string `json:"attestation_signature_sha256"`
		Fingerprint    string `json:"verification_key_fingerprint"`
		Checks         int    `json:"checks"`
	}
	if err := json.Unmarshal(certRaw, &cert); err != nil {
		return err
	}
	if cert.Schema != "neverlauncher-single-node-ga-verification-v1" || cert.Version != ver || cert.Commit != commit || cert.Status != "independently-attested" ||
		cert.RCSHA != singleNodeSHA0330(rcRaw) || cert.AttestationSHA != singleNodeSHA0330(reportRaw) ||
		cert.SignatureSHA != singleNodeSHA0330([]byte(strings.TrimSpace(string(sigRaw)))) || cert.Fingerprint != singleNodeSHA0330(pub) || cert.Checks != len(expectedChecks) {
		return errors.New("GA certificate is not bound to signed evidence and exact RC receipt")
	}
	return nil
}

func verifySingleNodeGABundle0330(dir, ver, commit, pub string) error {
	if !singleNodeGARequired0330(ver) {
		return nil
	}
	if err := verifySingleNodeGA0330(dir, ver, commit, pub); err != nil {
		return err
	}
	if err := verifySingleNodeGATestedArtifacts0330(dir); err != nil {
		return err
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "RELEASE_MANIFEST.json"))
	if err != nil {
		return err
	}
	var manifest struct {
		RequiredFiles []string `json:"requiredFiles"`
		Artifacts     []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
			SHA      string `json:"sha256"`
			Status   string `json:"status"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return err
	}
	for _, file := range singleNodeGAFiles0330 {
		present := false
		for _, required := range manifest.RequiredFiles {
			if required == file {
				present = true
				break
			}
		}
		if !present {
			return fmt.Errorf("GA evidence %s is not mandatory in signed manifest", file)
		}
		raw, err := singleNodeReadBounded0330(dir, file)
		if err != nil {
			return err
		}
		present = false
		for _, item := range manifest.Artifacts {
			if item.Name == file && item.Required && item.Status == "present" && item.SHA == singleNodeSHA0330(raw) {
				present = true
			}
		}
		if !present {
			return fmt.Errorf("GA evidence %s missing from signed artifact inventory", file)
		}
	}
	return nil
}

// The independent operator must have exercised the SAME Linux release bytes
// that the release signer is about to publish, not a different local build.
func verifySingleNodeGATestedArtifacts0330(dir string) error {
	raw, err := singleNodeReadBounded0330(dir, singleNodeGAFiles0330[0])
	if err != nil {
		return err
	}
	var report struct {
		TestedArtifacts map[string]string `json:"tested_artifacts"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	if len(report.TestedArtifacts) != 3 {
		return errors.New("GA tested artifact inventory incomplete")
	}
	for name, expected := range report.TestedArtifacts {
		if name != "neverlauncher-api-linux-x64" && name != "neverlauncher-cli-linux-x64" && name != "neverlauncher-linux-x64-0.33.0.tar.gz" {
			return fmt.Errorf("unapproved tested artifact: %s", name)
		}
		actual, _, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("GA tested artifact %s missing: %w", name, err)
		}
		if actual != expected {
			return fmt.Errorf("GA tested artifact %s differs from independently approved bytes", name)
		}
	}
	return nil
}
