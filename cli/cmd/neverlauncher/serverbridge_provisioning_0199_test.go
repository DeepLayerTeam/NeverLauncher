package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMarkerJar0199(t *testing.T, path string, entries ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("test")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeCertifiedArtifact0199(t *testing.T, dir, platform, ver string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "neverlauncher-" + platform + "-bridge-" + ver + ".jar"
	path := filepath.Join(dir, name)
	required := map[string][]string{
		"paper": {"plugin.yml", "ru/neverlauncher/bridge/paper/NeverLauncherPaperBridge.class"},
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, entry := range required[platform] {
		w, err := zw.Create(entry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("test")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	digest, size, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	targets := serverBridgeReleaseTargetsForVersion0150(ver)
	cert := serverBridge2Certification0150{
		SchemaVersion: "1.0", Release: "ServerBridge 3", Version: ver, ProtocolVersion: 3, Status: "certified",
		TargetCount: len(targets), ZeroPatch: true, NodeIdentity: "Ed25519", OneTimeJoin: true,
	}
	for _, id := range targets {
		item := serverBridge2CertifiedArtifact0150{ID: id, File: "neverlauncher-" + id + "-bridge-" + ver + ".jar", SHA256: strings.Repeat("a", 64), Bytes: 1}
		if id == platform {
			item.File = name
			item.SHA256 = digest
			item.Bytes = size
		}
		cert.Artifacts = append(cert.Artifacts, item)
	}
	raw, _ := json.Marshal(cert)
	if err := os.WriteFile(filepath.Join(dir, serverBridge3CertificationReleaseFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerBridgeDetectPaper0199(t *testing.T) {
	root := t.TempDir()
	writeMarkerJar0199(t, filepath.Join(root, "paper-1.21.1.jar"), "io/papermc/paper/configuration/GlobalConfiguration.class")
	got, err := detectServerBridgePlatform0199(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform != "paper" || got.Confidence != "high" {
		t.Fatalf("detection=%+v", got)
	}
	if got.InstallDir != filepath.Join(root, "plugins") {
		t.Fatalf("installDir=%s", got.InstallDir)
	}
}

func TestServerBridgeDetectHybridFailsClosed0199(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "mohist-1.21.1.jar"), []byte("hybrid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := detectServerBridgePlatform0199(root, ""); err == nil || !strings.Contains(strings.ToLower(err.Error()), "hybrid") {
		t.Fatalf("hybrid core was not rejected: %v", err)
	}
}

func TestServerBridgeInstallIdentityEnrollmentAndRollback0199(t *testing.T) {
	root := t.TempDir()
	writeMarkerJar0199(t, filepath.Join(root, "paper-1.21.1.jar"), "io/papermc/paper/configuration/GlobalConfiguration.class")
	artifacts := t.TempDir()
	writeCertifiedArtifact0199(t, artifacts, "paper", "0.19.9")

	if err := provisionServerBridge0199([]string{
		"install", "--server-root", root, "--artifact-dir", artifacts, "--bridge-version", "0.19.9",
		"--backend", "https://launcher.example.test", "--server-id", "paper-prod", "--project", "prod", "--profile", "survival",
	}, false); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	state, err := readBridgeProvisionState0199(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Platform != "paper" || state.Version != "0.19.9" {
		t.Fatalf("state=%+v", state)
	}
	if !fileExists0199(state.ArtifactPath) || !fileExists0199(state.ConfigPath) || !fileExists0199(state.IdentityPath) {
		t.Fatalf("managed files missing: %+v", state)
	}
	info, err := os.Stat(state.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity permissions=%o", info.Mode().Perm())
	}
	identity, err := loadNodeIdentityPublic0199(state.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}

	reqRaw, err := os.ReadFile(state.EnrollmentRequestPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reqRaw), "privateKey") || strings.Contains(string(reqRaw), "privateKeyPkcs8") {
		t.Fatal("enrollment request leaked private key")
	}
	var req bridgeEnrollmentRequest0199
	if err := json.Unmarshal(reqRaw, &req); err != nil {
		t.Fatal(err)
	}
	if req.ID != "paper-prod" || req.Kind != "paper" || req.ProjectID != "prod" || req.ProfileID != "survival" || req.KeyFingerprint != identity.Fingerprint || req.PublicKey != identity.PublicKey {
		t.Fatalf("enrollment request mismatch: %+v", req)
	}

	if err := rollbackServerBridge0199([]string{"rollback", "--server-root", root, "--transaction", state.TransactionID}); err != nil {
		t.Fatal(err)
	}
	if fileExists0199(state.ArtifactPath) || fileExists0199(state.ConfigPath) || fileExists0199(state.IdentityPath) || fileExists0199(statePath) {
		t.Fatal("initial install rollback did not restore pre-install filesystem")
	}
}

func TestServerBridgeUpgradeRollbackPreservesIdentity0199(t *testing.T) {
	root := t.TempDir()
	writeMarkerJar0199(t, filepath.Join(root, "paper-1.21.1.jar"), "io/papermc/paper/configuration/GlobalConfiguration.class")
	artifacts018 := t.TempDir()
	writeCertifiedArtifact0199(t, artifacts018, "paper", "0.19.8")

	if err := provisionServerBridge0199([]string{
		"install", "--server-root", root, "--artifact-dir", artifacts018, "--bridge-version", "0.19.8",
		"--backend", "https://launcher.example.test", "--server-id", "paper-prod", "--project", "prod", "--profile", "survival",
	}, false); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	before, err := readBridgeProvisionState0199(statePath)
	if err != nil {
		t.Fatal(err)
	}
	identityBefore, err := loadNodeIdentityPublic0199(before.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	oldArtifact := before.ArtifactPath
	if !fileExists0199(oldArtifact) {
		t.Fatalf("0.19.8 artifact missing before upgrade: %s", oldArtifact)
	}

	artifacts019 := t.TempDir()
	writeCertifiedArtifact0199(t, artifacts019, "paper", "0.19.9")
	if err := provisionServerBridge0199([]string{
		"upgrade", "--server-root", root, "--artifact-dir", artifacts019, "--bridge-version", "0.19.9",
	}, true); err != nil {
		t.Fatal(err)
	}

	after, err := readBridgeProvisionState0199(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != "0.19.9" || after.TransactionID == "" {
		t.Fatalf("upgrade state=%+v", after)
	}
	if fileExists0199(oldArtifact) {
		t.Fatalf("old bridge artifact was not transactionally replaced: %s", oldArtifact)
	}
	identityAfter, err := loadNodeIdentityPublic0199(after.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	if identityAfter.Fingerprint != identityBefore.Fingerprint || identityAfter.PublicKey != identityBefore.PublicKey {
		t.Fatal("upgrade rotated node identity unexpectedly")
	}

	if err := rollbackServerBridge0199([]string{"rollback", "--server-root", root, "--transaction", after.TransactionID}); err != nil {
		t.Fatal(err)
	}
	restored, err := readBridgeProvisionState0199(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Version != "0.19.8" || restored.ArtifactPath != oldArtifact || !fileExists0199(oldArtifact) {
		t.Fatalf("rollback did not restore 0.19.8 state/artifact: %+v", restored)
	}
	if fileExists0199(after.ArtifactPath) {
		t.Fatalf("rollback left upgraded artifact behind: %s", after.ArtifactPath)
	}
	identityRestored, err := loadNodeIdentityPublic0199(restored.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	if identityRestored.Fingerprint != identityBefore.Fingerprint || identityRestored.PublicKey != identityBefore.PublicKey {
		t.Fatal("rollback changed node identity")
	}
}

func TestServerBridgeDryRunDoesNotMutate0199(t *testing.T) {
	root := t.TempDir()
	writeMarkerJar0199(t, filepath.Join(root, "paper.jar"), "io/papermc/paper/configuration/GlobalConfiguration.class")
	artifacts := t.TempDir()
	writeCertifiedArtifact0199(t, artifacts, "paper", "0.19.9")
	if err := provisionServerBridge0199([]string{"install", "--server-root", root, "--artifact-dir", artifacts, "--bridge-version", "0.19.9", "--dry-run"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199))); !os.IsNotExist(err) {
		t.Fatalf("dry-run mutated server root: %v", err)
	}
}

func TestServerBridgeReleaseTargetCohortIncludesUniversalAdapters0199(t *testing.T) {
	for _, id := range []string{"quilt", "sponge", "vanilla"} {
		found := false
		for _, target := range serverBridgeUniversalReleaseTargets0198 {
			if target == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("release verifier missing %s", id)
		}
		if serverBridge2AllowlistFields0150[id] == "" {
			t.Fatalf("release verifier missing allowlist field for %s", id)
		}
	}
}
