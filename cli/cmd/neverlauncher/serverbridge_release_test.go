package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestServerBridge2CertificationRequired0150(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{{"0.14.10", false}, {"0.15.0", true}, {"0.15.1", true}, {"1.0.0", true}} {
		if got := serverBridge2CertificationRequired0150(tc.version); got != tc.want {
			t.Fatalf("required(%s)=%v want %v", tc.version, got, tc.want)
		}
	}
}

func TestVerifyServerBridge2CertificationInBundle0150(t *testing.T) {
	dir := t.TempDir()
	ver := "0.15.0"
	policy := map[string][]string{}
	cert := serverBridge2Certification0150{
		SchemaVersion: "1.0", Release: "ServerBridge 2", Version: ver, ProtocolVersion: 2,
		Status: "certified", TargetCount: len(serverBridge2ReleaseTargets0150), ZeroPatch: true,
		NodeIdentity: "Ed25519", OneTimeJoin: true,
	}
	for i, id := range serverBridge2ReleaseTargets0150 {
		name := fmt.Sprintf("neverlauncher-%s-bridge-%s.jar", id, ver)
		body := []byte(fmt.Sprintf("synthetic-platform-artifact:%s:%d", id, i))
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
		hash, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		cert.Artifacts = append(cert.Artifacts, serverBridge2CertifiedArtifact0150{ID: id, File: name, SHA256: hash, Bytes: size})
		policy[serverBridge2AllowlistFields0150[id]] = []string{hash}
	}
	certRaw, _ := json.Marshal(cert)
	if err := os.WriteFile(filepath.Join(dir, serverBridge2CertificationReleaseFile), certRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	allowRaw, _ := json.Marshal(map[string]map[string][]string{ver: policy})
	if err := os.WriteFile(filepath.Join(dir, "BRIDGE_RELEASE_ALLOWLIST.json"), allowRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyServerBridge2CertificationInBundle0150(dir, ver); err != nil {
		t.Fatalf("valid ServerBridge 2 release certification rejected: %v", err)
	}
	first := cert.Artifacts[0]
	if err := os.WriteFile(filepath.Join(dir, first.File), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyServerBridge2CertificationInBundle0150(dir, ver); err == nil {
		t.Fatal("tampered ServerBridge 2 artifact must be rejected")
	}
}
