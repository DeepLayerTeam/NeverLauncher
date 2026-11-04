package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardRuntimeInventory0505(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "mods"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "mods", "allowed.jar")
	if err := os.WriteFile(file, []byte("trusted bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("trusted bytes"))
	sha := hex.EncodeToString(sum[:])
	policy := guardCompatPolicy0502{Artifacts: []guardCompatArtifact0502{{Kind: "mod", Path: "mods/allowed.jar", SHA256: sha}}}
	config, err := guardRuntimeInventory0505(root, policy)
	if err != nil || !strings.Contains(config, "integrity.required=true") || !strings.Contains(config, "integrity.count=1") || !strings.Contains(config, sha) {
		t.Fatalf("signed inventory: %s, %v", config, err)
	}
	if err = os.WriteFile(file, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = guardRuntimeInventory0505(root, policy); err == nil {
		t.Fatal("digest replacement not rejected")
	}
	policy.RevokedDigests = []string{sha}
	if _, err = guardRuntimeInventory0505(root, policy); err == nil {
		t.Fatal("revocation not rejected")
	}
	policy.Artifacts = nil
	if _, err = guardRuntimeInventory0505(root, policy); err == nil {
		t.Fatal("empty inventory accepted")
	}
}
