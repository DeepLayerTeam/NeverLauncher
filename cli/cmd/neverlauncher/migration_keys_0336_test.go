package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateNeverMigrationKeys0336(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "new-never.json")
	if err := generateNeverMigrationKeys0336(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("secret file not 0600: %v", info.Mode())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		JWTKeyID             string            `json:"jwtActiveKid"`
		JWTKeys              map[string]string `json:"jwtKeys"`
		ManifestEd25519Seed  string            `json:"manifestEd25519Seed"`
		ManifestPublicSHA256 string            `json:"manifestPublicSha256"`
	}
	if err = json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.JWTKeys[keys.JWTKeyID]) != 64 || len(keys.ManifestEd25519Seed) != 64 || len(keys.ManifestPublicSHA256) != 64 || keys.JWTKeys[keys.JWTKeyID] == keys.ManifestEd25519Seed {
		t.Fatal("invalid/identical secret output")
	}
	if err = generateNeverMigrationKeys0336(path); err == nil {
		t.Fatal("secret file overwritten")
	}
}
