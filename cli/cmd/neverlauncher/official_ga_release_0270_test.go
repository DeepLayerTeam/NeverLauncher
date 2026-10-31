package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfficialMinecraftGAReceipt0270(t *testing.T) {
	root := t.TempDir()
	commit := strings.Repeat("a", 40)
	targets := []string{"windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}
	signed := make([]map[string]string, 0, len(targets))
	for _, target := range targets {
		signed = append(signed, map[string]string{"target": target, "status": "passed", "attestationSha256": strings.Repeat("b", 64), "signedArtifactSha256": strings.Repeat("c", 64)})
	}
	makeReceipt := func(status string, objects []map[string]string) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"schemaVersion": "launcher.official-minecraft.ga-receipt.v1", "productVersion": "0.27.0", "commit": commit, "status": status, "targets": objects})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, officialGACertification0270), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyOfficialGAReceipt0270(root, "0.27.0", commit); err == nil {
		t.Fatal("missing official GA proof was accepted")
	}
	makeReceipt("passed", signed)
	if err := verifyOfficialGAReceipt0270(root, "0.27.0", commit); err != nil {
		t.Fatal(err)
	}
	if err := verifyOfficialGAReceipt0270(root, "0.27.0", strings.Repeat("d", 40)); err == nil {
		t.Fatal("wrong release source accepted")
	}
	makeReceipt("blocked", signed)
	if err := verifyOfficialGAReceipt0270(root, "0.27.0", commit); err == nil {
		t.Fatal("blocked receipt accepted")
	}
	makeReceipt("passed", signed[:5])
	if err := verifyOfficialGAReceipt0270(root, "0.27.0", commit); err == nil {
		t.Fatal("missing platform accepted")
	}
	duplicate := append(append([]map[string]string{}, signed[:5]...), signed[0])
	makeReceipt("passed", duplicate)
	if err := verifyOfficialGAReceipt0270(root, "0.27.0", commit); err == nil {
		t.Fatal("duplicate platform accepted")
	}
	makeReceipt("passed", signed)
	if err := os.Remove(filepath.Join(root, officialGACertification0270)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, officialGACertification0270)); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := verifyOfficialGAReceipt0270(root, "0.27.0", commit); err == nil {
		t.Fatal("symlinked GA receipt accepted")
	}
	// Existing versions must remain upgrade-compatible: their release rules are unchanged.
	if err := verifyOfficialGAReceipt0270(root, "0.26.12", commit); err != nil {
		t.Fatal(err)
	}
}
