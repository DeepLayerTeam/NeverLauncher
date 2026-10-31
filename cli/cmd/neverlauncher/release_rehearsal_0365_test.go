package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRehearsal0365RequiredAndSignedReceipt(t *testing.T) {
	if !rehearsalRequired0365("0.36.5") || !rehearsalRequired0365("0.37.0") || rehearsalRequired0365("0.36.4") {
		t.Fatal("rehearsal policy version switch is unsafe")
	}
	t.Setenv("GITHUB_RUN_ID", "7654321")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	dir := t.TempDir()
	version := "0.36.5"
	commit := strings.Repeat("a", 40)
	if err := verifyRehearsal0365(dir, version, commit); err == nil {
		t.Fatal("missing receipt accepted")
	}
	approval := strings.Repeat("b", 64)
	receipt := map[string]any{"schemaVersion": "launcher.release.rehearsal.v1",
		"version": version, "commit": commit, "status": "package-and-ga-verified", "gaApprovalSha256": approval, "runId": "7654321", "runAttempt": "1"}
	ga := map[string]any{"approvalSha256": approval}
	targets := []map[string]any{}
	gaTargets := []map[string]any{}
	for _, target := range gaTargetNames0361 {
		binary, pack := gaTargetPaths0361(version, target)
		bdata := []byte("native-executable:" + target)
		pdata := []byte("production-package:" + target)
		if err := os.WriteFile(filepath.Join(dir, binary), bdata, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pack), pdata, 0600); err != nil {
			t.Fatal(err)
		}
		item := map[string]any{"target": target, "binary": binary, "package": pack,
			"binarySha256": gaSHA0361(bdata), "packageSha256": gaSHA0361(pdata), "packageMembers": 5}
		targets = append(targets, item)
		gaTargets = append(gaTargets, map[string]any{"target": target,
			"binarySha256": item["binarySha256"], "packageSha256": item["packageSha256"]})
	}
	receipt["targets"] = targets
	ga["targets"] = gaTargets
	write := func(name string, object map[string]any) []byte {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	write("GA_VERIFIED_TARGETS.json", ga)
	raw := write(rehearsalReceipt0365, receipt)
	sums := gaSHA0361(raw) + "  " + rehearsalReceipt0365 + "\n"
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyRehearsal0365(dir, version, commit); err != nil {
		t.Fatalf("valid signed checksum receipt rejected: %v", err)
	}
	if err := verifyRehearsal0365(dir, version, strings.Repeat("c", 40)); err == nil {
		t.Fatal("old commit accepted")
	}
	original := receipt["version"]
	receipt["version"] = "0.36.4"
	write(rehearsalReceipt0365, receipt)
	if err := verifyRehearsal0365(dir, version, commit); err == nil {
		t.Fatal("old version accepted")
	}
	receipt["version"] = original
	write(rehearsalReceipt0365, receipt)
	for _, change := range []string{"changed package", "missing target", "wrong checksum", "unsigned receipt"} {
		switch change {
		case "changed package":
			_, pack := gaTargetPaths0361(version, "linux-arm64")
			os.WriteFile(filepath.Join(dir, pack), []byte("tampered"), 0600)
		case "missing target":
			receipt["targets"] = targets[:5]
			write(rehearsalReceipt0365, receipt)
		case "wrong checksum":
			receipt["targets"] = targets
			write(rehearsalReceipt0365, receipt)
		case "unsigned receipt":
			os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(""), 0600)
		}
		if err := verifyRehearsal0365(dir, version, commit); err == nil {
			t.Fatalf("%s accepted", change)
		}
	}
}
