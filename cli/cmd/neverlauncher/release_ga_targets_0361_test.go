package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGA0361DirectSignerBlocksWithoutIndependentSignedEvidence(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_GA_EVIDENCE_DIR", "")
	t.Setenv("NEVERLAUNCHER_GA_TRUSTED_PUBLIC_KEY_FILE", "")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGATargets0361(t.TempDir(), "0.36.1", strings.Repeat("a", 40), pub); err == nil {
		t.Fatal("direct release signer bypassed mandatory GA")
	}
	if err := verifyGATargets0361(t.TempDir(), "0.37.0", strings.Repeat("a", 40), pub); err == nil {
		t.Fatal("future version bypassed mandatory GA")
	}
	if !gaTargetsRequired0361("1.0.0") || gaTargetsRequired0361("0.36.0") {
		t.Fatal("GA threshold violates historical compatibility")
	}
}

func TestGA0361AuthenticatesSixRealArtifactBytesAndSignedTraces(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle")
	evidence := filepath.Join(root, "evidence")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	operatorPub, operatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	releasePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "operator.pub")
	if err := os.WriteFile(key, []byte(hex.EncodeToString(operatorPub)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEVERLAUNCHER_GA_EVIDENCE_DIR", evidence)
	t.Setenv("NEVERLAUNCHER_GA_TRUSTED_PUBLIC_KEY_FILE", key)
	version := "0.36.1"
	commit := strings.Repeat("a", 40)
	now := time.Now().UTC()
	approval := gaApproval0361{Schema: "launcher.ga.targets.v2", Version: version, Commit: commit, Issued: now.Add(-time.Hour).Format("2006-01-02T15:04:05Z"), Expires: now.Add(time.Hour).Format("2006-01-02T15:04:05Z")}
	receipt := gaReceipt0361{Schema: "launcher.ga.verified-targets.v2", Version: version, Commit: commit, Status: "approved-for-release-signing", PublicKeySHA: gaSHA0361(operatorPub)}
	for _, target := range gaTargetNames0361 {
		binary, packageName := gaTargetPaths0361(version, target)
		binData := []byte("real-executable:" + target)
		packageData := []byte("real-package:" + target)
		if err := os.WriteFile(filepath.Join(bundle, binary), binData, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, packageName), packageData, 0600); err != nil {
			t.Fatal(err)
		}
		row := gaTarget0361{Target: target, Status: "certified", BinarySHA: gaSHA0361(binData), PackageSHA: gaSHA0361(packageData), Checks: map[string]gaFileHash0361{}}
		traceDir := filepath.Join(evidence, "targets", target)
		if err := os.MkdirAll(traceDir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, check := range gaCheckNames0361 {
			trace := gaTrace0361{Schema: "launcher.ga.execution.v2", Version: version, Commit: commit, Target: target, Kind: check, Status: "passed", Actual: true, Simulated: false, ArtifactSHA: row.BinarySHA, ExecutionID: "protected-run-012345"}
			raw, err := json.Marshal(trace)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(traceDir, check+".json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			row.Checks[check] = gaFileHash0361{SHA: gaSHA0361(raw)}
		}
		approval.Targets = append(approval.Targets, row)
		rec := struct {
			Target     string `json:"target"`
			Binary     string `json:"binary"`
			BinarySHA  string `json:"binarySha256"`
			Package    string `json:"package"`
			PackageSHA string `json:"packageSha256"`
			Checks     int    `json:"checksPassed"`
		}{target, binary, row.BinarySHA, packageName, row.PackageSHA, len(gaCheckNames0361)}
		// Populate the same (anonymous) receipt type via JSON below.
		rb, _ := json.Marshal(rec)
		var item struct {
			Target     string `json:"target"`
			Binary     string `json:"binary"`
			BinarySHA  string `json:"binarySha256"`
			Package    string `json:"package"`
			PackageSHA string `json:"packageSha256"`
			Checks     int    `json:"checksPassed"`
		}
		if err := json.Unmarshal(rb, &item); err != nil {
			t.Fatal(err)
		}
		receipt.Targets = append(receipt.Targets, item)
	}
	aRaw, _ := json.Marshal(approval)
	sig := hex.EncodeToString(ed25519.Sign(operatorPriv, append([]byte(gaTargetsDomain0361), aRaw...)))
	receipt.ApprovalSHA = gaSHA0361(aRaw)
	rRaw, _ := json.Marshal(receipt)
	for name, data := range map[string][]byte{"GA_TARGET_APPROVAL.json": aRaw, "GA_TARGET_APPROVAL.sig": []byte(sig), "GA_VERIFIED_TARGETS.json": rRaw} {
		if err := os.WriteFile(filepath.Join(bundle, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(evidence, "approval.json"), aRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidence, "approval.sig"), []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyGATargets0361(bundle, version, commit, releasePub); err != nil {
		t.Fatalf("valid signed six-target exact-byte verification rejected: %v", err)
	}
	file := filepath.Join(bundle, "launcher-desktop-windows-x64.exe")
	if err := os.WriteFile(file, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyGATargets0361(bundle, version, commit, releasePub); err == nil {
		t.Fatal("tampered executable passed GA")
	}
	if err := verifyGATargets0361(bundle, "0.36.2", commit, releasePub); err == nil {
		t.Fatal("wrong version accepted")
	}
}
