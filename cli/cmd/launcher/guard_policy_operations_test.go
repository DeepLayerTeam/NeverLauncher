package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuardPolicyOperations05011HistoryDiagnoseAndRollback(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	a := artifact0502(t, root, "mod", "mods/fabric-api.jar", "approved")
	p.Artifacts = []guardCompatArtifact0502{a}
	first := signCompat0502(t, p, priv)
	if err := guardCompatInstall0502(root, first, key); err != nil {
		t.Fatal(err)
	}
	report, err := guardCompatOperation05011(root, key, []string{"guard-policy-diagnose"})
	if err != nil || report["status"] != "pass" {
		t.Fatalf("valid diagnostic: %v %v", report, err)
	}
	if err := os.WriteFile(filepath.Join(root, "mods", "rogue.jar"), []byte("rogue"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err = guardCompatOperation05011(root, key, []string{"guard-policy-diagnose"})
	if err == nil || report["status"] != "blocked" {
		t.Fatal("foreign mod not diagnosed")
	}
	if err := os.Remove(filepath.Join(root, "mods", "rogue.jar")); err != nil {
		t.Fatal(err)
	}
	p.Epoch = 2
	p.RevokedDigests = []string{a.SHA256}
	second := signCompat0502(t, p, priv)
	if err := guardCompatInstall0502(root, second, key); err != nil {
		t.Fatal(err)
	}
	report, err = guardCompatOperation05011(root, key, []string{"guard-policy-history"})
	if err != nil {
		t.Fatal(err)
	}
	items := report["items"].([]guardHistoryItem05011)
	if len(items) != 2 || items[0].Epoch != 2 || items[1].Epoch != 1 || !items[0].Current {
		t.Fatalf("wrong history: %+v", items)
	}
	// Cannot restore prior policy without a new signature at a newer epoch.
	if err := guardCompatAuthorizeRollback05011(root, key, first); err == nil {
		t.Fatal("old epoch rollback accepted")
	}
	p.Epoch = 3
	p.RevokedDigests = nil
	bad := signCompat0502(t, p, priv)
	if err := guardCompatAuthorizeRollback05011(root, key, bad); err == nil {
		t.Fatal("rollback cleared revocation")
	}
	p.RevokedDigests = []string{a.SHA256}
	good := signCompat0502(t, p, priv)
	if err := guardCompatAuthorizeRollback05011(root, key, good); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatInstall0502(root, good, key); err != nil {
		t.Fatal(err)
	}
	report, err = guardCompatOperation05011(root, key, []string{"guard-policy-history"})
	if err != nil || len(report["items"].([]guardHistoryItem05011)) != 3 {
		t.Fatalf("rollback history: %v %v", report, err)
	}
}

func TestGuardPolicyOperations05011CrashAndHistoryTampering(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	if err := guardCompatInstall0502(root, signCompat0502(t, p, priv), key); err != nil {
		t.Fatal(err)
	}
	p.Epoch = 2
	file := signCompat0502(t, p, priv)
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	v, err := guardCompatVerifiedBytes0502(root, key, raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := guardCompatArchiveIncoming05011(root, key, raw, v); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after accepted.json was durably updated but before
	// compatibility.json could be replaced. Reinstalling the same signed epoch
	// must recover, and an older epoch must never be accepted.
	floor, _ := guardCompatPath0502(root, guardCompatFloorFile0502)
	state := []byte(`{"epoch":2,"digest":"` + v.Digest + `","rootSha256":"` + v.RootSHA256 + `"}`)
	if err := trustedAtomic0306(floor, state); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatInstall0502(root, file, key); err != nil {
		t.Fatal(err)
	}
	if err := guardCompatInstall0502(root, signCompat0502(t, policyFixture0502(), priv), key); err == nil {
		t.Fatal("downgrade succeeded")
	}
	archived, _ := guardCompatPath0502(root, guardHistoryDir05011+"/"+guardHistoryName05011(v))
	if err := os.WriteFile(archived, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := guardCompatOperation05011(root, key, []string{"guard-policy-history"})
	if err == nil || report["status"] != "blocked" {
		t.Fatal("corrupt history was accepted")
	}
}

func TestGuardPolicyOperations05011ExpiredPolicyCanRotate(t *testing.T) {
	root, key, priv := compatFixture0502(t)
	p := policyFixture0502()
	first := signCompat0502(t, p, priv)
	if err := guardCompatInstall0502(root, first, key); err != nil {
		t.Fatal(err)
	}
	// Do not need an expired client for the check: verify the same envelope at
	// time after expiry by direct historical verifier.
	raw, _ := os.ReadFile(first)
	v, err := guardCompatHistoricalVerify05011(root, key, raw)
	if err != nil || v.Policy.Epoch != 1 {
		t.Fatalf("historical verifier: %v", err)
	}
	report, err := guardCompatOperation05011(root, key, []string{"guard-policy-diagnose", "--project", "another"})
	if err == nil || !strings.Contains(report["detail"].(string), "scope") {
		t.Fatal("wrong project scope not diagnosed")
	}
}
