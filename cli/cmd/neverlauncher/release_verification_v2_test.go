package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeEd25519Pair0158(t *testing.T, dir, name string) (string, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, name+"-private.pem")
	pubPath := filepath.Join(dir, name+"-public.pem")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath, priv
}

func TestReleaseVerificationV2TrustLifecycleAndAntiRollback(t *testing.T) {
	tmp := t.TempDir()
	registry := filepath.Join(tmp, "registry")
	rootPriv, rootPub, _ := writeEd25519Pair0158(t, tmp, "root")
	releasePriv := filepath.Join(tmp, "release-private.pem")
	releasePub := filepath.Join(tmp, "release-public.pem")
	payload, err := rotateSecurityKey([]string{"rotate-key", "--registry-dir", registry, "--key", "release-signing", "--private-key-out", releasePriv, "--public-key-out", releasePub})
	if err != nil {
		t.Fatal(err)
	}
	key := payload["key"].(securityKeyRecord)
	policyPath := filepath.Join(tmp, releaseTrustPolicyFile0158)
	if _, err := exportReleaseTrustPolicy0158([]string{"trust-policy", "--registry-dir", registry, "--root-private-key", rootPriv, "--policy-out", policyPath}); err != nil {
		t.Fatal(err)
	}

	bundle := filepath.Join(tmp, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"RELEASE_MANIFEST.json": []byte("{\"version\":\"0.15.8\"}\n"),
		"SHA256SUMS":            []byte("0123456789abcdef  artifact\n"),
		"PROVENANCE.json":       []byte("{\"test\":true}\n"),
	} {
		if err := os.WriteFile(filepath.Join(bundle, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(policyPath)
	if err := os.WriteFile(filepath.Join(bundle, releaseTrustPolicyFile0158), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	priv, err := loadEd25519PrivateKey(releasePriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := signReleaseBundleV20158(bundle, priv); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(tmp, "trust-state.json")
	ctx, err := verifyReleaseSignatureV20158(bundle, rootPub, state, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Envelope.KeyID != key.ID || ctx.Policy.Epoch != 1 {
		t.Fatalf("unexpected envelope/policy: %#v %#v", ctx.Envelope, ctx.Policy)
	}
	if err := commitTrustState0158(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := loadTrustState0158(state)
	if err != nil {
		t.Fatal(err)
	}
	if s.HighestTrustEpoch != 1 || s.HighestRelease != "0.15.8" {
		t.Fatalf("unexpected trust state: %#v", s)
	}

	// A signed older release is rejected after 0.15.8 has been accepted.
	if err := os.WriteFile(filepath.Join(bundle, "RELEASE_MANIFEST.json"), []byte("{\"version\":\"0.15.7\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signReleaseBundleV20158(bundle, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyReleaseSignatureV20158(bundle, rootPub, state, policyPath); err == nil {
		t.Fatal("expected anti-rollback rejection")
	}

	// Rotation advances trust epoch and makes the old release key verify-only.
	if _, err := rotateSecurityKey([]string{"rotate-key", "--registry-dir", registry, "--key", "release-signing"}); err != nil {
		t.Fatal(err)
	}
	policy2 := filepath.Join(tmp, "policy2.json")
	if _, err := exportReleaseTrustPolicy0158([]string{"trust-policy", "--registry-dir", registry, "--root-private-key", rootPriv, "--policy-out", policy2}); err != nil {
		t.Fatal(err)
	}
	p2, err := loadReleaseTrustPolicy0158(policy2)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Epoch != 2 {
		t.Fatalf("epoch=%d want 2", p2.Epoch)
	}
	foundOld := false
	for _, k := range p2.Keys {
		if k.ID == key.ID {
			foundOld = true
			if k.Status != "verify-only" {
				t.Fatalf("old key status=%s", k.Status)
			}
		}
	}
	if !foundOld {
		t.Fatal("old key missing after rotation")
	}

	// A fresh verifier using the current policy can still verify a historical
	// release with a verify-only key, but a later revocation blocks it.
	freshState := filepath.Join(tmp, "fresh-trust-state.json")
	if _, err := verifyReleaseSignatureV20158(bundle, rootPub, freshState, policy2); err != nil {
		t.Fatalf("verify-only historical key should verify before revocation: %v", err)
	}
	if _, err := securityRevocations([]string{"revocation-list", "--registry-dir", registry, "--revoke", key.ID}); err != nil {
		t.Fatal(err)
	}
	policy3 := filepath.Join(tmp, "policy3.json")
	if _, err := exportReleaseTrustPolicy0158([]string{"trust-policy", "--registry-dir", registry, "--root-private-key", rootPriv, "--policy-out", policy3}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyReleaseSignatureV20158(bundle, rootPub, filepath.Join(tmp, "revoked-state.json"), policy3); err == nil {
		t.Fatal("revoked historical release key must be rejected by current trust policy")
	}
}

func TestReleaseTrustPolicyRejectsTampering(t *testing.T) {
	tmp := t.TempDir()
	registry := filepath.Join(tmp, "registry")
	rootPriv, rootPub, _ := writeEd25519Pair0158(t, tmp, "root")
	if _, err := rotateSecurityKey([]string{"rotate-key", "--registry-dir", registry, "--key", "release-signing"}); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(tmp, "policy.json")
	if _, err := exportReleaseTrustPolicy0158([]string{"trust-policy", "--registry-dir", registry, "--root-private-key", rootPriv, "--policy-out", policyPath}); err != nil {
		t.Fatal(err)
	}
	p, err := loadReleaseTrustPolicy0158(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyReleaseTrustPolicy0158(p, rootPub, parseTestTime0158(t, p.IssuedAt), true); err != nil {
		t.Fatal(err)
	}
	p.Epoch++
	if _, err := verifyReleaseTrustPolicy0158(p, rootPub, parseTestTime0158(t, p.IssuedAt), true); err == nil {
		t.Fatal("tampered policy must fail root signature")
	}
}

func parseTestTime0158(t *testing.T, value string) (out time.Time) {
	t.Helper()
	var err error
	out, err = time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return
}
