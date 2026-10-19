package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func TestFiniteReleaseVerifyOnlyOverlap02312(t *testing.T) {
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	fp := fingerprintEd255190158(pub)
	signer := releaseTrustKey0158{ID: "retired", Purpose: "release-signing", Algorithm: "Ed25519", PublicKey: hex.EncodeToString(pub), Fingerprint: fp, Status: "verify-only", NotBefore: now.Add(-72 * time.Hour).Format(time.RFC3339Nano), RetiredAt: now.Add(-time.Hour).Format(time.RFC3339Nano), VerifyUntil: now.Add(time.Hour).Format(time.RFC3339Nano)}
	policy := releaseTrustPolicy0158{Keys: []releaseTrustKey0158{signer}}
	if _, e = findTrustedReleaseKey0158(policy, signer.ID, fp, now.Add(-2*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e = findTrustedReleaseKey0158(policy, signer.ID, fp, now.Add(time.Minute)); e == nil {
		t.Fatal("retired signer backdating allowed new signature")
	}
	signer.RetiredAt = now.Add(-72 * time.Hour).Format(time.RFC3339Nano)
	signer.VerifyUntil = now.Add(-70 * time.Hour).Format(time.RFC3339Nano)
	policy.Keys = []releaseTrustKey0158{signer}
	if _, e = findTrustedReleaseKey0158(policy, signer.ID, fp, now.Add(-80*time.Hour)); e == nil {
		t.Fatal("expired verification overlap still trusted")
	}
	signer.Status = "revoked"
	policy.Keys = []releaseTrustKey0158{signer}
	if _, e = findTrustedReleaseKey0158(policy, signer.ID, fp, now.Add(-80*time.Hour)); e == nil {
		t.Fatal("revoked key accepted")
	}
}
