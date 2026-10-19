package prestarter

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

func trustFixture02312(t *testing.T) ([]byte, ed25519.PrivateKey, ed25519.PrivateKey, string) {
	t.Helper()
	_, root, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	policy := TrustPolicy{SchemaVersion: "1.0", Domain: trustPolicyDomain02312, Epoch: 10, IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), Keys: []TrustKey{{ID: "bootstrap-v2", Role: "bootstrap", PublicKey: hex.EncodeToString(signer.Public().(ed25519.PublicKey)), Status: "active", NotBefore: now.Add(-time.Hour).Format(time.RFC3339)}}}
	payload, _ := json.Marshal(policy)
	raw, e := SignedTrustPolicy(payload, root)
	if e != nil {
		t.Fatal(e)
	}
	return raw, root, signer, hex.EncodeToString(root.Public().(ed25519.PublicKey))
}
func TestRootSignedTrustRotationAndRevocation02312(t *testing.T) {
	raw, root, signer, key := trustFixture02312(t)
	dir := t.TempDir()
	p, e := AcceptTrustPolicy(dir, key, raw, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Authorize("bootstrap", "bootstrap-v2", hex.EncodeToString(signer.Public().(ed25519.PublicKey)), time.Now().Add(-time.Minute), time.Now(), true); e != nil {
		t.Fatal(e)
	}
	var envelope TrustPolicyEnvelope
	if e = json.Unmarshal(raw, &envelope); e != nil {
		t.Fatal(e)
	}
	envelope.RootSignature = strings.Repeat("a", 128)
	altered, _ := json.Marshal(envelope)
	if _, _, e = VerifyTrustPolicy(altered, key, time.Now().UTC()); e == nil {
		t.Fatal("bad root signature accepted")
	}
	// The next root-signed epoch revokes the previously active signer.
	p.Epoch++
	p.Keys[0].Status = "revoked"
	_, replacement, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p.Keys = append(p.Keys, TrustKey{ID: "replacement", Role: "bootstrap", PublicKey: hex.EncodeToString(replacement.Public().(ed25519.PublicKey)), Status: "active", NotBefore: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)})
	b, _ := json.Marshal(p)
	newer, e := SignedTrustPolicy(b, root)
	if e != nil {
		t.Fatal(e)
	}
	next, e := AcceptTrustPolicy(dir, key, newer, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if e = next.Authorize("bootstrap", "bootstrap-v2", p.Keys[0].PublicKey, time.Now(), time.Now(), true); e == nil {
		t.Fatal("revoked key authorized")
	}
	if _, e = AcceptTrustPolicy(dir, key, raw, time.Now().UTC()); e == nil {
		t.Fatal("old trust epoch replay accepted")
	}
	if _, e = os.Stat(filepath.Join(dir, "active-policy.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "trust-state.json")); e != nil {
		t.Fatal(e)
	}
}
func TestVerifyOnlyWindowAndFreeze02312(t *testing.T) {
	raw, root, _, key := trustFixture02312(t)
	p, _, e := VerifyTrustPolicy(raw, key, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	p.Keys[0].Status = "verify-only"
	p.Keys[0].VerifyUntil = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	p.Keys = append(p.Keys, TrustKey{ID: "new", Role: "bootstrap", PublicKey: strings.Repeat("7a", 32), Status: "active", NotBefore: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)})
	b, _ := json.Marshal(p)
	raw, e = SignedTrustPolicy(b, root)
	if e != nil {
		t.Fatal(e)
	}
	v, _, e := VerifyTrustPolicy(raw, key, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if e = v.Authorize("bootstrap", p.Keys[0].ID, p.Keys[0].PublicKey, time.Now().Add(-time.Minute), time.Now(), false); e != nil {
		t.Fatal(e)
	}
	if e = v.Authorize("bootstrap", p.Keys[0].ID, p.Keys[0].PublicKey, time.Now().Add(-time.Minute), time.Now().Add(2*time.Hour), false); e == nil {
		t.Fatal("retired signing key accepted past overlap")
	}
	if _, _, e = VerifyTrustPolicy(raw, key, time.Now().Add(25*time.Hour)); e == nil {
		t.Fatal("expired trust policy accepted")
	}
}

func TestDelegatedBootstrapCannotUseRevokedSigner02312(t *testing.T) {
	policyRaw, root, signer, rootHex := trustFixture02312(t)
	policy, _, err := VerifyTrustPolicy(policyRaw, rootHex, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cfg := identityConfig(baseParts())
	cfg.ProfilePublicKey = rootHex
	payload, _ := json.Marshal(cfg)
	signed, err := SignedEnvelopeDelegated(payload, signer, policyRaw, rootHex, "bootstrap-v2")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyEnvelopeWithPolicy(signed, rootHex, &policy); err != nil {
		t.Fatal(err)
	}
	var forged Envelope
	if err = json.Unmarshal(signed, &forged); err != nil {
		t.Fatal(err)
	}
	forged.SignedAt = time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)
	modified, _ := json.Marshal(forged)
	if _, _, err = VerifyEnvelopeWithPolicy(modified, rootHex, &policy); err == nil {
		t.Fatal("unsigned bootstrap metadata accepted")
	}
	if _, _, err = VerifyEnvelope(signed, rootHex); err == nil {
		t.Fatal("v2 config accepted without policy")
	}
	policy.Epoch++
	policy.Keys[0].Status = "revoked"
	_, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy.Keys = append(policy.Keys, TrustKey{ID: "replacement", Role: "bootstrap", PublicKey: hex.EncodeToString(replacement.Public().(ed25519.PublicKey)), Status: "active", NotBefore: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)})
	nextPayload, _ := json.Marshal(policy)
	nextRaw, err := SignedTrustPolicy(nextPayload, root)
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := VerifyTrustPolicy(nextRaw, rootHex, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyEnvelopeWithPolicy(signed, rootHex, &next); err == nil {
		t.Fatal("revoked old bootstrap accepted")
	}
}
