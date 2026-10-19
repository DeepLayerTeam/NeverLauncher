package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComponentDelegatedTrust02312(t *testing.T) {
	dir := t.TempDir()
	_, root, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	rootHex := hex.EncodeToString(root.Public().(ed25519.PublicKey))
	oldRoot := componentSetRootKey02312
	componentSetRootKey02312 = rootHex
	t.Cleanup(func() { componentSetRootKey02312 = oldRoot })
	makePolicy := func(epoch uint64, status string) []byte {
		p := TrustPolicy{SchemaVersion: "1.0", Domain: trustPolicyDomain02312, Epoch: epoch, IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), Keys: []TrustKey{{ID: "component-v1", Role: "component", PublicKey: hex.EncodeToString(signer.Public().(ed25519.PublicKey)), Status: status, NotBefore: now.Add(-time.Hour).Format(time.RFC3339)}}}
		if status != "active" {
			p.Keys = append(p.Keys, TrustKey{ID: "component-v2", Role: "component", PublicKey: strings.Repeat("12", 32), Status: "active", NotBefore: now.Add(-time.Hour).Format(time.RFC3339)})
		}
		b, _ := json.Marshal(p)
		signed, e := SignedTrustPolicy(b, root)
		if e != nil {
			t.Fatal(e)
		}
		return signed
	}
	manifest := []byte(`{"productVersion":"0.23.12","securityGeneration":100}`)
	manifestPath := filepath.Join(dir, "COMPONENT_UPDATE_MANIFEST.json")
	if e = os.WriteFile(manifestPath, manifest, 0600); e != nil {
		t.Fatal(e)
	}
	sign := func(policy []byte, epoch uint64) {
		p, digest, e := VerifyTrustPolicy(policy, rootHex, now)
		if e != nil {
			t.Fatal(e)
		}
		if p.Epoch != epoch {
			t.Fatal("fixture epoch")
		}
		h := sha256.Sum256(manifest)
		env := componentSignature02312{SchemaVersion: "2.0", Algorithm: "ed25519", KeyID: "component-v1", TrustEpoch: epoch, PolicySHA256: digest, ManifestSHA256: hex.EncodeToString(h[:]), SignedAt: now.Format(time.RFC3339), Signature: ""}
		env.Signature = hex.EncodeToString(ed25519.Sign(signer, componentTrustSignaturePayload02312(manifest, env)))
		b, _ := json.Marshal(env)
		if e = os.WriteFile(filepath.Join(dir, componentSignatureFile02312), b, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, componentPolicyFile02312), policy, 0600); e != nil {
			t.Fatal(e)
		}
	}
	first := makePolicy(1, "active")
	sign(first, 1)
	if e = verifyComponentTrust02312(manifestPath); e != nil {
		t.Fatal(e)
	}
	rootInstall := filepath.Join(dir, "install")
	if e = acceptComponentTrust02312(rootInstall, manifestPath); e != nil {
		t.Fatal(e)
	}
	// Signed manifest cannot be mixed with modified metadata or an older epoch.
	if e = os.WriteFile(manifestPath, append(manifest, ' '), 0600); e != nil {
		t.Fatal(e)
	}
	if e = verifyComponentTrust02312(manifestPath); e == nil {
		t.Fatal("mix-and-match manifest accepted")
	}
	if e = os.WriteFile(manifestPath, manifest, 0600); e != nil {
		t.Fatal(e)
	}
	revoked := makePolicy(2, "revoked")
	sign(revoked, 2)
	if e = verifyComponentTrust02312(manifestPath); e == nil {
		t.Fatal("revoked component signer accepted")
	}
	// Accepting a newer revocation epoch makes a previously signed older policy
	// permanently unusable, even if its signature itself is still valid.
	if _, e = AcceptTrustPolicy(filepath.Join(rootInstall, ".neverlauncher", "component-trust"), rootHex, revoked, now); e != nil {
		t.Fatal(e)
	}
	sign(first, 1)
	if e = acceptComponentTrust02312(rootInstall, manifestPath); e == nil {
		t.Fatal("old policy replay accepted")
	}
}
