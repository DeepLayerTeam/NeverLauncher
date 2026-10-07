package httpapi

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

const p1TestSigningSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestSignManifestProducesVerifiedEd25519Signature(t *testing.T) {
	s := Server{Config: config.Config{Environment: "production", ManifestSigningPrivateKey: p1TestSigningSeed}, State: NewRuntimeState()}
	manifest := model.Manifest{SchemaVersion: "1.0", ProjectID: "demo-project", ProfileID: "vanilla", Channel: "stable", Version: "0.21.2-test", Files: []model.ManifestFile{{Path: "libraries/fixture.jar", Size: 7, SHA256: "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5", Required: true}}}

	signed, err := s.signManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Signature == nil {
		t.Fatal("signed manifest must contain signature")
	}
	publicKey, err := hex.DecodeString(signed.Signature.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(signed.Signature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := signed
	unsigned.Signature = nil
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, sig) {
		t.Fatal("manifest signature is invalid")
	}
}

func TestSignManifestFailsClosedWithInvalidProductionKey(t *testing.T) {
	s := Server{Config: config.Config{Environment: "production", ManifestSigningPrivateKey: "not-a-key"}, State: NewRuntimeState()}
	if _, err := s.signManifest(model.Manifest{SchemaVersion: "1.0", ProjectID: "demo-project", ProfileID: "vanilla", Channel: "stable", Version: "0.21.2-test"}); err == nil {
		t.Fatal("signing must fail when production key is invalid")
	}
}
