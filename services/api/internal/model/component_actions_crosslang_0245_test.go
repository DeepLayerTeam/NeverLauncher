package model

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestGoSignedOptionalActionFixture0245(t *testing.T) {
	b, e := os.ReadFile("../../../../runtime/neverruntime/tests/fixtures/catalog_actions_0245_go_signed.json")
	if e != nil {
		t.Fatal(e)
	}
	var m Manifest
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	if e = ValidateManifestSchema(m); e != nil {
		t.Fatal(e)
	}
	if m.ComponentCatalog.Digest != ComponentCatalogDigest0245(*m.ComponentCatalog) {
		t.Fatal("invalid action digest")
	}
	signed := m.Signature
	if signed == nil {
		t.Fatal("missing signature")
	}
	pk, e := hex.DecodeString(signed.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := hex.DecodeString(signed.Signature)
	if e != nil {
		t.Fatal(e)
	}
	m.Signature = nil
	payload, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	if !ed25519.Verify(pk, payload, sig) {
		t.Fatal("signed optional actions fixture invalid")
	}
}
