package model

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestGoSignedConditionalCatalogFixture0244(t *testing.T) {
	raw, err := os.ReadFile("../../../../runtime/runtime/tests/fixtures/catalog_conditions_0244_go_signed.json")
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if err = ValidateManifestSchema(m); err != nil {
		t.Fatal(err)
	}
	signature := m.Signature
	if signature == nil {
		t.Fatal("missing signature")
	}
	pub, e1 := hex.DecodeString(signature.PublicKey)
	sig, e2 := hex.DecodeString(signature.Signature)
	if e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	m.Signature = nil
	payload, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	if !ed25519.Verify(pub, payload, sig) {
		t.Fatal("invalid cross-language signed fixture")
	}
	if m.ComponentCatalog.Digest != ComponentCatalogDigest0244(*m.ComponentCatalog) {
		t.Fatal("wrong catalog digest")
	}
}
