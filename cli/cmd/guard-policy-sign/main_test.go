package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestKeygenAndOfflineSignature(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private.hex")
	public := filepath.Join(dir, "public.hex")
	if err := keygen(private, public); err != nil {
		t.Fatal(err)
	}
	if err := keygen(private, public); err == nil {
		t.Fatal("key overwrite accepted")
	}
	input := filepath.Join(dir, "policy.json")
	content := []byte(`{"schemaVersion":"launcher.guard-compatibility.v1","epoch":1}`)
	if err := os.WriteFile(input, content, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "signed.json")
	if err := sign(input, private, out); err != nil {
		t.Fatal(err)
	}
	var env struct{ Payload, Signature string }
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	signature, _ := hex.DecodeString(env.Signature)
	rawPub, _ := os.ReadFile(public)
	pub, _ := hex.DecodeString(string(rawPub[:len(rawPub)-1]))
	if !ed25519.Verify(pub, append([]byte(domain), payload...), signature) {
		t.Fatal("signed payload does not verify")
	}
	if err := sign(input, private, out); err == nil {
		t.Fatal("signature overwrote existing output")
	}
}
