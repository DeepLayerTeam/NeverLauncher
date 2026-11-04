package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseSigningRejectsInconsistentEd25519Key0428(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private.key")
	modified := bytes.Clone(private)
	modified[len(modified)-1] ^= 0x40
	if err = os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(modified)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadEd25519PrivateKey(path); err == nil {
		t.Fatal("accepted tampered private/public key pair")
	}
	if err = os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(private)), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadEd25519PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, private) {
		t.Fatal("normal private key changed")
	}
}
func TestReleaseDetachedSignatureRemainsVerified0428(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "provenance.json")
	sig := file + ".sig"
	if err = os.WriteFile(file, []byte(`{"commit":"example"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = signDetachedFileWithKey(file, sig, private); err != nil {
		t.Fatal(err)
	}
	if err = verifyDetachedFileWithKey(file, sig, pub); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte(`{"commit":"altered"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = verifyDetachedFileWithKey(file, sig, pub); err == nil {
		t.Fatal("accepted modified provenance")
	}
}
