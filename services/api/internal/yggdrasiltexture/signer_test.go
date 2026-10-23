package yggdrasiltexture

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSHA1WithRSASignatureAndPEM0256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS80256(t, key)})
	dir := t.TempDir()
	filename := filepath.Join(dir, "yggdrasil.pem")
	if err := os.WriteFile(filename, p, 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	value := base64.StdEncoding.EncodeToString([]byte(`{"profileId":"abc","textures":{}}`))
	signed, err := signer.SignValue(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyValue(value, signed); err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyValue(value+"A", signed); err == nil {
		t.Fatal("signature must bind exact Base64 payload")
	}
	block, _ := pem.Decode([]byte(signer.PublicPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("invalid public PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum([]byte(value))
	sig, _ := base64.StdEncoding.DecodeString(signed)
	if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA1, digest[:], sig); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(filename); err == nil {
		t.Fatal("exposed private key must be rejected")
	}
}
func mustPKCS80256(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	raw, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestBadKey0256(t *testing.T) {
	if _, err := ParsePrivateKey([]byte("broken")); err == nil {
		t.Fatal("invalid key")
	}
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})); err == nil {
		t.Fatal("weak RSA key accepted")
	}
	k2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k2048)})
	if _, err := ParsePrivateKey(append(pemBytes, []byte("other")...)); err == nil {
		t.Fatal("trailing material accepted")
	}
	if _, err := ParsePrivateKey([]byte(strings.Repeat("x", 1024))); err == nil {
		t.Fatal("garbage accepted")
	}
}
