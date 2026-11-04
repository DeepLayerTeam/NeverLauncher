package sqlitepg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"testing"
)

func TestCoreTOTPCryptographicRewrap0474(t *testing.T) {
	coreKey := bytes.Repeat([]byte{0x42}, 32)
	seed := bytes.Repeat([]byte{0x37}, 20)
	sourceBlock, err := aes.NewCipher(coreKey)
	if err != nil {
		t.Fatal(err)
	}
	sourceAEAD, err := cipher.NewGCM(sourceBlock)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, sourceAEAD.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	old := sourceAEAD.Seal(nonce, nonce, seed, []byte("Launcher/TOTP/0.32.3"))
	if _, err = rewrapTOTP0474(old, MFASecrets0474{}); err == nil {
		t.Fatal("accepted missing secrets")
	}
	if _, err = rewrapTOTP0474(old, MFASecrets0474{SQLiteMFAKey: bytes.Repeat([]byte{0x43}, 32), PostgreSQLSecret: "destination-secret"}); err == nil {
		t.Fatal("accepted wrong Core MFA key")
	}
	encrypted, err := rewrapTOTP0474(old, MFASecrets0474{SQLiteMFAKey: coreKey, PostgreSQLSecret: "destination-secret"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	derived := sha256.Sum256([]byte("destination-secret"))
	destinationBlock, err := aes.NewCipher(derived[:])
	if err != nil {
		t.Fatal(err)
	}
	destinationAEAD, err := cipher.NewGCM(destinationBlock)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := destinationAEAD.Open(nil, payload[:destinationAEAD.NonceSize()], payload[destinationAEAD.NonceSize():], []byte("0.10.0"))
	if err != nil {
		t.Fatal(err)
	}
	expected := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	if string(restored) != expected {
		t.Fatalf("MFA seed changed on migration")
	}
}
