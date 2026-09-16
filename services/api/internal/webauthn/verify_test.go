package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestRegistrationAndAssertionES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("01234567890123456789012345678901")
	origin, rpID := "https://launcher.example.test", "example.test"
	credID := []byte("credential-id-012345678901234567890")
	clientCreate := testClientData(t, "webauthn.create", challenge, origin)
	authCreate := testRegistrationAuthData(t, rpID, credID, key)
	attestation := testCBORMap(
		testCBORText("fmt"), testCBORText("none"),
		testCBORText("attStmt"), []byte{0xa0},
		testCBORText("authData"), testCBORBytes(authCreate),
	)
	cfg := VerifyConfig{RPID: rpID, Origins: map[string]struct{}{origin: {}}, Challenge: challenge, RequireUV: true}
	registration, err := VerifyRegistration(cfg, clientCreate, attestation, credID)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if registration.Algorithm != -7 {
		t.Fatalf("algorithm=%d", registration.Algorithm)
	}

	clientGet := testClientData(t, "webauthn.get", challenge, origin)
	authGet := testAssertionAuthData(rpID, 1)
	clientHash := sha256.Sum256(clientGet)
	signed := append(append([]byte(nil), authGet...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := VerifyAssertion(cfg, clientGet, authGet, sig, registration.PublicKeyCOSE, 0, false)
	if err != nil {
		t.Fatalf("assertion failed: %v", err)
	}
	if assertion.SignCount != 1 || !assertion.UserVerified {
		t.Fatalf("unexpected assertion: %+v", assertion)
	}
}

func TestAssertionRejectsReplayAndWrongOrigin(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("01234567890123456789012345678901")
	origin, rpID := "https://launcher.example.test", "example.test"
	cose := testCOSEES256(key)
	auth := testAssertionAuthData(rpID, 5)
	client := testClientData(t, "webauthn.get", challenge, origin)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte(nil), auth...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	cfg := VerifyConfig{RPID: rpID, Origins: map[string]struct{}{origin: {}}, Challenge: challenge, RequireUV: true}
	if _, err := VerifyAssertion(cfg, client, auth, sig, cose, 5, false); err == nil {
		t.Fatal("non-increasing sign counter must be rejected")
	}
	wrong := testClientData(t, "webauthn.get", challenge, "https://evil.example")
	if _, err := VerifyAssertion(cfg, wrong, auth, sig, cose, 0, false); err == nil {
		t.Fatal("wrong origin must be rejected")
	}
}

func TestZeroCounterAuthenticatorIsAllowed(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := []byte("01234567890123456789012345678901")
	origin, rpID := "https://launcher.example.test", "example.test"
	auth := testAssertionAuthData(rpID, 0)
	client := testClientData(t, "webauthn.get", challenge, origin)
	h := sha256.Sum256(client)
	signed := append(append([]byte(nil), auth...), h[:]...)
	d := sha256.Sum256(signed)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
	cfg := VerifyConfig{RPID: rpID, Origins: map[string]struct{}{origin: {}}, Challenge: challenge, RequireUV: true}
	if _, err := VerifyAssertion(cfg, client, auth, sig, testCOSEES256(key), 0, false); err != nil {
		t.Fatalf("zero counter authenticator should be accepted: %v", err)
	}
}

func testClientData(t *testing.T, typ string, challenge []byte, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testRegistrationAuthData(t *testing.T, rpID string, cred []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, 0x45, 0, 0, 0, 0)
	out = append(out, make([]byte, 16)...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(cred)))
	out = append(out, l[:]...)
	out = append(out, cred...)
	return append(out, testCOSEES256(key)...)
}
func testAssertionAuthData(rpID string, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, 0x05)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], count)
	return append(out, c[:]...)
}
func testCOSEES256(key *ecdsa.PrivateKey) []byte {
	x := key.PublicKey.X.FillBytes(make([]byte, 32))
	y := key.PublicKey.Y.FillBytes(make([]byte, 32))
	return testCBORMap(testCBORInt(1), testCBORInt(2), testCBORInt(3), testCBORInt(-7), testCBORInt(-1), testCBORInt(1), testCBORInt(-2), testCBORBytes(x), testCBORInt(-3), testCBORBytes(y))
}
func testCBORMap(parts ...[]byte) []byte {
	out := testCBORHead(5, uint64(len(parts)/2))
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
func testCBORText(s string) []byte {
	b := []byte(s)
	return append(testCBORHead(3, uint64(len(b))), b...)
}
func testCBORBytes(b []byte) []byte { return append(testCBORHead(2, uint64(len(b))), b...) }
func testCBORInt(v int64) []byte {
	if v >= 0 {
		return testCBORHead(0, uint64(v))
	}
	return testCBORHead(1, uint64(-1-v))
}
func testCBORHead(major byte, n uint64) []byte {
	p := major << 5
	switch {
	case n < 24:
		return []byte{p | byte(n)}
	case n <= 255:
		return []byte{p | 24, byte(n)}
	case n <= 65535:
		return []byte{p | 25, byte(n >> 8), byte(n)}
	default:
		var b [9]byte
		b[0] = p | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b[:]
	}
}
