package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testPasskey117 struct {
	key        *ecdsa.PrivateKey
	credential []byte
	userHandle []byte
	rpID       string
	origin     string
}

func registerTestPasskey117(t *testing.T, h http.Handler, token string) (string, testPasskey117) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/register/begin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("passkey begin => %d %s", rr.Code, rr.Body.String())
	}
	var begin struct {
		Data struct {
			TransactionToken string `json:"transactionToken"`
			PublicKey        struct {
				Challenge string `json:"challenge"`
				RP        struct {
					ID string `json:"id"`
				} `json:"rp"`
				User struct {
					ID string `json:"id"`
				} `json:"user"`
			} `json:"publicKey"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(begin.Data.PublicKey.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	userHandle, err := base64.RawURLEncoding.DecodeString(begin.Data.PublicKey.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := make([]byte, 32)
	if _, err := rand.Read(cred); err != nil {
		t.Fatal(err)
	}
	rpID := begin.Data.PublicKey.RP.ID
	if rpID == "" {
		rpID = "example.test"
	}
	origin := "http://example.test"
	client := mustJSON117(t, map[string]any{"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin, "crossOrigin": false})
	authData := registrationAuthData117(t, rpID, cred, key)
	att := cborMap117(
		cborText117("fmt"), cborText117("none"),
		cborText117("attStmt"), []byte{0xa0},
		cborText117("authData"), cborBytes117(authData),
	)
	body := mustJSON117(t, map[string]any{
		"transactionToken": begin.Data.TransactionToken,
		"friendlyName":     "Integration passkey",
		"credential": map[string]any{
			"id":    base64.RawURLEncoding.EncodeToString(cred),
			"rawId": base64.RawURLEncoding.EncodeToString(cred),
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(client),
				"attestationObject": base64.RawURLEncoding.EncodeToString(att),
				"transports":        []string{"internal"},
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/register/complete", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("passkey complete => %d %s", rr.Code, rr.Body.String())
	}
	var complete struct {
		Data struct {
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &complete); err != nil || complete.Data.AccessToken == "" {
		t.Fatalf("passkey access token missing: %v %s", err, rr.Body.String())
	}
	return complete.Data.AccessToken, testPasskey117{key: key, credential: cred, userHandle: userHandle, rpID: rpID, origin: origin}
}

func passkeyLogin117(t *testing.T, h http.Handler, fixture testPasskey117) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/login/begin", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("passkey login begin => %d %s", rr.Code, rr.Body.String())
	}
	var begin struct {
		Data struct {
			TransactionToken string `json:"transactionToken"`
			PublicKey        struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	challenge, _ := base64.RawURLEncoding.DecodeString(begin.Data.PublicKey.Challenge)
	client := mustJSON117(t, map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": fixture.origin, "crossOrigin": false})
	authData := assertionAuthData117(fixture.rpID, 1)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte(nil), authData...), clientHash[:]...)
	signedHash := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, fixture.key, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON117(t, map[string]any{
		"transactionToken": begin.Data.TransactionToken,
		"deviceId":         "passkey-test",
		"credential": map[string]any{
			"id": base64.RawURLEncoding.EncodeToString(fixture.credential), "rawId": base64.RawURLEncoding.EncodeToString(fixture.credential), "type": "public-key",
			"response": map[string]any{
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(client),
				"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
				"signature":         base64.RawURLEncoding.EncodeToString(sig),
				"userHandle":        base64.RawURLEncoding.EncodeToString(fixture.userHandle),
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/login/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("passkey login complete => %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Data struct {
			Tokens struct {
				AccessToken string `json:"accessToken"`
			} `json:"tokens"`
			AuthStrength string `json:"authStrength"`
			Session      struct {
				Provider   string `json:"provider"`
				IdentityID string `json:"identityId"`
			} `json:"session"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Data.Tokens.AccessToken == "" || out.Data.AuthStrength != "phishing-resistant" {
		t.Fatalf("passkey login payload invalid: %v %s", err, rr.Body.String())
	}
	if out.Data.Session.Provider != "passkey" || out.Data.Session.IdentityID != "" {
		t.Fatalf("passwordless passkey must not fabricate local identity: provider=%q identity=%q body=%s", out.Data.Session.Provider, out.Data.Session.IdentityID, rr.Body.String())
	}
	return out.Data.Tokens.AccessToken
}

func TestPasskeyRegistrationAndPasswordlessLogin117(t *testing.T) {
	h := testServer(t)
	passwordToken := loginAdmin(t, h)
	stepped, fixture := registerTestPasskey117(t, h, passwordToken)
	if stepped == passwordToken {
		t.Fatal("step-up must mint a new access token")
	}
	_ = passkeyLogin117(t, h, fixture)
}

func registrationAuthData117(t *testing.T, rpID string, credential []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), rpHash[:]...)
	out = append(out, 0x45) // UP | UV | AT
	out = append(out, 0, 0, 0, 0)
	out = append(out, make([]byte, 16)...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credential)))
	out = append(out, l[:]...)
	out = append(out, credential...)
	x := key.PublicKey.X.FillBytes(make([]byte, 32))
	y := key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose := cborMap117(
		cborInt117(1), cborInt117(2),
		cborInt117(3), cborInt117(-7),
		cborInt117(-1), cborInt117(1),
		cborInt117(-2), cborBytes117(x),
		cborInt117(-3), cborBytes117(y),
	)
	return append(out, cose...)
}
func assertionAuthData117(rpID string, signCount uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, 0x05)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], signCount)
	return append(out, c[:]...)
}
func mustJSON117(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func cborMap117(parts ...[]byte) []byte {
	out := cborHead117(5, uint64(len(parts)/2))
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
func cborText117(s string) []byte {
	b := []byte(s)
	return append(cborHead117(3, uint64(len(b))), b...)
}
func cborBytes117(b []byte) []byte { return append(cborHead117(2, uint64(len(b))), b...) }
func cborInt117(v int64) []byte {
	if v >= 0 {
		return cborHead117(0, uint64(v))
	}
	return cborHead117(1, uint64(-1-v))
}
func cborHead117(major byte, n uint64) []byte {
	prefix := major << 5
	switch {
	case n < 24:
		return []byte{prefix | byte(n)}
	case n <= 255:
		return []byte{prefix | 24, byte(n)}
	case n <= 65535:
		return []byte{prefix | 25, byte(n >> 8), byte(n)}
	default:
		var b [9]byte
		b[0] = prefix | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b[:]
	}
}

func TestPhishingResistantPolicyBlocksSessionUntilPasskey117(t *testing.T) {
	h := testServer(t)
	passwordToken := loginAdmin(t, h)
	stepped, fixture := registerTestPasskey117(t, h, passwordToken)

	policyBody := bytes.NewBufferString(`{"requirement":"phishing-resistant"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/mfa/policy", policyBody)
	req.Header.Set("Authorization", "Bearer "+stepped)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set policy => %d %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"email":"admin@neverlauncher.local","password":"admin","deviceId":"policy-test"}`))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("password login must pause for passkey => %d %s", rr.Code, rr.Body.String())
	}
	var pending struct {
		Data struct {
			TransactionToken string `json:"transactionToken"`
			PublicKey        struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(pending.Data.PublicKey.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	body := signedAssertionBody117(t, pending.Data.TransactionToken, challenge, fixture, 1)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/mfa/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte(`"authStrength":"phishing-resistant"`)) {
		t.Fatalf("passkey MFA continuation => %d %s", rr.Code, rr.Body.String())
	}
}

func signedAssertionBody117(t *testing.T, tx string, challenge []byte, fixture testPasskey117, signCount uint32) []byte {
	t.Helper()
	client := mustJSON117(t, map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": fixture.origin, "crossOrigin": false})
	authData := assertionAuthData117(fixture.rpID, signCount)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte(nil), authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, fixture.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return mustJSON117(t, map[string]any{
		"transactionToken": tx,
		"deviceId":         "mfa-policy-test",
		"credential": map[string]any{
			"id": base64.RawURLEncoding.EncodeToString(fixture.credential), "rawId": base64.RawURLEncoding.EncodeToString(fixture.credential), "type": "public-key",
			"response": map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(client), "authenticatorData": base64.RawURLEncoding.EncodeToString(authData), "signature": base64.RawURLEncoding.EncodeToString(sig), "userHandle": base64.RawURLEncoding.EncodeToString(fixture.userHandle)},
		},
	})
}
