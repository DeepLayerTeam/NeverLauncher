package oidcconnector

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

func TestOIDCConnectorAuthorizationCodePKCEAndIDTokenValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	expectedNonce := strings.Repeat("n", 43)
	expectedChallenge := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSONTest(w, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "userinfo_endpoint": issuer + "/userinfo", "jwks_uri": issuer + "/jwks", "token_endpoint_auth_methods_supported": []string{"none"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			e := big.NewInt(int64(key.PublicKey.E)).Bytes()
			writeJSONTest(w, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "kid-1", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", 400)
				return
			}
			verifier := r.Form.Get("code_verifier")
			sum := sha256.Sum256([]byte(verifier))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != expectedChallenge {
				http.Error(w, "pkce mismatch", 400)
				return
			}
			accessHash := sha256.Sum256([]byte("access-1"))
			atHash := base64.RawURLEncoding.EncodeToString(accessHash[:len(accessHash)/2])
			idToken := signRS256Test(t, key, "kid-1", map[string]any{"iss": issuer, "sub": "user-42", "aud": "client-1", "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": expectedNonce, "at_hash": atHash, "email": "player@example.test", "email_verified": true, "preferred_username": "player", "name": "OIDC Player", "groups": []string{"vip"}, "amr": []string{"pwd", "mfa"}})
			writeJSONTest(w, map[string]any{"access_token": "access-1", "token_type": "Bearer", "refresh_token": "refresh-1", "expires_in": 300, "id_token": idToken})
		case "/userinfo":
			writeJSONTest(w, map[string]any{"sub": "user-42", "roles": []string{"member"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(server.URL)
	c, err := New(context.Background(), Config{ID: "oidc-test", Issuer: issuer, ClientID: "client-1", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://launcher.example.test/callback"}, HostAllowlist: []string{parsed.Hostname()}, AllowedCIDRs: []string{"127.0.0.1/32", "::1/128"}, CAFile: caPath, UserInfoMode: "required", RequireVerifiedEmail: true, AllowedIDTokenAlgs: []string{"RS256"}, Provisioning: ProvisioningConfig{Mode: "jit", DefaultRole: "player"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	expectedChallenge = base64.RawURLEncoding.EncodeToString(sum[:])
	start, err := c.BeginBrowserAuth(context.Background(), authconnector.BrowserAuthRequest{RedirectURI: "https://launcher.example.test/callback", State: strings.Repeat("s", 43), Nonce: expectedNonce, PKCEChallenge: expectedChallenge})
	if err != nil {
		t.Fatal(err)
	}
	authURL, _ := url.Parse(start.AuthorizationURL)
	q := authURL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") != expectedNonce || q.Get("state") != strings.Repeat("s", 43) {
		t.Fatalf("unexpected authorization URL: %s", start.AuthorizationURL)
	}
	auth, err := c.CompleteBrowserAuth(context.Background(), authconnector.BrowserAuthCallback{RedirectURI: "https://launcher.example.test/callback", Code: "code-1", State: strings.Repeat("s", 43), Nonce: expectedNonce, PKCEVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Identity.Subject != "user-42" || auth.Identity.Email != "player@example.test" || auth.Identity.DisplayName != "OIDC Player" || auth.ProviderToken != "refresh-1" {
		t.Fatalf("unexpected auth: %+v", auth)
	}
	if len(auth.Identity.Roles) != 1 || auth.Identity.Roles[0] != "member" {
		t.Fatalf("userinfo claims not merged: %+v", auth.Identity)
	}
	if strings.Join(auth.AuthMethods, ",") != "pwd,mfa" {
		t.Fatalf("unexpected amr: %v", auth.AuthMethods)
	}
	if _, err := c.CompleteBrowserAuth(context.Background(), authconnector.BrowserAuthCallback{RedirectURI: "https://launcher.example.test/callback", Code: "code-2", State: strings.Repeat("s", 43), Nonce: "wrong-" + expectedNonce, PKCEVerifier: verifier}); err == nil {
		t.Fatal("expected nonce validation failure")
	}
}

func TestOIDCNormalizeRejectsUnsafeConfiguration(t *testing.T) {
	_, err := Normalize(Config{ID: "bad", Issuer: "http://idp.example.test", ClientID: "client", RedirectURIs: []string{"https://app.example/cb"}, TokenEndpointAuthMethod: "none"})
	if err == nil {
		t.Fatal("expected non-HTTPS issuer rejection")
	}
	_, err = Normalize(Config{ID: "bad", Issuer: "https://idp.example.test", ClientID: "client", RedirectURIs: []string{"https://app.example/cb"}, TokenEndpointAuthMethod: "none", AllowedIDTokenAlgs: []string{"none"}})
	if err == nil {
		t.Fatal("expected alg none rejection")
	}
	_, err = Normalize(Config{ID: "bad", Issuer: "https://idp.example.test", ClientID: "client", RedirectURIs: []string{"https://app.example/cb"}, TokenEndpointAuthMethod: "client_secret_basic"})
	if err == nil {
		t.Fatal("expected missing client secret rejection")
	}
}

func signRS256Test(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func writeJSONTest(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestJWTRejectsAudienceAndIssuerMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := RuntimeConfig{Config: Config{Issuer: "https://issuer.example", ClientID: "client", AllowedIDTokenAlgs: []string{"RS256"}}, ClockSkewValue: time.Minute, allowedIDTokenAlgSet: map[string]struct{}{"RS256": {}}}
	e := big.NewInt(int64(key.PublicKey.E)).Bytes()
	keys := []jwk{{Kty: "RSA", Kid: "k", Use: "sig", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(e)}}
	base := map[string]any{"iss": cfg.Issuer, "sub": "u", "aud": cfg.ClientID, "exp": time.Now().Add(time.Minute).Unix(), "nonce": "n"}
	raw := signRS256Test(t, key, "k", base)
	if _, err := verifyIDToken(raw, keys, cfg, "n", true); err != nil {
		t.Fatal(err)
	}
	base["aud"] = "other"
	raw = signRS256Test(t, key, "k", base)
	if _, err := verifyIDToken(raw, keys, cfg, "n", true); err == nil {
		t.Fatal("expected audience mismatch")
	}
	base["aud"] = cfg.ClientID
	base["iss"] = "https://evil.example"
	raw = signRS256Test(t, key, "k", base)
	if _, err := verifyIDToken(raw, keys, cfg, "n", true); err == nil {
		t.Fatal("expected issuer mismatch")
	}
}
