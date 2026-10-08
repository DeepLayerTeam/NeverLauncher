package microsoftconnector

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

const (
	testTenantID = "11111111-2222-3333-4444-555555555555"
	testObjectID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testClientID = "99999999-8888-7777-6666-555555555555"
)

func TestMicrosoftConnectorAuthorizationCodePKCEMultitenantAndRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	expectedNonce := strings.Repeat("n", 43)
	expectedChallenge := ""
	var authority string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/common/v2.0/.well-known/openid-configuration":
			writeMicrosoftJSONTest(w, map[string]any{
				"issuer": authority + "/{tenantid}/v2.0", "authorization_endpoint": authority + "/authorize", "token_endpoint": authority + "/token",
				"jwks_uri": authority + "/jwks", "end_session_endpoint": authority + "/logout", "token_endpoint_auth_methods_supported": []string{"none"}, "id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			e := big.NewInt(int64(key.PublicKey.E)).Bytes()
			writeMicrosoftJSONTest(w, map[string]any{"keys": []any{map[string]any{
				"kty": "RSA", "kid": "microsoft-kid", "use": "sig", "alg": "RS256", "issuer": authority + "/{tenantid}/v2.0",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e),
			}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != testClientID {
				http.Error(w, "client mismatch", http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") == "authorization_code" {
				verifier := r.Form.Get("code_verifier")
				sum := sha256.Sum256([]byte(verifier))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != expectedChallenge {
					http.Error(w, "pkce mismatch", http.StatusBadRequest)
					return
				}
				writeMicrosoftJSONTest(w, microsoftTokenResponseTest(t, key, authority, expectedNonce, "refresh-1"))
				return
			}
			if r.Form.Get("grant_type") == "refresh_token" && r.Form.Get("refresh_token") == "refresh-1" {
				writeMicrosoftJSONTest(w, microsoftTokenResponseTest(t, key, authority, "", "refresh-2"))
				return
			}
			http.Error(w, "unexpected grant", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	authority = server.URL
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	connector, err := New(context.Background(), Config{
		ID: "microsoft", Cloud: "custom", AuthorityURL: authority, AllowCustomAuthority: true, Tenant: "common", ClientID: testClientID,
		RedirectURIs: []string{"https://launcher.example.test/callback"}, PostLogoutRedirectURIs: []string{"https://launcher.example.test/signed-out"},
		AllowedTenantIDs: []string{testTenantID}, AllowedCIDRs: []string{"127.0.0.1/32", "::1/128"}, CAFile: caPath,
		Provisioning: ProvisioningConfig{Mode: "jit", DefaultRole: "player"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	expectedChallenge = base64.RawURLEncoding.EncodeToString(sum[:])
	start, err := connector.BeginBrowserAuth(context.Background(), authconnector.BrowserAuthRequest{
		RedirectURI: "https://launcher.example.test/callback", State: strings.Repeat("s", 43), Nonce: expectedNonce, PKCEChallenge: expectedChallenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	q := authURL.Query()
	if q.Get("code_challenge_method") != "S256" || !strings.Contains(" "+q.Get("scope")+" ", " offline_access ") {
		t.Fatalf("Microsoft authorization URL lacks PKCE/offline_access: %s", start.AuthorizationURL)
	}
	auth, err := connector.CompleteBrowserAuth(context.Background(), authconnector.BrowserAuthCallback{
		RedirectURI: "https://launcher.example.test/callback", Code: "code", State: strings.Repeat("s", 43), Nonce: expectedNonce, PKCEVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Identity.Subject != strings.ToLower(testTenantID+":"+testObjectID) || auth.ProviderToken != "refresh-1" || auth.Identity.Email != "player@example.test" {
		t.Fatalf("unexpected Microsoft authentication: %+v", auth)
	}
	refreshed, err := connector.Refresh(context.Background(), auth.ProviderToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Identity.Subject != auth.Identity.Subject || refreshed.ProviderToken != "refresh-2" {
		t.Fatalf("unexpected refresh result: %+v", refreshed)
	}
	logout, err := connector.ProviderLogoutURL("https://launcher.example.test/signed-out")
	if err != nil || !strings.Contains(logout, "post_logout_redirect_uri=") {
		t.Fatalf("unexpected logout URL %q err=%v", logout, err)
	}
	if _, err := connector.ProviderLogoutURL("https://evil.example/signed-out"); err == nil {
		t.Fatal("expected unregistered post-logout redirect rejection")
	}
}

func TestMicrosoftIssuerPolicyRejectsTenantAndSigningKeyConfusion(t *testing.T) {
	p := microsoftIssuerPolicy{authorityBase: "https://login.microsoftonline.com", tenant: "common", tenantMode: "common", allowedTenantIDs: map[string]struct{}{testTenantID: {}}}
	claims := map[string]any{"tid": testTenantID, "iss": "https://login.microsoftonline.com/" + testTenantID + "/v2.0"}
	if err := p.ValidateTokenIssuer("https://login.microsoftonline.com/{tenantid}/v2.0", claims, "https://login.microsoftonline.com/{tenantid}/v2.0"); err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{"tid": "22222222-2222-3333-4444-555555555555", "iss": "https://login.microsoftonline.com/22222222-2222-3333-4444-555555555555/v2.0"}
	if err := p.ValidateTokenIssuer("https://login.microsoftonline.com/{tenantid}/v2.0", bad, "https://login.microsoftonline.com/{tenantid}/v2.0"); err == nil {
		t.Fatal("expected tenant allowlist rejection")
	}
	if err := p.ValidateTokenIssuer("https://login.microsoftonline.com/{tenantid}/v2.0", claims, "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"); err == nil {
		t.Fatal("expected signing-key issuer rejection")
	}
}

func TestMicrosoftConfigUsesKnownCloudAuthoritiesAndStableTenantRules(t *testing.T) {
	for cloud, want := range map[string]string{"global": "https://login.microsoftonline.com", "usgov": "https://login.microsoftonline.us", "china": "https://login.partner.microsoftonline.cn"} {
		cfg, err := Normalize(Config{ID: "ms-" + cloud, Cloud: cloud, Tenant: testTenantID, ClientID: testClientID, RedirectURIs: []string{"https://launcher.example/cb"}})
		if err != nil {
			t.Fatalf("%s: %v", cloud, err)
		}
		if cfg.AuthorityBase != want {
			t.Fatalf("%s authority=%q want=%q", cloud, cfg.AuthorityBase, want)
		}
	}
	if _, err := Normalize(Config{ID: "bad", Cloud: "global", Tenant: "contoso.onmicrosoft.com", ClientID: testClientID, RedirectURIs: []string{"https://launcher.example/cb"}}); err == nil {
		t.Fatal("expected mutable tenant-domain rejection")
	}
}

func microsoftTokenResponseTest(t *testing.T, key *rsa.PrivateKey, authority, nonce, refresh string) map[string]any {
	t.Helper()
	claims := map[string]any{
		"iss": authority + "/" + testTenantID + "/v2.0", "sub": "pairwise-subject", "tid": testTenantID, "oid": testObjectID,
		"aud": testClientID, "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "preferred_username": "player@example.test", "email": "player@example.test", "name": "Microsoft Player", "amr": []string{"pwd", "mfa"},
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return map[string]any{"access_token": "access-token", "token_type": "Bearer", "refresh_token": refresh, "expires_in": 300, "id_token": signMicrosoftRS256Test(t, key, claims)}
}

func signMicrosoftRS256Test(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "microsoft-kid", "typ": "JWT"})
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

func writeMicrosoftJSONTest(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
