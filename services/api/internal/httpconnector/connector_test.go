package httpconnector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

const fixtureSecret = "0123456789abcdef0123456789abcdef-fixture"

func TestHTTPConnectorProductionFlow(t *testing.T) {
	t.Setenv("NL_HTTP_TEST_SECRET", fixtureSecret)
	mux := http.NewServeMux()
	fixture := func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if !verifyFixtureRequest(r, body) {
			t.Errorf("request signature invalid for %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req requestEnvelope
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				t.Error(err)
				return
			}
			if req.ProtocolVersion != protocolVersion || req.RequestID == "" {
				t.Errorf("invalid request envelope: %+v", req)
			}
		}
		switch r.URL.Path {
		case "/health":
			writeFixtureSigned(w, r, http.StatusOK, healthResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Status: "ok"})
		case "/authenticate":
			if req.Identifier != "player@example.test" || req.Password != "secret" {
				writeFixtureSigned(w, r, http.StatusUnauthorized, remoteErrorResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Error: remoteError{Code: "invalid_credentials"}})
				return
			}
			expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			writeFixtureSigned(w, r, http.StatusOK, identityResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Subject: "user-42", Username: "player", Email: "player@example.test", DisplayName: "Player", Groups: []string{"vip"}, Roles: []string{"member"}, Claims: map[string]any{"region": "eu"}, AuthMethods: []string{"password"}, ProviderToken: "provider-refresh-secret", ExpiresAt: &expires})
		case "/resolve":
			writeFixtureSigned(w, r, http.StatusOK, identityResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Subject: req.Subject, Email: "player@example.test"})
		case "/refresh":
			if req.ProviderToken != "provider-refresh-secret" {
				t.Errorf("provider token lost: %q", req.ProviderToken)
			}
			writeFixtureSigned(w, r, http.StatusOK, identityResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Subject: "user-42", Email: "player@example.test", ProviderToken: "provider-refresh-rotated"})
		case "/logout":
			writeFixtureSigned(w, r, http.StatusOK, actionResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Status: "revoked"})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			writeFixtureSigned(w, r, http.StatusNotFound, remoteErrorResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Error: remoteError{Code: "identity_not_found"}})
		}
	}
	mux.HandleFunc("/health", fixture)
	mux.HandleFunc("/authenticate", fixture)
	mux.HandleFunc("/resolve", fixture)
	mux.HandleFunc("/refresh", fixture)
	mux.HandleFunc("/logout", fixture)
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	connector := newFixtureConnector(t, server)
	defer connector.Close()

	auth, err := connector.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "player@example.test", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Identity.Subject != "user-42" || auth.Identity.Email != "player@example.test" || auth.ProviderToken != "provider-refresh-secret" {
		t.Fatalf("unexpected auth result: %+v", auth)
	}
	if len(auth.Identity.Groups) != 1 || len(auth.Identity.Roles) != 1 {
		t.Fatalf("mapping lost: %+v", auth.Identity)
	}

	resolved, err := connector.ResolveIdentity(context.Background(), authconnector.ResolveRequest{Subject: "user-42"})
	if err != nil || resolved.Subject != "user-42" {
		t.Fatalf("resolve failed: %+v err=%v", resolved, err)
	}
	refreshed, err := connector.Refresh(context.Background(), auth.ProviderToken)
	if err != nil || refreshed.ProviderToken != "provider-refresh-rotated" {
		t.Fatalf("refresh failed: %+v err=%v", refreshed, err)
	}
	if err := connector.Revoke(context.Background(), authconnector.RevokeRequest{Subject: "user-42", ProviderToken: refreshed.ProviderToken}); err != nil {
		t.Fatal(err)
	}

	_, err = connector.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "player@example.test", Secret: "wrong"})
	if authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestHTTPConnectorRejectsBadSignatureAndSubjectChange(t *testing.T) {
	t.Setenv("NL_HTTP_TEST_SECRET", fixtureSecret)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		if r.URL.Path == "/health" {
			writeFixtureSigned(w, r, http.StatusOK, healthResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Status: "ok"})
			return
		}
		if r.URL.Path == "/resolve" {
			writeFixtureSigned(w, r, http.StatusOK, identityResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Subject: "different-subject"})
			return
		}
		body, _ := json.Marshal(identityResponse{ProtocolVersion: protocolVersion, Issuer: "fixture-issuer", Subject: "user-42"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(headerKeyID, "fixture-key")
		w.Header().Set(headerTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
		w.Header().Set(headerNonce, r.Header.Get(headerNonce))
		w.Header().Set(headerSignature, "v1="+strings.Repeat("00", sha256.Size))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	connector := newFixtureConnector(t, server)
	defer connector.Close()
	_, err := connector.AuthenticatePassword(context.Background(), authconnector.PasswordRequest{Identifier: "x", Secret: "x"})
	if authconnector.CodeOf(err) != authconnector.ErrUnavailable {
		t.Fatalf("bad signature should fail unavailable, got %v", err)
	}
	_, err = connector.ResolveIdentity(context.Background(), authconnector.ResolveRequest{Subject: "user-42"})
	if authconnector.CodeOf(err) != authconnector.ErrMisconfigured {
		t.Fatalf("subject change must fail closed, got %v", err)
	}
}

func TestSSRFSafeDialerRejectsPrivateByDefault(t *testing.T) {
	cfg := RuntimeConfig{Config: Config{HostAllowlist: []string{"127.0.0.1"}}}
	d := ssrfSafeDialer{cfg: cfg}
	if err := d.validateIP(net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("loopback accepted without explicit CIDR")
	}
	_, cidr, _ := net.ParseCIDR("127.0.0.1/32")
	d.cfg.ParsedAllowedCIDRs = []*net.IPNet{cidr}
	if err := d.validateIP(net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("explicit allow CIDR rejected: %v", err)
	}
	if err := d.validateIP(net.ParseIP("169.254.169.254")); err == nil {
		t.Fatal("metadata/link-local address accepted")
	}
}

func TestNormalizeRequiresHTTPSHMACAndSafeEndpoints(t *testing.T) {
	t.Setenv("NL_HTTP_TEST_SECRET", fixtureSecret)
	base := Config{ID: "cms", BaseURL: "https://auth.example.com", Issuer: "cms", HMAC: HMACConfig{SecretEnv: "NL_HTTP_TEST_SECRET"}}
	if _, err := Normalize(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := base
	bad.BaseURL = "http://auth.example.com"
	if _, err := Normalize(bad); err == nil {
		t.Fatal("plaintext HTTP accepted")
	}
	bad = base
	bad.HMAC = HMACConfig{}
	if _, err := Normalize(bad); err == nil {
		t.Fatal("unsigned provider accepted")
	}
	bad = base
	bad.Endpoints.Authenticate = "https://evil.example/authenticate"
	if _, err := Normalize(bad); err == nil {
		t.Fatal("absolute endpoint URL accepted")
	}
	bad = base
	bad.HostAllowlist = []string{"other.example.com"}
	if _, err := Normalize(bad); err == nil {
		t.Fatal("base host outside allowlist accepted")
	}
}

func newFixtureConnector(t *testing.T, server *httptest.Server) *Connector {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cert := server.Certificate()
	if cert == nil {
		t.Fatal("fixture TLS certificate missing")
	}
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// Verify the fixture really is a certificate before passing it to connector TLS roots.
	if _, err := x509.ParseCertificate(cert.Raw); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ID: "fixture-http", DisplayName: "Fixture HTTP", BaseURL: server.URL, Issuer: "fixture-issuer",
		HostAllowlist: []string{parsed.Hostname()}, AllowedCIDRs: []string{"127.0.0.1/32", "::1/128"},
		HMAC: HMACConfig{KeyID: "fixture-key", SecretEnv: "NL_HTTP_TEST_SECRET", MaxClockSkew: "2m"},
		MTLS: MTLSConfig{CAFile: caPath}, Provisioning: ProvisioningConfig{Mode: "jit", DefaultRole: "player"},
	}
	connector, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return connector
}

func verifyFixtureRequest(r *http.Request, body []byte) bool {
	timestamp := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	provided, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get(headerSignature), "v1="))
	if err != nil || timestamp == "" || nonce == "" || r.Header.Get(headerKeyID) != "fixture-key" || r.Header.Get(headerConnectorID) != "fixture-http" {
		return false
	}
	expected := sign([]byte(fixtureSecret), requestCanonical(r.Method, r.URL.EscapedPath(), timestamp, nonce, body))
	return hmac.Equal(expected, provided)
}

func writeFixtureSigned(w http.ResponseWriter, r *http.Request, status int, value any) {
	body, _ := json.Marshal(value)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonce := r.Header.Get(headerNonce)
	signature := sign([]byte(fixtureSecret), responseCanonical(status, timestamp, nonce, body))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(headerKeyID, "fixture-key")
	w.Header().Set(headerTimestamp, timestamp)
	w.Header().Set(headerNonce, nonce)
	w.Header().Set(headerSignature, "v1="+hex.EncodeToString(signature))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func TestResponseReplayAndTimestampWindowAreRejected(t *testing.T) {
	t.Setenv("NL_HTTP_TEST_SECRET", fixtureSecret)
	cfg, err := Normalize(Config{ID: "fixture", BaseURL: "https://auth.example.com", Issuer: "issuer", HMAC: HMACConfig{KeyID: "fixture-key", SecretEnv: "NL_HTTP_TEST_SECRET", MaxClockSkew: "30s"}})
	if err != nil {
		t.Fatal(err)
	}
	client := newSignedClient(cfg, &http.Client{})
	body := []byte(`{"protocolVersion":"neverlauncher-http-auth/1","issuer":"issuer","status":"ok"}`)
	nonce := "0123456789abcdef"
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	response.Header.Set(headerKeyID, "fixture-key")
	response.Header.Set(headerTimestamp, stamp)
	response.Header.Set(headerNonce, nonce)
	response.Header.Set(headerSignature, "v1="+hex.EncodeToString(sign([]byte(fixtureSecret), responseCanonical(http.StatusOK, stamp, nonce, body))))
	if err := client.verifyResponse(response, nonce, body); err != nil {
		t.Fatalf("first signed response rejected: %v", err)
	}
	if err := client.verifyResponse(response, nonce, body); authconnector.CodeOf(err) != authconnector.ErrUnavailable {
		t.Fatalf("replayed response accepted: %v", err)
	}

	oldNonce := "fedcba9876543210"
	oldStamp := strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10)
	old := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	old.Header.Set(headerKeyID, "fixture-key")
	old.Header.Set(headerTimestamp, oldStamp)
	old.Header.Set(headerNonce, oldNonce)
	old.Header.Set(headerSignature, "v1="+hex.EncodeToString(sign([]byte(fixtureSecret), responseCanonical(http.StatusOK, oldStamp, oldNonce, body))))
	if err := client.verifyResponse(old, oldNonce, body); authconnector.CodeOf(err) != authconnector.ErrUnavailable {
		t.Fatalf("stale response accepted: %v", err)
	}
}
