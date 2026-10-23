package officialminecraft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Client, *httptest.Server, *[]string) {
	t.Helper()
	calls := []string{}
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/devicecode":
			if r.FormValue("scope") != "XboxLive.signin offline_access" {
				t.Errorf("scope mismatch")
			}
			io.WriteString(w, `{"device_code":"dsecret","user_code":"ABCD","verification_uri":"https://microsoft.com/link","expires_in":900,"interval":5}`)
		case "/token":
			if r.FormValue("grant_type") == "urn:ietf:params:oauth:grant-type:device_code" && r.FormValue("device_code") == "pending" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"authorization_pending"}`)
				return
			}
			io.WriteString(w, `{"access_token":"ms-secret","refresh_token":"refresh-secret","expires_in":3600,"token_type":"Bearer"}`)
		case "/user/authenticate":
			var p struct{ Properties struct{ RpsTicket string } }
			_ = json.NewDecoder(r.Body).Decode(&p)
			if p.Properties.RpsTicket != "d=ms-secret" {
				t.Errorf("unexpected Xbox RPS ticket")
			}
			io.WriteString(w, `{"Token":"xbl","DisplayClaims":{"xui":[{"uhs":"user-hash"}]}}`)
		case "/xsts/authorize":
			io.WriteString(w, `{"Token":"xsts","DisplayClaims":{"xui":[{"uhs":"user-hash"}]}}`)
		case "/authentication/login_with_xbox":
			var p struct{ IdentityToken string }
			_ = json.NewDecoder(r.Body).Decode(&p)
			if p.IdentityToken != "XBL3.0 x=user-hash;xsts" {
				t.Errorf("unexpected Minecraft identity token")
			}
			io.WriteString(w, `{"access_token":"minecraft-secret","token_type":"Bearer","expires_in":7200}`)
		case "/entitlements/mcstore":
			if r.Header.Get("Authorization") != "Bearer minecraft-secret" {
				t.Error("wrong entitlement bearer")
			}
			io.WriteString(w, `{"items":[{"name":"product_minecraft"}]}`)
		case "/minecraft/profile":
			if r.Header.Get("Authorization") != "Bearer minecraft-secret" {
				t.Errorf("missing minecraft bearer")
			}
			io.WriteString(w, `{"id":"123456781234123412341234567890ab","name":"RealOwner","skins":[{"id":"skin0","state":"ACTIVE","variant":"CLASSIC"}],"capes":[{"id":"mine","state":"ACTIVE"}]}`)
		case "/minecraft/profile/capes/active":
			if r.Method == "PUT" {
				var p struct {
					CapeID string `json:"capeId"`
				}
				json.NewDecoder(r.Body).Decode(&p)
				if p.CapeID != "mine" {
					t.Errorf("wrong cape ID")
				}
			}
			if r.Method == "DELETE" {
				w.WriteHeader(204)
				return
			}
			io.WriteString(w, `{"id":"123456781234123412341234567890ab","name":"RealOwner"}`)
		case "/minecraft/profile/skins":
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
				t.Errorf("missing multipart")
			}
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				t.Error(err)
			}
			if r.FormValue("variant") != "slim" {
				t.Errorf("wrong skin model")
			}
			f, _, e := r.FormFile("file")
			if e != nil {
				t.Error(e)
			} else {
				head := make([]byte, 8)
				io.ReadFull(f, head)
				if !bytes.Equal(head, []byte("\x89PNG\r\n\x1a\n")) {
					t.Error("wrong PNG")
				}
				f.Close()
			}
			io.WriteString(w, `{"id":"123456781234123412341234567890ab","name":"RealOwner"}`)
		case "/minecraft/profile/skins/active":
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(handler)
	c := New()
	c.microsoft = srv.URL
	c.xbox = srv.URL
	c.xsts = srv.URL
	c.minecraft = srv.URL
	return c, srv, &calls
}
func TestFullOfficialAuthAndOperations(t *testing.T) {
	c, srv, _ := fixture(t)
	defer srv.Close()
	ctx := context.Background()
	code, err := c.Begin(ctx, "client")
	if err != nil || code.UserCode != "ABCD" {
		t.Fatalf("device code: %+v %v", code, err)
	}
	_, err = c.Complete(ctx, "client", "pending")
	if !errors.Is(err, ErrPending) {
		t.Fatalf("expected pending: %v", err)
	}
	ms, err := c.Complete(ctx, "client", "dsecret")
	if err != nil {
		t.Fatal(err)
	}
	mc, err := c.Exchange(ctx, ms.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Profile(ctx, mc.AccessToken)
	if err != nil || p.ID != "123456781234123412341234567890ab" {
		t.Fatalf("profile %+v %v", p, err)
	}
	if _, err = c.SelectCape(ctx, mc.AccessToken, "not-mine"); err == nil {
		t.Fatal("unowned cape selected")
	}
	if _, err = c.SelectCape(ctx, mc.AccessToken, "mine"); err != nil {
		t.Fatal(err)
	}
	if err = c.ResetCape(ctx, mc.AccessToken); err != nil {
		t.Fatal(err)
	}
	if err = c.ResetSkin(ctx, mc.AccessToken); err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), []byte("sample")...)
	if _, err = c.UploadSkin(ctx, mc.AccessToken, "slim", png); err != nil {
		t.Fatal(err)
	}
	if _, err = c.UploadSkin(ctx, mc.AccessToken, "invalid", png); err == nil {
		t.Fatal("invalid variant accepted")
	}
	refreshed, err := c.Refresh(ctx, "client", ms.RefreshToken)
	if err != nil || refreshed.RefreshToken == "" {
		t.Fatalf("refresh: %+v %v", refreshed, err)
	}
}
func TestRedirectNotFollowedAndSizeBound(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("redirect followed") }))
	defer evil.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL, http.StatusFound) }))
	defer server.Close()
	c := New()
	c.microsoft = server.URL
	if _, err := c.Begin(context.Background(), "client"); err == nil {
		t.Fatal("redirect accepted")
	}
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("x"), maxResponse+1)) }))
	defer huge.Close()
	c.microsoft = huge.URL
	if _, err := c.Begin(context.Background(), "client"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("unbounded response %v", err)
	}
}
func TestMicrosoftVerificationHostRestricted(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"device_code":"a","user_code":"b","verification_uri":"https://evil.example/","expires_in":100}`)
	}))
	defer s.Close()
	c := New()
	c.microsoft = s.URL
	if _, err := c.Begin(context.Background(), "id"); err == nil {
		t.Fatal("untrusted verification uri")
	}
}
func TestHTTPTimeoutConfigured(t *testing.T) {
	if New().http.Timeout > 20*time.Second {
		t.Fatal("timeout too long")
	}
}

func TestPKCEAuthorizationCodeExchangeAndEntitlements(t *testing.T) {
	clientID := "4b8f7734-4f10-44ca-b870-b4d89d34a319"
	c, srv, _ := fixture(t)
	defer srv.Close()
	redirect := "http://localhost:62481/minecraft-poc/callback"
	verifier := strings.Repeat("A", 64)
	challenge, err := PKCEChallenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := c.AuthorizationURL(clientID, redirect, strings.Repeat("B", 43), challenge)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge") != challenge || q.Get("code_challenge_method") != "S256" || q.Get("scope") != "XboxLive.signin offline_access" || q.Get("redirect_uri") != redirect || q.Get("response_type") != "code" {
		t.Fatalf("unexpected authorization request: %s", authURL)
	}
	tokens, err := c.ExchangeAuthorizationCode(context.Background(), clientID, redirect, "valid-code", verifier)
	if err != nil || tokens.AccessToken != "ms-secret" {
		t.Fatalf("code exchange: %v", err)
	}
	if count, err := c.EntitlementCount(context.Background(), "minecraft-secret"); err != nil || count != 1 {
		t.Fatalf("entitlements: count=%d err=%v", count, err)
	}
}

func TestRejectUntrustedPKCEInputs(t *testing.T) {
	c := New()
	for _, bad := range []string{"", "00000000-0000-0000-0000-000000000000", "microsoft-id", "${CLIENT_ID}"} {
		if err := ValidateClientID(bad); err == nil {
			t.Errorf("accepted client ID %q", bad)
		}
	}
	for _, bad := range []string{"https://localhost:1000/minecraft-poc/callback", "http://example.org:1000/minecraft-poc/callback", "http://127.0.0.1:1000/evil", "http://localhost:1000/minecraft-poc/callback?code=secret", "http://evil@localhost:1000/minecraft-poc/callback", "http://0.0.0.0:1000/minecraft-poc/callback"} {
		if err := ValidateLoopbackRedirect(bad); err == nil {
			t.Errorf("accepted redirect %q", bad)
		}
	}
	if _, err := PKCEChallenge("too-short"); err == nil {
		t.Fatal("accepted short verifier")
	}
	if _, err := c.AuthorizationURL("4b8f7734-4f10-44ca-b870-b4d89d34a319", "http://localhost:1/minecraft-poc/callback", "short", strings.Repeat("a", 43)); err == nil {
		t.Fatal("accepted short state")
	}
}

func TestMinecraftRegistrationRejectionCodeIsSanitized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"errorMessage":"Invalid app registration. https://aka.ms/AppRegInfo"}`)
	}))
	defer srv.Close()
	c := New()
	c.minecraft = srv.URL
	_, err := c.EntitlementCount(context.Background(), "redacted")
	var serviceErr *ServiceError
	if !errors.As(err, &serviceErr) || serviceErr.Code != "invalid_app_registration" {
		t.Fatalf("want safe classified rejection, got %v", err)
	}
}
