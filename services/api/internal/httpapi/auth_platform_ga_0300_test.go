package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/protection"
)

func TestAuthPlatformRejectsAmbiguousMutations0300(t *testing.T) {
	api := testServer(t)
	admin := loginAdmin(t, api)
	admin, _ = registerTestPasskey117(t, api, admin)
	for _, tt := range []struct{ path, body string }{
		{"/api/v1/auth/oidc/local/begin", `{"deviceId":"a","DeviceID":"b"}`},
		{"/api/v1/auth/oidc/local/complete", `{"code":"a","code":"b","state":"a","transaction":"a"}`},
		{"/api/v1/auth/oidc/local/complete", `{"code":"a","state":"a","transaction":"a"}{}`},
		{"/api/v1/auth/oidc/local/begin", `{"redirectUri":"a","unknown":true}`},
	} {
		res := request0211(t, api, http.MethodPost, tt.path, "", tt.body)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous OIDC request: %s => %d %s", tt.path, res.Code, res.Body)
		}
	}
	// Provider linking requires exact password proof even for a signed-in user.
	for _, body := range []string{
		`{"identifier":"external@example.test","Identifier":"other@example.test","password":"some-secret"}`,
		`{"identifier":"external@example.test","password":"some-secret"} {"password":"other"}`,
	} {
		res := request0211(t, api, http.MethodPost, "/api/v1/auth/providers/local/link/password", admin, body)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous password proof accepted: %d %s", res.Code, res.Body)
		}
	}
	current := request0211(t, api, http.MethodGet, "/api/v1/auth/sessions", admin, "")
	if current.Code != http.StatusOK {
		t.Fatalf("unexpected current session: %d %s", current.Code, current.Body)
	}
	for _, body := range []string{
		`{"allExceptCurrent":true,"AllExceptCurrent":false}`,
		`{"allExceptCurrent":true} {"allExceptCurrent":false}`,
		`{"unknown":true}`,
		`not-json`,
		`{ "allExceptCurrent":false, "allExceptCurrent":true }`,
	} {
		res := request0211(t, api, http.MethodPost, "/api/v1/auth/sessions/revoke", admin, body)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("invalid revocation accepted: %q: %d %s", body, res.Code, res.Body)
		}
		still := request0211(t, api, http.MethodGet, "/api/v1/auth/sessions", admin, "")
		if still.Code != http.StatusOK {
			t.Fatalf("invalid request revoked session: %d", still.Code)
		}
	}
	oversized := request0211(t, api, http.MethodPost, "/api/v1/auth/sessions/revoke", admin, `{"allExceptCurrent":false,"pad":"`+strings.Repeat("x", 16*1024)+`"}`)
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unbounded revocation body: %d", oversized.Code)
	}
	// Both destructive Admin mutations must reject duplicates before touching data.
	for _, body := range []string{
		`{"userId":"first","userId":"second"}`,
		`{"userId":"first","UserID":"second"}`,
		`{"userId":"first"}{"userId":"second"}`,
	} {
		res := request0211(t, api, http.MethodPost, "/api/v1/admin/auth/sessions/revoke", admin, body)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("invalid admin revoke accepted: %d %s", res.Code, res.Body)
		}
	}
	created := request0211(t, api, http.MethodPost, "/api/v1/admin/users", admin, `{"email":"ga0300@example.test","displayName":"GA proof","roleId":"player","password":"strong-password-0300"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("could not create test account: %d %s", created.Code, created.Body)
	}
	// Server replies with user ID; all data comes from real Admin user creation.
	var user model.User
	if err := json.Unmarshal(created.Body.Bytes(), &user); err != nil || user.ID == "" {
		t.Fatalf("created user: %v %s", err, created.Body)
	}
	for _, body := range []string{
		`{"reason":"valid reason","Reason":"overriding reason"}`,
		`{"reason":"valid reason"}{"reason":"second"}`,
		`{"reason":"valid reason","expiresAt":null,"expiresAt":null}`,
	} {
		res := request0211(t, api, http.MethodPost, "/api/v1/admin/protection/users/"+user.ID+"/ban", admin, body)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous ban accepted: %d %s", res.Code, res.Body)
		}
	}
	fresh := request0211(t, api, http.MethodPost, "/api/v1/admin/login", "", `{"email":"ga0300@example.test","password":"strong-password-0300"}`)
	if fresh.Code != http.StatusOK {
		t.Fatalf("ambiguous ban mutated account: %d %s", fresh.Code, fresh.Body)
	}
	// Valid ban and revocation remain functional after malformed requests.
	good := request0211(t, api, http.MethodPost, "/api/v1/admin/protection/users/"+user.ID+"/ban", admin, `{"reason":"verified confirmed account compromise"}`)
	if good.Code != http.StatusOK {
		t.Fatalf("valid protection ban failed: %d %s", good.Code, good.Body)
	}
	blocked := request0211(t, api, http.MethodPost, "/api/v1/admin/login", "", `{"email":"ga0300@example.test","password":"strong-password-0300"}`)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("ban failed to block login: %d %s", blocked.Code, blocked.Body)
	}
}

func TestProviderConfigRejectsDuplicateAndNestedAliases0300(t *testing.T) {
	for _, payload := range []string{
		`{"id":"safe","ID":"evil"}`,
		`{"hmac":{"secretEnv":"safe","SecretEnv":"evil"}}`,
		`{"dsnEnv":"safe"}{"dsnEnv":"evil"}`,
		`{"id":"safe","unsafeField":true}`,
	} {
		var target struct {
			ID     string `json:"id"`
			DSNEnv string `json:"dsnEnv"`
			HMAC   struct {
				SecretEnv string `json:"secretEnv"`
			} `json:"hmac"`
		}
		if err := strictProviderConfig02910([]byte(payload), &target); err == nil {
			t.Fatalf("ambiguous provider config accepted: %s", payload)
		}
	}
}

func TestProtectionCannotUseMissingSessionStore0300(t *testing.T) {
	repo := repository.NewMemoryRepository("")
	if _, err := repo.SaveUser(model.User{ID: "protection0300", Email: "protection0300@example.test", Status: "active", RoleID: "player"}); err != nil {
		t.Fatal(err)
	}
	server := Server{Repo: repo}
	d := server.evaluateProtection0298(context.Background(), protection.Request{Stage: protection.BeforeJoin, UserID: "protection0300", SessionID: "forged-parent-session"})
	if d.Action != protection.Deny || d.Reason != "session_store_unavailable" {
		t.Fatalf("session bypass in unconfigured host: %+v", d)
	}
}
