package officialminecraft

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sessionProfileID = "123456781234123412341234567890ab"

func TestSignedServerHashMatchesJavaBigInteger(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"Notch", "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"},
		{"jeb_", "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1"},
		{"simon", "88e16a1019277b15d58faf0541e11910eb756f6"},
	} {
		if got := SignedServerHash(tc.input, nil, nil); got != tc.want {
			t.Errorf("%s: %s", tc.input, got)
		}
	}
}

func TestLiveSessionserverProtocolFixture(t *testing.T) {
	username := "PrivatePerson"
	for _, tc := range []struct {
		name                    string
		joinStatus, checkStatus int
		uuid, nameResult        string
		wantError               bool
	}{
		{"success", 204, 200, sessionProfileID, username, false},
		{"join403", 403, 200, sessionProfileID, username, true},
		{"join200isNotSuccess", 200, 200, sessionProfileID, username, true},
		{"notJoined", 204, 204, sessionProfileID, username, true},
		{"uuidMismatch", 204, 200, strings.Repeat("a", 32), username, true},
		{"nameMismatch", 204, 200, sessionProfileID, "OtherPerson", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var challenge string
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path == "/session/minecraft/join" {
					if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
						t.Error("bad join headers")
					}
					var data map[string]string
					if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
						t.Error(err)
					}
					if data["accessToken"] != "SECRET_MC_TOKEN" || data["selectedProfile"] != sessionProfileID {
						t.Error("wrong bearer or profile")
					}
					if len(data["serverId"]) < 30 || strings.ContainsAny(data["serverId"], " \r\n") {
						t.Error("invalid challenge")
					}
					challenge = data["serverId"]
					w.WriteHeader(tc.joinStatus)
					return
				}
				if r.URL.Path == "/session/minecraft/hasJoined" {
					if r.Method != http.MethodGet || r.URL.Query().Get("serverId") != challenge || r.URL.Query().Get("username") != username {
						t.Error("wrong hasJoined query")
					}
					if r.Header.Get("Authorization") != "" {
						t.Error("bearer leaked to hasJoined")
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.checkStatus)
					if tc.checkStatus == 200 {
						fmt.Fprintf(w, `{"id":%q,"name":%q,"properties":[]}`, tc.uuid, tc.nameResult)
					}
					return
				}
				t.Errorf("unexpected %s", r.URL.Path)
				http.NotFound(w, r)
			}))
			defer srv.Close()
			c := New()
			c.sessionserver = srv.URL
			err := c.VerifyOnlineSession(context.Background(), "SECRET_MC_TOKEN", Profile{ID: sessionProfileID, Name: username})
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v", err)
			}
			if tc.joinStatus != 204 && requests != 1 {
				t.Fatalf("hasJoined called after join was rejected: %d", requests)
			}
			if tc.joinStatus == 204 && requests != 2 {
				t.Fatalf("join/hasJoined missing: %d", requests)
			}
		})
	}
}
func TestSessionserverNoTokenLeakOnErrorAndBadInput(t *testing.T) {
	c := New()
	for _, p := range []Profile{{ID: "bad", Name: "Player"}, {ID: sessionProfileID, Name: "with spaces"}} {
		if err := c.VerifyOnlineSession(context.Background(), "secret", p); err == nil {
			t.Fatal("bad identity accepted")
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session/minecraft/join" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error":"InvalidToken SECRET_DO_NOT_ECHO"}`)
		}
	}))
	defer srv.Close()
	c.sessionserver = srv.URL
	err := c.VerifyOnlineSession(context.Background(), "SECRET_DO_NOT_ECHO", Profile{ID: sessionProfileID, Name: "Player"})
	if err == nil || strings.Contains(err.Error(), "SECRET_DO_NOT_ECHO") {
		t.Fatalf("secret in error: %v", err)
	}
}
