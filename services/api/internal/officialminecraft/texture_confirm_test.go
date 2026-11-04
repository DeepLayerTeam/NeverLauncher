package officialminecraft

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const textureUUID0395 = "1234567890abcdef1234567890abcdef"

func TestTextureConfirmation0395ReadsFreshOfficialProfile(t *testing.T) {
	var reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/minecraft/profile" || r.Header.Get("Authorization") != "Bearer owner-token" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n := reads.Add(1)
		state := "INACTIVE"
		if n >= 2 {
			state = "ACTIVE"
		}
		fmt.Fprintf(w, `{"id":"%s","name":"Player","capes":[{"id":"owned","state":"%s"}]}`, textureUUID0395, state)
	}))
	defer srv.Close()
	c := New()
	c.minecraft = srv.URL
	profile, err := c.ConfirmTexture0395(context.Background(), "owner-token", textureUUID0395, "cape-select", "owned")
	if err != nil || len(profile.Capes) != 1 || profile.Capes[0].State != "ACTIVE" || reads.Load() != 2 {
		t.Fatalf("failed to confirm delayed activation: %+v err=%v reads=%d", profile, err, reads.Load())
	}
}

func TestTextureConfirmation0395RejectsWrongIdentityWithoutRetry(t *testing.T) {
	var reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		fmt.Fprint(w, `{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Other","capes":[]}`)
	}))
	defer srv.Close()
	c := New()
	c.minecraft = srv.URL
	_, err := c.ConfirmTexture0395(context.Background(), "owner-token", textureUUID0395, "cape-reset", "")
	if err == nil || reads.Load() != 1 {
		t.Fatalf("accepted wrong Minecraft identity: %v reads=%d", err, reads.Load())
	}
}

func TestTextureConfirmation0395RequiresActiveSelectionAndModel(t *testing.T) {
	p := Profile{ID: textureUUID0395, Skins: []Skin{{State: "ACTIVE", Variant: "CLASSIC"}},
		Capes: []Cape{{ID: "a", State: "INACTIVE"}, {ID: "b", State: "ACTIVE"}}}
	if confirmedTexture0395(p, "cape-select", "a") || confirmedTexture0395(p, "cape-reset", "") ||
		confirmedTexture0395(p, "skin-upload", "slim") || confirmedTexture0395(p, "invalid", "") {
		t.Fatal("accepted unconfirmed official texture operation")
	}
	if !confirmedTexture0395(p, "cape-select", "b") || !confirmedTexture0395(p, "skin-upload", "classic") {
		t.Fatal("rejected observed official texture operation")
	}
	p.Capes[1].State = "INACTIVE"
	if !confirmedTexture0395(p, "cape-reset", "") {
		t.Fatal("reset cape not confirmed")
	}
}

func TestTextureConfirmation0395CancelsWithoutFurtherProviderRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		cancel()
		fmt.Fprintf(w, `{"id":"%s","name":"Player","capes":[{"id":"a","state":"INACTIVE"}]}`, textureUUID0395)
	}))
	defer srv.Close()
	c := New()
	c.minecraft = srv.URL
	_, err := c.ConfirmTexture0395(ctx, "owner-token", strings.ToUpper(textureUUID0395), "cape-select", "a")
	if err == nil || reads.Load() != 1 {
		t.Fatalf("cancel not enforced err=%v reads=%d", err, reads.Load())
	}
}
