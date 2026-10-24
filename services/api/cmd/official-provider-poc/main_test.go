package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/officialminecraft"
)

const ownClientID = "4b8f7734-4f10-44ca-b870-b4d89d34a319"

// All these tests are SIMULATIONS. The CLI has no switch for replacing real
// endpoints, and none of these reports constitutes external approval evidence.
type simulatedProvider struct {
	reject            error
	badState          bool
	onlineReject      error
	duplicateCallback chan int
}

func (*simulatedProvider) Begin(context.Context, string) (officialminecraft.DeviceCode, error) {
	return officialminecraft.DeviceCode{}, errors.New("not used")
}
func (*simulatedProvider) Complete(context.Context, string, string) (officialminecraft.OAuthTokens, error) {
	return officialminecraft.OAuthTokens{}, errors.New("not used")
}
func (p *simulatedProvider) AuthorizationURL(_ string, redirect, state, challenge string) (string, error) {
	if challenge == "" {
		return "", errors.New("missing PKCE challenge")
	}
	go func() {
		if p.badState { // Wrong state may never authorize or terminate the local listener.
			_, _ = http.Get(redirect + "?state=attacker&code=wrong")
			time.Sleep(15 * time.Millisecond)
		}
		if p.duplicateCallback != nil {
			response, err := http.Get(redirect + "?state=" + url.QueryEscape(state) + "&state=attacker&code=authorized")
			if err != nil {
				p.duplicateCallback <- 0
			} else {
				p.duplicateCallback <- response.StatusCode
				response.Body.Close()
			}
		}
		_, _ = http.Get(redirect + "?state=" + url.QueryEscape(state) + "&code=authorized")
	}()
	return "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize", nil
}
func (*simulatedProvider) ExchangeAuthorizationCode(_ context.Context, _, redirect, code, verifier string) (officialminecraft.OAuthTokens, error) {
	if code != "authorized" || verifier == "" || !strings.HasPrefix(redirect, "http://localhost:") {
		return officialminecraft.OAuthTokens{}, errors.New("invalid callback or verifier")
	}
	return officialminecraft.OAuthTokens{AccessToken: "PRIVATE-MS", RefreshToken: "PRIVATE-REFRESH", TokenType: "Bearer", ExpiresIn: 3600}, nil
}
func (*simulatedProvider) Refresh(_ context.Context, _, refresh string) (officialminecraft.OAuthTokens, error) {
	if refresh != "PRIVATE-REFRESH" {
		return officialminecraft.OAuthTokens{}, errors.New("not a refresh token")
	}
	return officialminecraft.OAuthTokens{AccessToken: "PRIVATE-MS2", RefreshToken: "PRIVATE-REFRESH2", TokenType: "Bearer", ExpiresIn: 3600}, nil
}
func (p *simulatedProvider) ExchangeWithStages(_ context.Context, ms string, stagePassed func(string)) (officialminecraft.MinecraftToken, error) {
	if ms != "PRIVATE-MS2" {
		return officialminecraft.MinecraftToken{}, errors.New("wrong token type")
	}
	stagePassed("xbox_live")
	stagePassed("xsts")
	if p.reject != nil {
		return officialminecraft.MinecraftToken{}, p.reject
	}
	stagePassed("minecraft_token")
	return officialminecraft.MinecraftToken{AccessToken: "PRIVATE-MC", TokenType: "Bearer", ExpiresIn: 7200}, nil
}
func (*simulatedProvider) EntitlementCount(_ context.Context, token string) (int, error) {
	if token != "PRIVATE-MC" {
		return 0, errors.New("wrong bearer")
	}
	return 0, nil
}
func (p *simulatedProvider) VerifyOnlineSession(_ context.Context, token string, profile officialminecraft.Profile) error {
	if p.onlineReject != nil {
		return p.onlineReject
	}
	if token != "PRIVATE-MC" || profile.Name != "PrivatePerson" {
		return errors.New("wrong online session identity")
	}
	return nil
}
func (*simulatedProvider) Profile(_ context.Context, token string) (officialminecraft.Profile, error) {
	if token != "PRIVATE-MC" {
		return officialminecraft.Profile{}, errors.New("wrong bearer")
	}
	return officialminecraft.Profile{ID: "123456781234123412341234567890ab", Name: "PrivatePerson"}, nil
}

func TestBrowserPKCEPOCRedactsAllTokensAndNeverClaimsFormalApproval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var instructions bytes.Buffer
	r := verify(ctx, &simulatedProvider{badState: true}, options{ClientID: ownClientID, Flow: "browser", OpenBrowser: false}, &instructions)
	if r.Result != "provider_access_verified" {
		t.Fatalf("unexpected result %+v", r)
	}
	if r.ExternalAppApproval != "requires_independent_provider_confirmation" {
		t.Fatal("simulated access was treated as approval")
	}
	if r.MinecraftServicesAccess != "verified_live_profile" || len(r.Stages) != 8 {
		t.Fatalf("unexpected stage sequence %+v", r)
	}
	if r.EntitlementItems == nil || *r.EntitlementItems != 0 {
		t.Fatal("zero entitlements may coexist with active Java profile")
	}
	if r.MinecraftProfileSHA256 == "" {
		t.Fatal("missing hashed subject")
	}
	payload, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE-MS", "PRIVATE-REFRESH", "PRIVATE-MC", "PrivatePerson", "123456781234123412341234567890ab", "authorized"} {
		if bytes.Contains(payload, []byte(secret)) {
			t.Fatalf("report leaked %q", secret)
		}
	}
	if !strings.Contains(instructions.String(), "Microsoft personal-account") {
		t.Fatal("missing browser instructions")
	}
}

func TestExplicitAppApprovalRejectionReportsBlockingStage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	r := verify(ctx, &simulatedProvider{reject: &officialminecraft.ServiceError{Status: 403, Code: "invalid_app_registration"}}, options{ClientID: ownClientID, Flow: "browser"}, new(bytes.Buffer))
	if r.Result != "blocked" || r.MinecraftServicesAccess != "not_verified" {
		t.Fatalf("incorrect access assertion: %+v", r)
	}
	last := r.Stages[len(r.Stages)-1]
	if last.Name != "minecraft_token" || last.Status != "blocked" || last.ErrorCode != "minecraft_app_not_authorized" || last.HTTPStatus != 403 {
		t.Fatalf("unexpected rejection: %+v", last)
	}
}

func TestReportExclusivePrivateAndAtomicEnoughForProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof.json")
	r := newReport(options{ClientID: ownClientID, Flow: "browser"})
	if err := writeReport(path, r); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("report permissions: %o", info.Mode().Perm())
	}
	if err := writeReport(path, r); err == nil {
		t.Fatal("existing report overwritten")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed report
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Schema != "neverlauncher.official-provider-poc.v1" {
		t.Fatal("wrong report schema")
	}
}

func TestSessionserviceFailureAlwaysBlocksPOC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	provider := &simulatedProvider{onlineReject: officialminecraft.ErrOnlineIdentityMismatch}
	r := verify(ctx, provider, options{ClientID: ownClientID, Flow: "browser", RequireOnlineSession: true}, io.Discard)
	if r.Result != "blocked" || r.OnlineModeSession != "not_verified" || r.MinecraftServicesAccess != "verified_live_profile" {
		t.Fatalf("incorrect release gate %+v", r)
	}
	last := r.Stages[len(r.Stages)-1]
	if last.Name != "sessionserver_join_has_joined" || last.ErrorCode != "online_mode_identity_mismatch" {
		t.Fatalf("unexpected stage %+v", last)
	}
}

func TestOAuthCallbackRejectsDuplicateStateWithoutConsumingGrant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	p := &simulatedProvider{duplicateCallback: make(chan int, 1)}
	r := verify(ctx, p, options{ClientID: ownClientID, Flow: "browser"}, io.Discard)
	if r.Result != "provider_access_verified" {
		t.Fatalf("later legitimate callback rejected: %+v", r)
	}
	if status := <-p.duplicateCallback; status != http.StatusBadRequest {
		t.Fatalf("duplicate state accepted: %d", status)
	}
}
