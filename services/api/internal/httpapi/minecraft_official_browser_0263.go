package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/officialminecraft"
)

// OAuth code/verifier is received exclusively from the native desktop client,
// not from its renderer or from the user's browser. The account is bound to
// the authenticated Never session before issuing the existing opaque ticket.
// Client ID always comes from this server's own application registration.
type officialBrowserRequest0263 struct {
	Code        string `json:"code"`
	Verifier    string `json:"verifier"`
	RedirectURI string `json:"redirectUri"`
}

func validateOfficialBrowserRequest0263(v officialBrowserRequest0263) error {
	if err := officialminecraft.ValidateLoopbackRedirect(v.RedirectURI); err != nil {
		return err
	}
	if _, err := officialminecraft.PKCEChallenge(v.Verifier); err != nil {
		return err
	}
	if len(v.Code) < 8 || len(v.Code) > 4096 || strings.ContainsAny(v.Code, "\r\n\x00") {
		return errors.New("invalid authorization code")
	}
	return nil
}

func (s Server) officialBrowserConfig0263(w http.ResponseWriter, r *http.Request) {
	if _, err := s.officialActor0257(r); err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if officialminecraft.ValidateClientID(s.Config.MinecraftMicrosoftClientID) != nil || len(s.Config.AuthTokenSecret) < 24 {
		writeError(w, 503, "own Microsoft public client registration and ticket encryption required")
		return
	}
	officialWrite0257(w, 200, map[string]string{
		"clientId": s.Config.MinecraftMicrosoftClientID,
	})
}

// provider is a narrow injectable seam for verifying the complete token chain
// with a local HTTP fixture. Production always uses officialminecraft.New().
type officialBrowserProvider0263 interface {
	ExchangeAuthorizationCode(context.Context, string, string, string, string) (officialminecraft.OAuthTokens, error)
	Exchange(context.Context, string) (officialminecraft.MinecraftToken, error)
	Profile(context.Context, string) (officialminecraft.Profile, error)
}

func exchangeOfficialBrowser0263(ctx context.Context, provider officialBrowserProvider0263, clientID string, v officialBrowserRequest0263) (officialminecraft.OAuthTokens, officialminecraft.MinecraftToken, officialminecraft.Profile, error) {
	if err := officialminecraft.ValidateClientID(clientID); err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if err := validateOfficialBrowserRequest0263(v); err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	tokens, err := provider.ExchangeAuthorizationCode(ctx, clientID, v.RedirectURI, v.Code, v.Verifier)
	if err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, errors.New("missing Microsoft bearer/refresh token")
	}
	mc, err := provider.Exchange(ctx, tokens.AccessToken)
	if err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if mc.AccessToken == "" || mc.ExpiresIn <= 0 {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, errors.New("missing Minecraft bearer")
	}
	profile, err := provider.Profile(ctx, mc.AccessToken)
	if err != nil {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, err
	}
	if !validOfficialProfile0263(profile) {
		return officialminecraft.OAuthTokens{}, officialminecraft.MinecraftToken{}, officialminecraft.Profile{}, errors.New("unverified Minecraft Java profile")
	}
	return tokens, mc, profile, nil
}

func validOfficialProfile0263(profile officialminecraft.Profile) bool {
	if len(profile.ID) != 32 || len(profile.Name) < 3 || len(profile.Name) > 16 {
		return false
	}
	for _, c := range profile.ID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	for _, c := range profile.Name {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_') {
			return false
		}
	}
	return true
}

func (s Server) officialBrowserExchange0263(w http.ResponseWriter, r *http.Request) {
	actor, err := s.officialActor0257(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if officialminecraft.ValidateClientID(s.Config.MinecraftMicrosoftClientID) != nil || len(s.Config.AuthTokenSecret) < 24 {
		writeError(w, 503, "own official application registration is not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var v officialBrowserRequest0263
	if err := decoder.Decode(&v); err != nil {
		writeError(w, 400, "invalid browser code payload")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, 400, "unexpected browser payload data")
		return
	}
	if err := validateOfficialBrowserRequest0263(v); err != nil {
		writeError(w, 400, "invalid browser callback credentials")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
	defer cancel()
	tokens, mc, profile, err := exchangeOfficialBrowser0263(ctx, officialminecraft.New(), s.Config.MinecraftMicrosoftClientID, v)
	if err != nil {
		officialFail0257(w, err)
		return
	}
	expiry := time.Now().Add(time.Duration(mc.ExpiresIn) * time.Second).Unix()
	if expiry > time.Now().Add(24*time.Hour).Unix() {
		expiry = time.Now().Add(24 * time.Hour).Unix()
	}
	linked := officialState0257{
		Kind: "linked", User: actor.Sub, Session: actor.SessionID,
		Expires:          time.Now().Add(30 * 24 * time.Hour).Unix(),
		MicrosoftRefresh: tokens.RefreshToken, MinecraftToken: mc.AccessToken,
		MinecraftExpires: expiry, UUID: strings.ToLower(profile.ID), Name: profile.Name,
	}
	ticket, err := officialSeal0257(s.Config.AuthTokenSecret, linked)
	if err != nil {
		writeError(w, 503, "secure official session unavailable")
		return
	}
	officialWrite0257(w, 200, map[string]any{
		"realm": "official-minecraft", "profile": profile, "session": ticket, "expiresAt": linked.Expires,
	})
}
