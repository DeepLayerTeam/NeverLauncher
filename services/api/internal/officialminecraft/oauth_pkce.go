package officialminecraft

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var publicClientID = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// ValidateClientID ensures the POC cannot silently fall back to another
// launcher's public app registration. It must be provided explicitly.
func ValidateClientID(clientID string) error {
	if !publicClientID.MatchString(clientID) || strings.EqualFold(clientID, "00000000-0000-0000-0000-000000000000") {
		return errors.New("a real application (client) ID UUID is required")
	}
	return nil
}

// ValidateLoopbackRedirect restricts authorization codes to a loopback-only
// receiver. The caller MUST validate OAuth state before exchanging the code.
func ValidateLoopbackRedirect(redirect string) error {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Port() == "" || u.Path != "/minecraft-poc/callback" {
		return errors.New("redirect must be http://localhost:<port>/minecraft-poc/callback (or 127.0.0.1)")
	}
	if u.Hostname() != "localhost" && net.ParseIP(u.Hostname()) == nil {
		return errors.New("redirect host is not loopback")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !ip.IsLoopback() {
		return errors.New("redirect host is not loopback")
	}
	if u.Port() == "0" {
		return errors.New("redirect must have an assigned port")
	}
	return nil
}

func PKCEChallenge(verifier string) (string, error) {
	if len(verifier) < 43 || len(verifier) > 128 || !regexp.MustCompile(`^[A-Za-z0-9._~-]+$`).MatchString(verifier) {
		return "", errors.New("invalid PKCE verifier")
	}
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func (c *Client) AuthorizationURL(clientID, redirect, state, challenge string) (string, error) {
	if err := ValidateClientID(clientID); err != nil {
		return "", err
	}
	if err := ValidateLoopbackRedirect(redirect); err != nil {
		return "", err
	}
	if len(state) < 32 || len(state) > 256 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(state) {
		return "", errors.New("invalid OAuth state")
	}
	if len(challenge) != 43 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(challenge) {
		return "", errors.New("invalid S256 challenge")
	}
	v := url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"response_mode": {"query"}, "scope": {"XboxLive.signin offline_access"},
		"state": {state}, "code_challenge_method": {"S256"}, "code_challenge": {challenge},
	}
	return fmt.Sprintf("%s/authorize?%s", c.microsoft, v.Encode()), nil
}

func (c *Client) ExchangeAuthorizationCode(ctx context.Context, clientID, redirect, code, verifier string) (OAuthTokens, error) {
	if err := ValidateClientID(clientID); err != nil {
		return OAuthTokens{}, err
	}
	if err := ValidateLoopbackRedirect(redirect); err != nil {
		return OAuthTokens{}, err
	}
	if len(code) == 0 || len(code) > 4096 || strings.ContainsAny(code, "\r\n") {
		return OAuthTokens{}, errors.New("invalid OAuth code")
	}
	if _, err := PKCEChallenge(verifier); err != nil {
		return OAuthTokens{}, err
	}
	body, ct := form(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code": {code}, "code_verifier": {verifier}, "scope": {"XboxLive.signin offline_access"},
	})
	var result OAuthTokens
	if err := c.request(ctx, "POST", c.microsoft+"/token", "", ct, body, &result); err != nil {
		return OAuthTokens{}, err
	}
	if result.AccessToken == "" || !strings.EqualFold(result.TokenType, "Bearer") || result.ExpiresIn <= 0 {
		return OAuthTokens{}, errors.New("incomplete Microsoft authorization code token response")
	}
	return result, nil
}

// EntitlementCount returns the number of entitlements visible to Minecraft
// Services, not a purchase-ownership assertion. Java/Game Pass accounts can
// have an accessible live profile even with zero mcstore entitlement items.
func (c *Client) EntitlementCount(ctx context.Context, token string) (int, error) {
	var reply struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if token == "" {
		return 0, errors.New("missing Minecraft token")
	}
	if err := c.request(ctx, "GET", c.minecraft+"/entitlements/mcstore", token, "", nil, &reply); err != nil {
		return 0, err
	}
	if reply.Items == nil {
		return 0, errors.New("invalid entitlements response: missing items array")
	}
	return len(reply.Items), nil
}
