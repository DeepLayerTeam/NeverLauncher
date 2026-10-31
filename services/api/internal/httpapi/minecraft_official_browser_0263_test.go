package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/officialminecraft"
)

const ownMicrosoftClient0263 = "01234567-89ab-cdef-0123-456789abcdef"
const pkceVerifier0263 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

var browserRequest0263 = officialBrowserRequest0263{
	Code:        "live-code-only-native123",
	Verifier:    pkceVerifier0263,
	RedirectURI: "http://localhost:45678/minecraft-poc/callback",
}

type browserMockProvider0263 struct {
	calls  []string
	failAt string
}

func (f *browserMockProvider0263) ExchangeAuthorizationCode(_ context.Context, clientID, redirect, code, verifier string) (officialminecraft.OAuthTokens, error) {
	f.calls = append(f.calls, "microsoft")
	if f.failAt == "microsoft" {
		return officialminecraft.OAuthTokens{}, errors.New("provider rejected code")
	}
	if clientID != ownMicrosoftClient0263 || redirect != browserRequest0263.RedirectURI || code != browserRequest0263.Code || verifier != pkceVerifier0263 {
		return officialminecraft.OAuthTokens{}, errors.New("unexpected native auth grant")
	}
	return officialminecraft.OAuthTokens{AccessToken: "fixture-ms-bearer", RefreshToken: "fixture-refresh", ExpiresIn: 3600, TokenType: "Bearer"}, nil
}
func (f *browserMockProvider0263) Exchange(_ context.Context, bearer string) (officialminecraft.MinecraftToken, error) {
	f.calls = append(f.calls, "xbox-minecraft")
	if bearer != "fixture-ms-bearer" || f.failAt == "xbox-minecraft" {
		return officialminecraft.MinecraftToken{}, errors.New("provider rejected Xbox chain")
	}
	return officialminecraft.MinecraftToken{AccessToken: "fixture-minecraft-bearer", ExpiresIn: 7200, TokenType: "Bearer"}, nil
}
func (f *browserMockProvider0263) Profile(_ context.Context, bearer string) (officialminecraft.Profile, error) {
	f.calls = append(f.calls, "java-profile")
	if bearer != "fixture-minecraft-bearer" || f.failAt == "java-profile" {
		return officialminecraft.Profile{}, errors.New("no Minecraft Java access")
	}
	return officialminecraft.Profile{ID: "123456781234123412341234567890ab", Name: "ExampleUser"}, nil
}

func TestBrowserPKCEExchangeRealChainMock0263(t *testing.T) {
	f := &browserMockProvider0263{}
	ms, mc, profile, err := exchangeOfficialBrowser0263(context.Background(), f, ownMicrosoftClient0263, browserRequest0263)
	if err != nil || ms.RefreshToken != "fixture-refresh" || mc.AccessToken != "fixture-minecraft-bearer" || profile.ID == "" {
		t.Fatalf("unexpected chain: %v", err)
	}
	if strings.Join(f.calls, ",") != "microsoft,xbox-minecraft,java-profile" {
		t.Fatal(f.calls)
	}
	for _, stage := range []string{"microsoft", "xbox-minecraft", "java-profile"} {
		bad := &browserMockProvider0263{failAt: stage}
		if _, _, _, err := exchangeOfficialBrowser0263(context.Background(), bad, ownMicrosoftClient0263, browserRequest0263); err == nil {
			t.Fatalf("%s unexpectedly accepted", stage)
		}
	}
}
func TestBrowserPKCERejectsMalformedGrants0263(t *testing.T) {
	for _, change := range []func(*officialBrowserRequest0263){
		func(v *officialBrowserRequest0263) { v.RedirectURI = "http://evil.test:4444/minecraft-poc/callback" },
		func(v *officialBrowserRequest0263) { v.RedirectURI = "http://localhost:4444/other" },
		func(v *officialBrowserRequest0263) { v.Verifier = "short" },
		func(v *officialBrowserRequest0263) { v.Code = "bad\r\ncode" },
		func(v *officialBrowserRequest0263) { v.Code = "" },
	} {
		v := browserRequest0263
		change(&v)
		mock := &browserMockProvider0263{}
		if _, _, _, err := exchangeOfficialBrowser0263(context.Background(), mock, ownMicrosoftClient0263, v); err == nil || len(mock.calls) != 0 {
			t.Fatalf("invalid grant reached Microsoft API: %+v", v)
		}
	}
	if _, _, _, err := exchangeOfficialBrowser0263(context.Background(), &browserMockProvider0263{}, "00000000-0000-0000-0000-000000000000", browserRequest0263); err == nil {
		t.Fatal("client ID placeholder accepted")
	}
	if validOfficialProfile0263(officialminecraft.Profile{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "Some-Invalid"}) {
		t.Fatal("invalid Minecraft name accepted")
	}
}
