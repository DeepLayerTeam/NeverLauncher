package httpapi

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/officialminecraft"
)

func TestOfficialTicketsBoundAndTamperProof0257(t *testing.T) {
	secret := "a-long-independent-server-secret-at-least-32-bytes"
	st := officialState0257{Kind: "linked", User: "user-A", Session: "session-A", Expires: time.Now().Add(time.Hour).Unix(), UUID: "123456781234123412341234567890ab", MinecraftToken: "official-secret-not-local"}
	ticket, err := officialSeal0257(secret, st)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := officialOpen0257(secret, ticket)
	if err != nil || decrypted.MinecraftToken != st.MinecraftToken || decrypted.User != "user-A" {
		t.Fatal("ticket round trip", err)
	}
	if strings.Contains(ticket, "official-secret") || strings.Contains(ticket, st.UUID) {
		t.Fatal("official secret leaked")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ticket)
	raw[len(raw)-1] ^= 0x80
	if _, err = officialOpen0257(secret, base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("modified ticket accepted")
	}
	if _, err = officialOpen0257("a-different-long-server-secret-012345", ticket); err == nil {
		t.Fatal("different server key accepted")
	}
	st.Expires = time.Now().Add(-time.Second).Unix()
	expired, _ := officialSeal0257(secret, st)
	if _, err = officialOpen0257(secret, expired); err == nil {
		t.Fatal("expired ticket accepted")
	}
	if _, err = officialSeal0257("short", st); err == nil {
		t.Fatal("weak secret accepted")
	}
}
func TestOfficialPollRate0257(t *testing.T) {
	if !officialPollingAllowed0257("fixture-independent-secret", time.Minute) {
		t.Fatal("first poll rejected")
	}
	if officialPollingAllowed0257("fixture-independent-secret", time.Minute) {
		t.Fatal("poll replay accepted")
	}
}

// 0.26.4: a redeemed Microsoft device grant must be resumable after an Xbox or
// Minecraft transient error, without leaking either bearer in the flow ticket.
func TestRedeemedDeviceFlowPreservesMicrosoftGrant0264(t *testing.T) {
	secret := "a-long-independent-server-secret-at-least-32-bytes"
	state := officialState0257{
		Kind: "redeemed", User: "user-A", Session: "session-A", Expires: time.Now().Add(5 * time.Minute).Unix(),
		DeviceCode: "provider-device-code", Interval: 15, MicrosoftAccess: "ms-access-sensitive",
		MicrosoftRefresh: "ms-refresh-sensitive", MicrosoftAccessExpires: time.Now().Add(time.Hour).Unix(),
	}
	ticket, err := officialSeal0257(secret, state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ticket, state.MicrosoftAccess) || strings.Contains(ticket, state.MicrosoftRefresh) || strings.Contains(ticket, state.DeviceCode) {
		t.Fatal("redeemed device flow contains plaintext provider secret")
	}
	restored, err := officialOpen0257(secret, ticket)
	if err != nil || restored.Kind != "redeemed" || restored.MicrosoftAccess != state.MicrosoftAccess || restored.MicrosoftRefresh != state.MicrosoftRefresh {
		t.Fatalf("redeemed device flow was not recoverable: %v", err)
	}
	if _, err := officialOpen0257("wrong-independent-secret-that-is-long-enough", ticket); err == nil {
		t.Fatal("device flow decrypted with another backend secret")
	}
}
func TestDeviceTransientClassifications0264(t *testing.T) {
	if !officialTransient0257(context.DeadlineExceeded) || !officialTransient0257(&officialminecraft.ServiceError{Status: 429, Code: "upstream_error"}) ||
		!officialTransient0257(&officialminecraft.ServiceError{Status: 503, Code: "upstream_error"}) {
		t.Fatal("temporary provider failures were marked permanent")
	}
	if officialTransient0257(officialminecraft.ErrExpired) || officialTransient0257(officialminecraft.ErrDenied) ||
		officialTransient0257(&officialminecraft.ServiceError{Status: 403, Code: "invalid_app_registration"}) ||
		officialTransient0257(&officialminecraft.ServiceError{Status: 400, Code: "invalid_grant"}) ||
		officialTransient0257(context.Canceled) || officialTransient0257(nil) {
		t.Fatal("permanent or canceled provider failure was marked retryable")
	}
}
