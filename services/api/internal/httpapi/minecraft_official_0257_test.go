package httpapi

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestOfficialTicketsBoundAndTamperProof0257(t *testing.T) {
	secret := "a-long-independent-server-secret-at-least-32-bytes"
	st := officialState0257{Kind: "linked", User: "user-A", Session: "never-session-A", Expires: time.Now().Add(time.Hour).Unix(), UUID: "123456781234123412341234567890ab", MinecraftToken: "official-secret-not-local"}
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
