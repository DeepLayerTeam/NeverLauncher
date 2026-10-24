package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/officialminecraft"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// The native Tauri manager is the only caller that supplies the short-lived
// Minecraft bearer. The Backend verifies it with Minecraft Services itself.
// Tokens never enter the Never database, renderer, response, or audit event.
type officialLinkRequest0268 struct {
	MinecraftAccessToken string `json:"minecraftAccessToken"`
	ExpectedUUID         string `json:"expectedUuid"`
	Confirm              bool   `json:"confirm"`
}

var errLinkProofMalformed0268 = errors.New("malformed Minecraft proof")
var errLinkProofMismatch0268 = errors.New("Minecraft UUID proof mismatch")

type minecraftProfileVerifier0268 interface {
	Profile(context.Context, string) (officialminecraft.Profile, error)
}

func freshNeverIdentity0268(claims authClaims, clock time.Time) bool {
	// The authenticated Never session is proof of its side of the link. Require
	// recent Never authentication to prevent account linking via a stolen old JWT.
	return claims.AuthTime > 0 && claims.AuthTime <= clock.Unix() && clock.Unix()-claims.AuthTime <= 15*60
}

func canonicalMinecraftUUID0268(raw string) (string, bool) {
	if len(raw) != 32 {
		return "", false
	}
	for _, r := range raw {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return "", false
		}
	}
	return strings.ToLower(raw), true
}

func verifiedLinkProfile0268(ctx context.Context, verifier minecraftProfileVerifier0268, token, expected string) (officialminecraft.Profile, error) {
	if len(token) < 16 || len(token) > 8192 || strings.ContainsAny(token, "\r\n\x00\t ") {
		return officialminecraft.Profile{}, errLinkProofMalformed0268
	}
	uuid, ok := canonicalMinecraftUUID0268(expected)
	if !ok {
		return officialminecraft.Profile{}, errLinkProofMalformed0268
	}
	profile, err := verifier.Profile(ctx, token)
	if err != nil {
		return officialminecraft.Profile{}, err
	}
	actual, valid := canonicalMinecraftUUID0268(profile.ID)
	if !valid || !validOfficialProfile0263(profile) || actual != uuid {
		return officialminecraft.Profile{}, errLinkProofMismatch0268
	}
	return profile, nil
}

func (s Server) officialLinkStore0268() (repository.OfficialLinkStore0268, bool) {
	store, ok := s.Repo.(repository.OfficialLinkStore0268)
	return store, ok
}

func (s Server) officialLinksGet0268(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	claims, err := s.officialActor0257(r)
	if err != nil {
		writeError(w, 401, "Never authentication required")
		return
	}
	store, ok := s.officialLinkStore0268()
	if !ok {
		writeError(w, 503, "durable official identity store required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	links, err := store.ListOfficialLinks0268(ctx, claims.Sub)
	if err != nil {
		writeError(w, 503, "official identity storage unavailable")
		return
	}
	officialWrite0257(w, 200, map[string]any{"links": links})
}

func (s Server) officialLinkCreate0268(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	claims, err := s.officialActor0257(r)
	if err != nil {
		writeError(w, 401, "Never authentication required")
		return
	}
	if !freshNeverIdentity0268(claims, time.Now()) {
		writeError(w, 403, "recent Never login required to link an account")
		return
	}
	store, ok := s.officialLinkStore0268()
	if !ok {
		writeError(w, 503, "durable official identity store required")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, 415, "application/json required")
		return
	}
	var input officialLinkRequest0268
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 12*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		writeError(w, 400, "invalid official identity link request")
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		writeError(w, 400, "invalid official identity link request")
		return
	}
	if !input.Confirm {
		writeError(w, 400, "explicit confirmation required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// Input bearer intentionally never appears in logs, error strings or stored rows.
	profile, err := verifiedLinkProfile0268(ctx, officialminecraft.New(), input.MinecraftAccessToken, input.ExpectedUUID)
	input.MinecraftAccessToken = ""
	if errors.Is(err, errLinkProofMalformed0268) {
		writeError(w, 400, "invalid Minecraft proof request")
		return
	}
	if errors.Is(err, errLinkProofMismatch0268) {
		writeError(w, 403, "selected Minecraft UUID was not verified")
		return
	}
	if err != nil {
		officialFail0257(w, err)
		return
	}
	link, err := store.UpsertOfficialLink0268(ctx, claims.Sub, strings.ToLower(profile.ID), profile.Name)
	if errors.Is(err, repository.ErrOfficialLinkOwned0268) {
		writeError(w, 409, "Minecraft UUID is already linked to another Never account")
		return
	}
	if err != nil {
		writeError(w, 503, "official identity storage unavailable")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "official-minecraft:link", Target: link.MinecraftUUID, CreatedAt: time.Now().UTC()})
	officialWrite0257(w, 200, link)
}

func (s Server) officialLinkRemove0268(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	claims, err := s.officialActor0257(r)
	if err != nil {
		writeError(w, 401, "Never authentication required")
		return
	}
	if !freshNeverIdentity0268(claims, time.Now()) {
		writeError(w, 403, "recent Never login required to unlink an account")
		return
	}
	uuid, valid := canonicalMinecraftUUID0268(r.PathValue("minecraftUuid"))
	if !valid {
		writeError(w, 400, "invalid Minecraft UUID")
		return
	}
	store, ok := s.officialLinkStore0268()
	if !ok {
		writeError(w, 503, "durable official identity store required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err = store.RemoveOfficialLink0268(ctx, claims.Sub, uuid)
	if errors.Is(err, repository.ErrOfficialLinkAbsent0268) {
		writeError(w, 404, "Minecraft UUID not linked to this Never account")
		return
	}
	if err != nil {
		writeError(w, 503, "official identity storage unavailable")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "official-minecraft:unlink", Target: uuid, CreatedAt: time.Now().UTC()})
	officialWrite0257(w, 200, map[string]any{"unlinked": uuid})
}
