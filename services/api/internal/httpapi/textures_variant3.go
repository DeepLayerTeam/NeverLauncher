package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"gitflic.ru/skif4er/launcher/services/api/internal/texturefetch"
	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

// Per-instance abuse control; clusters should also apply an ingress limit.
var textureURLImportWindow0254 = struct {
	sync.Mutex
	users map[string]textureURLImportCount0254
}{users: make(map[string]textureURLImportCount0254)}

type textureURLImportCount0254 struct {
	count int
	until time.Time
}

func admitTextureURLImport0254(userID string) bool {
	now := time.Now()
	state := &textureURLImportWindow0254
	state.Lock()
	defer state.Unlock()
	if len(state.users) > 10000 {
		for key, value := range state.users {
			if now.After(value.until) {
				delete(state.users, key)
			}
		}
		if len(state.users) > 10000 {
			return false
		}
	}
	value := state.users[userID]
	if !now.Before(value.until) {
		value = textureURLImportCount0254{until: now.Add(time.Minute)}
	}
	if value.count >= 5 {
		return false
	}
	value.count++
	state.users[userID] = value
	return true
}

type textureURLImport0254 struct {
	URL              string `json:"url"`
	ProfileUUID      string `json:"profileUuid,omitempty"`
	ExpectedRevision *int64 `json:"expectedRevision"`
	Model            string `json:"model"`
	Visibility       string `json:"visibility"`
}

// textureImport0254 is an authenticated, self-profile-only URL import.
// Remote URLs are never persisted as live texture references. Only verified,
// normalized PNGs are stored using the same CAS/quota/storage path as uploads.
func (s Server) textureImport0254(w http.ResponseWriter, r *http.Request) {
	profile, user, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authenticated local Minecraft profile required")
		return
	}
	if s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "texture storage unavailable")
		return
	}
	if _, ok := s.Repo.(repository.TextureUploadRepository0252); !ok {
		writeError(w, http.StatusServiceUnavailable, "texture database unavailable")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.PathValue("kind")))
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "kind must be skin or cape")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var input textureURLImport0254
	if err := dec.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid import JSON")
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "expected exactly one JSON object")
		return
	}
	if input.ProfileUUID != "" && minecraftID119(input.ProfileUUID) != minecraftID119(profile.UUID) {
		writeError(w, http.StatusForbidden, "Minecraft profile does not belong to account")
		return
	}
	if input.ExpectedRevision == nil || *input.ExpectedRevision < 0 {
		writeError(w, http.StatusBadRequest, "nonnegative expectedRevision required")
		return
	}
	if input.Model == "" {
		input.Model = "classic"
	}
	if input.Visibility == "" {
		input.Visibility = "public"
	}
	if input.Model != "classic" && input.Model != "slim" || kind == "cape" && input.Model != "classic" || (input.Visibility != "public" && input.Visibility != "private" && input.Visibility != "unlisted") {
		writeError(w, http.StatusBadRequest, "invalid model or visibility")
		return
	}
	// Reject obviously stale CAS revisions before consuming outbound network
	// resources. StageTextureUpload0253 revalidates this under a database lock.
	selectionRepo, ok := s.textureRepository0251()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "texture database unavailable")
		return
	}
	preflightCtx, preflightCancel := context.WithTimeout(r.Context(), 5*time.Second)
	assigned, preflightErr := selectionRepo.ListTextureAssignments0251(preflightCtx, profile)
	preflightCancel()
	if preflightErr != nil {
		writeError(w, http.StatusServiceUnavailable, "texture database unavailable")
		return
	}
	currentRevision := int64(0)
	for _, item := range assigned {
		if item.Kind == kind && item.ProjectID == "" {
			currentRevision = item.Revision
			break
		}
	}
	if currentRevision != *input.ExpectedRevision {
		writeError(w, http.StatusConflict, "texture revision conflict; reload and retry")
		return
	}
	if !admitTextureURLImport0254(user.ID) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "texture URL import rate limit exceeded")
		return
	}
	fetcher, err := texturefetch.New(os.Getenv("LAUNCHER_TEXTURE_FETCH_HOST_ALLOWLIST"))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "texture fetch host policy invalid")
		return
	}
	normalized, err := fetcher.Fetch(r.Context(), input.URL, kind, input.Model)
	if err != nil {
		status := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, texturefetch.ErrUnsafe):
			status = http.StatusBadRequest
		case errors.Is(err, texturefetch.ErrTooLarge), errors.Is(err, texturepng.ErrTooLarge):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, texturefetch.ErrBusy):
			status = http.StatusTooManyRequests
		case errors.Is(err, texturefetch.ErrRemote):
			status = http.StatusBadGateway
		}
		// Avoid reflecting remote content, URL, DNS results or internal addresses.
		writeError(w, status, "remote URL must be public HTTPS and return a valid bounded Minecraft PNG")
		return
	}
	s.persistTexture0254(w, r, profile, user, normalized, kind, input.Model, input.Visibility, *input.ExpectedRevision, "import")
}

// persistTexture0254 is the single persistence path used by both multipart
// uploads and remote imports. Staging is done before any object write.
func (s Server) persistTexture0254(w http.ResponseWriter, r *http.Request, profile model.MinecraftProfile, user model.User, normalized texturepng.Result, kind, modelName, visibility string, expected int64, action string) {
	repo, ok := s.Repo.(repository.TextureUploadRepository0252)
	if !ok || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "texture storage unavailable")
		return
	}
	// Reserve digest and enforce ownership, revision and quota BEFORE any
	// persistent object write. Failed saves remain GC-visible as staging rows.
	source := "managed-upload"
	if action == "import" {
		source = "managed-url-import"
	}
	staged := repository.VerifiedTexture0252{
		Digest: normalized.Digest, Width: normalized.Width, Height: normalized.Height,
		Size: int64(len(normalized.PNG)), Driver: s.Storage.Driver(),
		ObjectKey: "texture-blobs/sha256/" + normalized.Digest[:2] + "/" + normalized.Digest + ".png",
		Kind:      kind, Model: modelName, Visibility: visibility, ExpectedRevision: expected, Source: source,
	}
	stagingRepo, ok := s.Repo.(interface {
		StageTextureUpload0253(context.Context, model.MinecraftProfile, repository.VerifiedTexture0252) error
	})
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "texture staging unavailable")
		return
	}
	stageCtx, stageCancel := context.WithTimeout(r.Context(), 10*time.Second)
	stageErr := stagingRepo.StageTextureUpload0253(stageCtx, profile, staged)
	stageCancel()
	switch {
	case errors.Is(stageErr, repository.ErrTextureRevisionConflict0251):
		writeError(w, http.StatusConflict, "texture revision conflict; reload and retry")
		return
	case errors.Is(stageErr, repository.ErrTextureUploadDenied0252):
		writeError(w, http.StatusForbidden, "texture upload denied by policy")
		return
	case errors.Is(stageErr, repository.ErrTextureUploadLimit0252):
		writeError(w, http.StatusRequestEntityTooLarge, "texture quota exceeded")
		return
	case errors.Is(stageErr, repository.ErrNotFound):
		writeError(w, http.StatusForbidden, "Minecraft profile ownership mismatch")
		return
	case stageErr != nil:
		writeError(w, http.StatusServiceUnavailable, "texture staging transaction failed")
		return
	}
	key, size, err := storage.PutTextureImmutable0253(r.Context(), s.Storage, normalized.Digest, normalized.PNG)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "failed to persist PNG")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	input := repository.VerifiedTexture0252{Digest: normalized.Digest, Width: normalized.Width, Height: normalized.Height, Size: size, Driver: s.Storage.Driver(), ObjectKey: key, Kind: kind, Model: modelName, Visibility: visibility, ExpectedRevision: expected, Source: source}
	updated, err := repo.UploadTexture0252(ctx, profile, input)
	switch {
	case errors.Is(err, repository.ErrTextureRevisionConflict0251):
		writeError(w, http.StatusConflict, "texture revision conflict; reload and retry")
		return
	case errors.Is(err, repository.ErrTextureUploadDenied0252), errors.Is(err, repository.ErrTextureCapeDenied0251):
		writeError(w, http.StatusForbidden, "texture upload is not permitted by policy")
		return
	case errors.Is(err, repository.ErrTextureUploadLimit0252):
		writeError(w, http.StatusRequestEntityTooLarge, "texture exceeds project quota")
		return
	case errors.Is(err, repository.ErrNotFound):
		writeError(w, http.StatusForbidden, "profile ownership verification failed")
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "texture upload transaction failed")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("texture-" + action + "-0254"), Actor: user.Email, Action: "texture:" + action, Target: profile.UUID + ":" + kind, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"assignment": updated, "digest": normalized.Digest, "width": normalized.Width, "height": normalized.Height, "bytes": size, "previewUrl": "/api/v1/me/textures/" + kind + "/image", "method": action}})
}
