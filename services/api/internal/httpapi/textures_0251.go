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
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// Current profile is resolved from the authenticated Never account, never from
// a supplied UUID. Official identities are deliberately not writable here.
func (s Server) ownedTextureProfile0251(r *http.Request) (model.MinecraftProfile, model.User, error) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		return model.MinecraftProfile{}, model.User{}, err
	}
	user, err := s.Repo.GetUser(claims.Sub)
	if err != nil || user.Status == "disabled" {
		return model.MinecraftProfile{}, model.User{}, errAuthRequired
	}
	p, err := s.ensureMinecraftProfile119(user)
	if err != nil {
		return model.MinecraftProfile{}, model.User{}, err
	}
	if p.UserID != user.ID || p.Issuer != "neverlauncher" || p.Realm != "local" {
		return model.MinecraftProfile{}, model.User{}, errAuthRequired
	}
	return p, user, nil
}

func (s Server) textureRepository0251() (repository.TextureRepository0251, bool) {
	repo, ok := s.Repo.(repository.TextureRepository0251)
	return repo, ok
}

func (s Server) textureMine0251(w http.ResponseWriter, r *http.Request) {
	profile, _, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный пользовательский сеанс")
		return
	}
	repo, ok := s.textureRepository0251()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "texture database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	items, err := repo.ListTextureAssignments0251(ctx, profile)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "texture database unavailable")
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"realm": "local-project", "profileUuid": profile.UUID, "profileName": profile.Name, "items": items}})
}

type textureSelectionChange0251 struct {
	ProfileUUID      string `json:"profileUuid,omitempty"` // optional assertion, never an authorization mechanism
	ExpectedRevision int64  `json:"expectedRevision"`
	Model            string `json:"model"`
	Visibility       string `json:"visibility"`
	Active           *bool  `json:"active"`
}

func (s Server) textureSelectionPatch0251(w http.ResponseWriter, r *http.Request) {
	profile, user, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный пользовательский сеанс")
		return
	}
	repo, ok := s.textureRepository0251()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "texture database unavailable")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.PathValue("kind")))
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "kind должен быть skin или cape")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input textureSelectionChange0251
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "JSON должен содержать один объект")
		return
	}
	if input.ProfileUUID != "" && minecraftID119(input.ProfileUUID) != minecraftID119(profile.UUID) {
		writeError(w, http.StatusForbidden, "Minecraft profile не принадлежит пользователю")
		return
	}
	if input.ExpectedRevision < 1 || input.Active == nil || (input.Model != "classic" && input.Model != "slim") || (input.Visibility != "public" && input.Visibility != "private" && input.Visibility != "unlisted") {
		writeError(w, http.StatusBadRequest, "требуются expectedRevision, active, model и visibility")
		return
	}
	if kind == "cape" && input.Model != "classic" {
		writeError(w, http.StatusBadRequest, "плащи не используют slim-модель")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	updated, err := repo.UpdateTextureSelection0251(ctx, profile, kind, input.ExpectedRevision, input.Model, input.Visibility, *input.Active)
	if errors.Is(err, repository.ErrTextureUploadDenied0252) {
		writeError(w, http.StatusForbidden, "skin selection is not permitted by project policy")
		return
	}
	if errors.Is(err, repository.ErrTextureNotSelected0255) {
		writeError(w, http.StatusConflict, "select a saved image before activation")
		return
	}
	if errors.Is(err, repository.ErrTextureCapeDenied0251) {
		writeError(w, http.StatusForbidden, "cape selection is not permitted by project policy")
		return
	}
	if errors.Is(err, repository.ErrTextureRevisionConflict0251) {
		writeError(w, http.StatusConflict, "texture revision conflict; reload and retry")
		return
	}
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "texture assignment not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "texture update failed")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("texture-selection-0251"), Actor: user.Email, Action: "texture:selection:update", Target: profile.UUID + ":" + kind, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": updated})
}

func (s Server) textureHistory0251(w http.ResponseWriter, r *http.Request) {
	profile, _, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный пользовательский сеанс")
		return
	}
	repo, ok := s.textureRepository0251()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "texture database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	kind := strings.ToLower(strings.TrimSpace(r.PathValue("kind")))
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "kind должен быть skin или cape")
		return
	}
	events, err := repo.ListTextureRevisions0251(ctx, profile, kind)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "texture history unavailable")
		return
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{"assignmentId": e.AssignmentID, "revision": e.Revision, "snapshot": json.RawMessage(e.Snapshot), "actorUserId": e.ActorUserID, "event": e.Event, "reason": e.Reason, "createdAt": e.CreatedAt})
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": out})
}
