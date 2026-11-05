package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Каждая операция разрешается по каноническому локальному Minecraft UUID
// аутентифицированной учётной записи; profileUuid служит только строгим
// утверждением о владении.
type textureServiceRequest0255 struct {
	ProfileUUID      string `json:"profileUuid,omitempty"`
	ExpectedRevision *int64 `json:"expectedRevision,omitempty"`
	Digest           string `json:"digest,omitempty"`
	Model            string `json:"model,omitempty"`
	Visibility       string `json:"visibility,omitempty"`
}

func textureServiceDecode0255(w http.ResponseWriter, r *http.Request, profile model.MinecraftProfile) (textureServiceRequest0255, bool) {
	var input textureServiceRequest0255
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "Некорректный JSON-запрос")
		return input, false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "Требуется один объект JSON")
		return input, false
	}
	if input.ProfileUUID != "" && minecraftID119(input.ProfileUUID) != minecraftID119(profile.UUID) {
		writeError(w, http.StatusForbidden, "Профиль Minecraft не принадлежит данной учётной записи")
		return input, false
	}
	return input, true
}

func textureServiceError0255(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrTextureRevisionConflict0251):
		writeError(w, http.StatusConflict, "Конфликт ревизии текстуры: обновите данные и повторите попытку")
	case errors.Is(err, repository.ErrTextureInUse0255):
		writeError(w, http.StatusConflict, "Перед удалением необходимо сбросить выбор текстуры")
	case errors.Is(err, repository.ErrTextureUploadDenied0252), errors.Is(err, repository.ErrTextureCapeDenied0251):
		writeError(w, http.StatusForbidden, "Выбор текстуры запрещён политикой")
	case errors.Is(err, repository.ErrNotFound), errors.Is(err, repository.ErrTextureNotSelected0255):
		writeError(w, http.StatusNotFound, "Текстура недоступна для данной учётной записи")
	default:
		writeError(w, http.StatusServiceUnavailable, "Ошибка операции с базой данных текстур")
	}
}

func (s Server) textureServiceRepo0255() (repository.TextureServiceRepository0255, bool) {
	v, ok := s.Repo.(repository.TextureServiceRepository0255)
	return v, ok
}

func (s Server) textureLibraryList0255(w http.ResponseWriter, r *http.Request) {
	profile, _, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Требуется авторизация")
		return
	}
	repo, ok := s.textureServiceRepo0255()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" && kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "Тип должен быть skin или cape")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	items, err := repo.ListSavedTextures0255(ctx, profile, kind)
	if err != nil {
		textureServiceError0255(w, err)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"profileUuid": profile.UUID, "items": items}})
}

func (s Server) textureSavedSelect0255(w http.ResponseWriter, r *http.Request) {
	profile, user, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Требуется авторизация")
		return
	}
	repo, ok := s.textureServiceRepo0255()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	kind := r.PathValue("kind")
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "Недопустимый тип")
		return
	}
	input, ok := textureServiceDecode0255(w, r, profile)
	if !ok {
		return
	}
	if input.ExpectedRevision == nil || *input.ExpectedRevision < 0 || len(input.Digest) != 64 || (input.Model != "classic" && input.Model != "slim") ||
		(input.Visibility != "public" && input.Visibility != "private" && input.Visibility != "unlisted") || (kind == "cape" && input.Model != "classic") {
		writeError(w, http.StatusBadRequest, "Требуются digest, expectedRevision, model и visibility")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	updated, err := repo.SelectSavedTexture0255(ctx, profile, kind, input.Digest, *input.ExpectedRevision, input.Model, input.Visibility)
	if err != nil {
		textureServiceError0255(w, err)
		return
	}
	s.textureServiceAudit0255(r, user, profile, kind, "select")
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": updated})
}

func (s Server) textureClear0255(w http.ResponseWriter, r *http.Request) {
	profile, user, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Требуется авторизация")
		return
	}
	repo, ok := s.textureServiceRepo0255()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	kind := r.PathValue("kind")
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "Недопустимый тип")
		return
	}
	input, ok := textureServiceDecode0255(w, r, profile)
	if !ok {
		return
	}
	if input.ExpectedRevision == nil || *input.ExpectedRevision < 1 || input.Digest != "" || input.Model != "" || input.Visibility != "" {
		writeError(w, http.StatusBadRequest, "Требуется expectedRevision")
		return
	}
	deleteAsset := r.Method == http.MethodDelete
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	updated, err := repo.ClearTexture0255(ctx, profile, kind, *input.ExpectedRevision, deleteAsset)
	if err != nil {
		textureServiceError0255(w, err)
		return
	}
	action := "reset"
	if deleteAsset {
		action = "delete"
	}
	s.textureServiceAudit0255(r, user, profile, kind, action)
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": updated})
}

func (s Server) textureSavedImage0255(w http.ResponseWriter, r *http.Request) {
	profile, _, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Требуется авторизация")
		return
	}
	repo, ok := s.textureServiceRepo0255()
	if !ok || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище текстур недоступно")
		return
	}
	kind, digest := r.PathValue("kind"), r.PathValue("digest")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	meta, found, err := repo.ReadSavedTextureBlob0255(ctx, profile, kind, digest)
	if err != nil {
		textureServiceError0255(w, err)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	s.serveVerifiedTexture0255(w, r, digest, meta, true)
}

func (s Server) textureSavedDelete0255(w http.ResponseWriter, r *http.Request) {
	profile, user, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Требуется авторизация")
		return
	}
	repo, ok := s.textureServiceRepo0255()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	kind, digest := r.PathValue("kind"), strings.ToLower(r.PathValue("digest"))
	if (kind != "skin" && kind != "cape") || len(digest) != 64 {
		writeError(w, http.StatusBadRequest, "Некорректный тип или digest")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := repo.DeleteSavedTexture0255(ctx, profile, kind, digest); err != nil {
		textureServiceError0255(w, err)
		return
	}
	s.textureServiceAudit0255(r, user, profile, kind, "library-delete")
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"deleted": true, "digest": digest, "kind": kind}})
}

func (s Server) textureServiceAudit0255(r *http.Request, user model.User, p model.MinecraftProfile, kind, action string) {
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("texture-" + action + "-0255"), Actor: user.Email, Action: "texture:" + action, Target: p.UUID + ":" + kind, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
}
