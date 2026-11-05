package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func (s Server) textureAdminRepo0259(w http.ResponseWriter) (repository.TextureAdminRepository0259, bool) {
	repo, ok := s.Repo.(repository.TextureAdminRepository0259)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "Для хранилища политик текстур необходим PostgreSQL")
		return nil, false
	}
	return repo, true
}
func adminTextureProject0259(r *http.Request) (string, bool) {
	project := strings.TrimSpace(r.URL.Query().Get("projectId"))
	return project, len(project) <= 128 && !strings.ContainsAny(project, "\r\n\x00")
}
func adminTextureError0259(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrTexturePolicyInvalid0259):
		writeError(w, 400, "Некорректная политика текстур или изображение по умолчанию: допустимы только проверенные публичные PNG")
	case errors.Is(err, repository.ErrTexturePolicyConflict0259):
		writeError(w, 409, "Политика текстур изменилась: обновите текущую ревизию")
	case errors.Is(err, repository.ErrNotFound):
		writeError(w, 404, "Проект или пользователь не найден")
	default:
		writeError(w, 503, "Хранилище политик текстур недоступно")
	}
}
func adminTextureRead0259[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var request T
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		writeError(w, 400, "Некорректный JSON операции с текстурами")
		return request, false
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, 400, "Лишние данные после объекта JSON")
		return request, false
	}
	return request, true
}
func (s Server) adminTexturePolicyGet0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	result, err := repo.GetTexturePolicy0259(r.Context(), project)
	if err != nil {
		adminTextureError0259(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s Server) adminTexturePolicyPut0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	req, ok := adminTextureRead0259[repository.TexturePolicyChange0259](w, r)
	if !ok {
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	result, err := repo.SaveTexturePolicy0259(r.Context(), project, req, claims.Sub)
	if err != nil {
		adminTextureError0259(w, err)
		return
	}
	s.audit(r, claims.Email, "texture:policy:update", project)
	writeJSON(w, 200, result)
}
func (s Server) adminTexturePolicyHistory0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	result, err := repo.ListTexturePolicyHistory0259(r.Context(), project)
	if err != nil {
		adminTextureError0259(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": result})
}
func (s Server) adminTextureExceptions0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	user := strings.TrimSpace(r.URL.Query().Get("userId"))
	if len(user) > 128 {
		writeError(w, 400, "Некорректный идентификатор пользователя")
		return
	}
	result, err := repo.ListTextureExceptions0259(r.Context(), project, user)
	if err != nil {
		adminTextureError0259(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": result})
}
func (s Server) adminTextureExceptionPut0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	user := strings.TrimSpace(r.PathValue("userId"))
	if user == "" || len(user) > 128 {
		writeError(w, 400, "Некорректный идентификатор пользователя")
		return
	}
	req, ok := adminTextureRead0259[repository.TextureException0259](w, r)
	if !ok {
		return
	}
	if req.UserID != "" && req.UserID != user {
		writeError(w, 400, "Идентификатор пользователя не совпадает")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	if err = repo.SetTextureException0259(r.Context(), project, user, req, claims.Sub); err != nil {
		adminTextureError0259(w, err)
		return
	}
	s.audit(r, claims.Email, "texture:exception:update", project+":"+user+":"+req.Kind)
	writeJSON(w, 200, map[string]any{"status": "saved"})
}
func (s Server) adminTextureExceptionHistory0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	result, err := repo.ListTextureExceptionHistory0259(r.Context(), project)
	if err != nil {
		adminTextureError0259(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": result})
}
func (s Server) adminTextureDefaultOptions0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	result, err := repo.ListTextureDefaultOptions0259(r.Context(), project)
	if err != nil {
		adminTextureError0259(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": result})
}

func (s Server) adminTexturePlayerHistory0259(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.textureAdminRepo0259(w)
	if !ok {
		return
	}
	project, valid := adminTextureProject0259(r)
	if !valid {
		writeError(w, 400, "Недопустимый идентификатор проекта")
		return
	}
	user := strings.TrimSpace(r.PathValue("userId"))
	if user == "" || len(user) > 128 {
		writeError(w, 400, "Некорректный идентификатор пользователя")
		return
	}
	result, err := repo.ListTexturePlayerHistory0259(r.Context(), project, user)
	if err != nil {
		adminTextureError0259(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": result})
}
