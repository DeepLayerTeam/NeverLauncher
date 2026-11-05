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

// Контроль злоупотреблений в рамках экземпляра; в кластерах также нужен лимит
// на ingress.
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

// textureImport0254 — авторизованный импорт URL только в собственный профиль.
// Удалённые URL никогда не сохраняются как действующие ссылки на текстуры. Хранятся
// только проверенные нормализованные PNG по тем же CAS, квотам и пути хранилища,
// что и загрузки.
func (s Server) textureImport0254(w http.ResponseWriter, r *http.Request) {
	profile, user, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Необходим авторизованный локальный профиль Minecraft")
		return
	}
	if s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище текстур недоступно")
		return
	}
	if _, ok := s.Repo.(repository.TextureUploadRepository0252); !ok {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.PathValue("kind")))
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "Тип должен быть skin или cape")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var input textureURLImport0254
	if err := dec.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "Некорректный JSON импорта")
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "Ожидался ровно один объект JSON")
		return
	}
	if input.ProfileUUID != "" && minecraftID119(input.ProfileUUID) != minecraftID119(profile.UUID) {
		writeError(w, http.StatusForbidden, "Профиль Minecraft не принадлежит данной учётной записи")
		return
	}
	if input.ExpectedRevision == nil || *input.ExpectedRevision < 0 {
		writeError(w, http.StatusBadRequest, "Необходимо указать неотрицательное expectedRevision")
		return
	}
	if input.Model == "" {
		input.Model = "classic"
	}
	if input.Visibility == "" {
		input.Visibility = "public"
	}
	if input.Model != "classic" && input.Model != "slim" || kind == "cape" && input.Model != "classic" || (input.Visibility != "public" && input.Visibility != "private" && input.Visibility != "unlisted") {
		writeError(w, http.StatusBadRequest, "Некорректная модель или настройка видимости")
		return
	}
	// Отклоняйте заведомо устаревшие ревизии CAS до использования исходящих сетевых
	// ресурсов. StageTextureUpload0253 перепроверяет их под блокировкой БД.
	selectionRepo, ok := s.textureRepository0251()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	preflightCtx, preflightCancel := context.WithTimeout(r.Context(), 5*time.Second)
	assigned, preflightErr := selectionRepo.ListTextureAssignments0251(preflightCtx, profile)
	preflightCancel()
	if preflightErr != nil {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
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
		writeError(w, http.StatusConflict, "Конфликт ревизии текстуры: обновите данные и повторите попытку")
		return
	}
	if !admitTextureURLImport0254(user.ID) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "Превышен лимит импорта текстур по URL")
		return
	}
	fetcher, err := texturefetch.New(os.Getenv("LAUNCHER_TEXTURE_FETCH_HOST_ALLOWLIST"))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Некорректная политика хоста для загрузки текстур")
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
		// Не отражайте удалённое содержимое, URL, результаты DNS или внутренние адреса.
		writeError(w, status, "Удалённый адрес должен использовать общедоступный HTTPS и возвращать корректный PNG Minecraft допустимого размера")
		return
	}
	s.persistTexture0254(w, r, profile, user, normalized, kind, input.Model, input.Visibility, *input.ExpectedRevision, "import")
}

// persistTexture0254 — единый путь сохранения для multipart-загрузок и
// удалённого импорта. Подготовка выполняется до любой записи объекта.
func (s Server) persistTexture0254(w http.ResponseWriter, r *http.Request, profile model.MinecraftProfile, user model.User, normalized texturepng.Result, kind, modelName, visibility string, expected int64, action string) {
	repo, ok := s.Repo.(repository.TextureUploadRepository0252)
	if !ok || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище текстур недоступно")
		return
	}
	// Резервируйте хеш и проверяйте владение, ревизию и квоту ДО долговременной
	// записи объекта. Неудачные сохранения остаются видны очистке в виде строк
	// staging.
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
		writeError(w, http.StatusServiceUnavailable, "Подготовка текстуры недоступна")
		return
	}
	stageCtx, stageCancel := context.WithTimeout(r.Context(), 10*time.Second)
	stageErr := stagingRepo.StageTextureUpload0253(stageCtx, profile, staged)
	stageCancel()
	switch {
	case errors.Is(stageErr, repository.ErrTextureRevisionConflict0251):
		writeError(w, http.StatusConflict, "Конфликт ревизии текстуры: обновите данные и повторите попытку")
		return
	case errors.Is(stageErr, repository.ErrTextureUploadDenied0252):
		writeError(w, http.StatusForbidden, "Загрузка текстуры запрещена политикой")
		return
	case errors.Is(stageErr, repository.ErrTextureUploadLimit0252):
		writeError(w, http.StatusRequestEntityTooLarge, "Превышена квота текстур")
		return
	case errors.Is(stageErr, repository.ErrNotFound):
		writeError(w, http.StatusForbidden, "Не совпадают данные владельца профиля Minecraft")
		return
	case stageErr != nil:
		writeError(w, http.StatusServiceUnavailable, "Не удалось выполнить транзакцию подготовки текстуры")
		return
	}
	key, size, err := storage.PutTextureImmutable0253(r.Context(), s.Storage, normalized.Digest, normalized.PNG)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Не удалось сохранить PNG")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	input := repository.VerifiedTexture0252{Digest: normalized.Digest, Width: normalized.Width, Height: normalized.Height, Size: size, Driver: s.Storage.Driver(), ObjectKey: key, Kind: kind, Model: modelName, Visibility: visibility, ExpectedRevision: expected, Source: source}
	updated, err := repo.UploadTexture0252(ctx, profile, input)
	switch {
	case errors.Is(err, repository.ErrTextureRevisionConflict0251):
		writeError(w, http.StatusConflict, "Конфликт ревизии текстуры: обновите данные и повторите попытку")
		return
	case errors.Is(err, repository.ErrTextureUploadDenied0252), errors.Is(err, repository.ErrTextureCapeDenied0251):
		writeError(w, http.StatusForbidden, "Политика запрещает загрузку текстуры")
		return
	case errors.Is(err, repository.ErrTextureUploadLimit0252):
		writeError(w, http.StatusRequestEntityTooLarge, "Текстура превышает квоту проекта")
		return
	case errors.Is(err, repository.ErrNotFound):
		writeError(w, http.StatusForbidden, "Не удалось подтвердить владение профилем")
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "Не удалось выполнить транзакцию загрузки текстуры")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("texture-" + action + "-0254"), Actor: user.Email, Action: "texture:" + action, Target: profile.UUID + ":" + kind, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"assignment": updated, "digest": normalized.Digest, "width": normalized.Width, "height": normalized.Height, "bytes": size, "previewUrl": "/api/v1/me/textures/" + kind + "/image", "method": action}})
}
