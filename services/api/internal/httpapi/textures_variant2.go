package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

const maxMultipartTexture0252 = texturepng.MaxEncodedBytes + 16*1024

func (s Server) textureUpload0252(w http.ResponseWriter, r *http.Request) {
	profile, user, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Необходим авторизованный локальный профиль Minecraft")
		return
	}
	if _, ok := s.Repo.(repository.TextureUploadRepository0252); !ok || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище текстур недоступно")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.PathValue("kind")))
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "Тип должен быть skin или cape")
		return
	}
	if r.ContentLength > maxMultipartTexture0252 {
		writeError(w, http.StatusRequestEntityTooLarge, "Размер загрузки превышает ограничение")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartTexture0252)
	multipart, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusUnsupportedMediaType, "Требуется формат multipart/form-data")
		return
	}
	fields := make(map[string]string, 4)
	var file []byte
	sawFile := false
	for count := 0; ; count++ {
		if count >= 8 {
			writeError(w, http.StatusBadRequest, "Слишком много частей составного запроса")
			return
		}
		part, nextErr := multipart.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			textureMultipartError0252(w, nextErr)
			return
		}
		name := part.FormName()
		if name == "file" {
			if sawFile {
				part.Close()
				writeError(w, http.StatusBadRequest, "Необходимо передать один PNG-файл")
				return
			}
			sawFile = true
			file, err = io.ReadAll(io.LimitReader(part, texturepng.MaxEncodedBytes+1))
			part.Close()
			if err != nil {
				textureMultipartError0252(w, err)
				return
			}
			if len(file) > texturepng.MaxEncodedBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "Размер PNG превышает ограничение")
				return
			}
			continue
		}
		switch name {
		case "model", "visibility", "expectedRevision", "profileUuid":
		default:
			part.Close()
			writeError(w, http.StatusBadRequest, "Неожиданное поле составного запроса")
			return
		}
		if _, duplicate := fields[name]; duplicate {
			part.Close()
			writeError(w, http.StatusBadRequest, "Повторяющееся поле multipart")
			return
		}
		value, readErr := io.ReadAll(io.LimitReader(part, 257))
		part.Close()
		if readErr != nil {
			textureMultipartError0252(w, readErr)
			return
		}
		if len(value) > 256 {
			writeError(w, http.StatusBadRequest, "Слишком длинное поле multipart")
			return
		}
		fields[name] = string(value)
	}
	if !sawFile || len(file) == 0 {
		writeError(w, http.StatusBadRequest, "Необходим PNG-файл")
		return
	}
	if fields["profileUuid"] != "" && minecraftID119(fields["profileUuid"]) != minecraftID119(profile.UUID) {
		writeError(w, http.StatusForbidden, "Профиль Minecraft не принадлежит данной учётной записи")
		return
	}
	revisionRaw, exists := fields["expectedRevision"]
	if !exists || revisionRaw == "" {
		writeError(w, http.StatusBadRequest, "Требуется expectedRevision (0 для первой загрузки)")
		return
	}
	expected, err := strconv.ParseInt(revisionRaw, 10, 64)
	if err != nil || expected < 0 {
		writeError(w, http.StatusBadRequest, "Некорректное значение expectedRevision")
		return
	}
	visibility := fields["visibility"]
	if visibility == "" {
		visibility = "public"
	}
	if visibility != "public" && visibility != "private" && visibility != "unlisted" {
		writeError(w, http.StatusBadRequest, "Некорректное значение видимости")
		return
	}
	modelName := fields["model"]
	if modelName == "" {
		modelName = "classic"
	}
	normalized, err := texturepng.Process(bytes.NewReader(file), kind, modelName)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, texturepng.ErrTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeError(w, status, "Некорректный PNG: "+err.Error())
		return
	}
	s.persistTexture0254(w, r, profile, user, normalized, kind, modelName, visibility, expected, "upload")
}

func textureMultipartError0252(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "Размер multipart-загрузки превышает ограничение")
		return
	}
	writeError(w, http.StatusBadRequest, "Некорректная multipart-загрузка")
}

func (s Server) textureBlobGet0252(w http.ResponseWriter, r *http.Request) {
	s.serveTextureBlob0252(w, r, r.PathValue("digest"), model.MinecraftProfile{}, false)
}

func (s Server) textureMineImage0252(w http.ResponseWriter, r *http.Request) {
	profile, _, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Требуется авторизация")
		return
	}
	kind := r.PathValue("kind")
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "Недопустимый тип")
		return
	}
	repo, ok := s.textureRepository0251()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	items, err := repo.ListTextureAssignments0251(ctx, profile)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "База данных текстур недоступна")
		return
	}
	for _, item := range items {
		if item.Kind == kind && item.ProjectID == "" && item.BlobDigest != "" {
			s.serveTextureBlob0252(w, r, item.BlobDigest, profile, true)
			return
		}
	}
	writeError(w, http.StatusNotFound, "Управляемая текстура не найдена")
}

func (s Server) serveTextureBlob0252(w http.ResponseWriter, r *http.Request, digest string, profile model.MinecraftProfile, owner bool) {
	repo, ok := s.Repo.(repository.TextureUploadRepository0252)
	if !ok || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище текстур недоступно")
		return
	}
	if len(digest) != 64 {
		http.NotFound(w, r)
		return
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			http.NotFound(w, r)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	meta, found, err := repo.ReadTextureBlob0252(ctx, digest, profile, owner)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Метаданные текстуры недоступны")
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	s.serveVerifiedTexture0255(w, r, digest, meta, owner)
}

// Общий проверенный на целостность механизм записи для активных текстур и
// предпросмотров сохранённой библиотеки.
func (s Server) serveVerifiedTexture0255(w http.ResponseWriter, r *http.Request, digest string, meta repository.TextureBlob0252, owner bool) {
	if meta.StorageDriver != s.Storage.Driver() {
		writeError(w, http.StatusServiceUnavailable, "Драйвер хранилища текстур не совпадает с ожидаемым")
		return
	}
	file, size, err := storage.OpenTexture0252(s.Storage, digest)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Данные текстуры недоступны")
		return
	}
	defer file.Close()
	if size > texturepng.MaxEncodedBytes || meta.ByteSize > texturepng.MaxEncodedBytes || meta.ByteSize < 1 {
		writeError(w, http.StatusServiceUnavailable, "Некорректный размер данных текстуры")
		return
	}
	content, err := io.ReadAll(io.LimitReader(file, texturepng.MaxEncodedBytes+1))
	if err != nil || int64(len(content)) != meta.ByteSize {
		writeError(w, http.StatusServiceUnavailable, "Не удалось прочитать данные текстуры")
		return
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != digest {
		writeError(w, http.StatusServiceUnavailable, "Нарушена целостность данных текстуры")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", digest))
	if owner {
		w.Header().Set("Cache-Control", "private, no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
	}
	http.ServeContent(w, r, digest+".png", time.Time{}, bytes.NewReader(content))
}
