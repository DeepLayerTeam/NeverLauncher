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
		writeError(w, http.StatusUnauthorized, "authenticated local Minecraft profile required")
		return
	}
	if _, ok := s.Repo.(repository.TextureUploadRepository0252); !ok || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "texture storage unavailable")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.PathValue("kind")))
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "kind must be skin or cape")
		return
	}
	if r.ContentLength > maxMultipartTexture0252 {
		writeError(w, http.StatusRequestEntityTooLarge, "upload exceeds size limit")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartTexture0252)
	multipart, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusUnsupportedMediaType, "multipart/form-data required")
		return
	}
	fields := make(map[string]string, 4)
	var file []byte
	sawFile := false
	for count := 0; ; count++ {
		if count >= 8 {
			writeError(w, http.StatusBadRequest, "too many multipart parts")
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
				writeError(w, http.StatusBadRequest, "one PNG file required")
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
				writeError(w, http.StatusRequestEntityTooLarge, "PNG exceeds size limit")
				return
			}
			continue
		}
		switch name {
		case "model", "visibility", "expectedRevision", "profileUuid":
		default:
			part.Close()
			writeError(w, http.StatusBadRequest, "unexpected multipart field")
			return
		}
		if _, duplicate := fields[name]; duplicate {
			part.Close()
			writeError(w, http.StatusBadRequest, "duplicate multipart field")
			return
		}
		value, readErr := io.ReadAll(io.LimitReader(part, 257))
		part.Close()
		if readErr != nil {
			textureMultipartError0252(w, readErr)
			return
		}
		if len(value) > 256 {
			writeError(w, http.StatusBadRequest, "multipart field too long")
			return
		}
		fields[name] = string(value)
	}
	if !sawFile || len(file) == 0 {
		writeError(w, http.StatusBadRequest, "file PNG required")
		return
	}
	if fields["profileUuid"] != "" && minecraftID119(fields["profileUuid"]) != minecraftID119(profile.UUID) {
		writeError(w, http.StatusForbidden, "Minecraft profile does not belong to account")
		return
	}
	revisionRaw, exists := fields["expectedRevision"]
	if !exists || revisionRaw == "" {
		writeError(w, http.StatusBadRequest, "expectedRevision required (0 for first upload)")
		return
	}
	expected, err := strconv.ParseInt(revisionRaw, 10, 64)
	if err != nil || expected < 0 {
		writeError(w, http.StatusBadRequest, "invalid expectedRevision")
		return
	}
	visibility := fields["visibility"]
	if visibility == "" {
		visibility = "public"
	}
	if visibility != "public" && visibility != "private" && visibility != "unlisted" {
		writeError(w, http.StatusBadRequest, "invalid visibility")
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
		writeError(w, status, "invalid PNG: "+err.Error())
		return
	}
	s.persistTexture0254(w, r, profile, user, normalized, kind, modelName, visibility, expected, "upload")
}

func textureMultipartError0252(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "multipart upload exceeds size limit")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid multipart upload")
}

func (s Server) textureBlobGet0252(w http.ResponseWriter, r *http.Request) {
	s.serveTextureBlob0252(w, r, r.PathValue("digest"), model.MinecraftProfile{}, false)
}

func (s Server) textureMineImage0252(w http.ResponseWriter, r *http.Request) {
	profile, _, err := s.ownedTextureProfile0251(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	kind := r.PathValue("kind")
	if kind != "skin" && kind != "cape" {
		writeError(w, http.StatusBadRequest, "invalid kind")
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
	for _, item := range items {
		if item.Kind == kind && item.ProjectID == "" && item.BlobDigest != "" {
			s.serveTextureBlob0252(w, r, item.BlobDigest, profile, true)
			return
		}
	}
	writeError(w, http.StatusNotFound, "managed texture not found")
}

func (s Server) serveTextureBlob0252(w http.ResponseWriter, r *http.Request, digest string, profile model.MinecraftProfile, owner bool) {
	repo, ok := s.Repo.(repository.TextureUploadRepository0252)
	if !ok || s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "texture storage unavailable")
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
		writeError(w, http.StatusServiceUnavailable, "texture metadata unavailable")
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	s.serveVerifiedTexture0255(w, r, digest, meta, owner)
}

// Shared integrity-checked writer for active textures and saved-library previews.
func (s Server) serveVerifiedTexture0255(w http.ResponseWriter, r *http.Request, digest string, meta repository.TextureBlob0252, owner bool) {
	if meta.StorageDriver != s.Storage.Driver() {
		writeError(w, http.StatusServiceUnavailable, "texture storage driver mismatch")
		return
	}
	file, size, err := storage.OpenTexture0252(s.Storage, digest)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "texture blob unavailable")
		return
	}
	defer file.Close()
	if size > texturepng.MaxEncodedBytes || meta.ByteSize > texturepng.MaxEncodedBytes || meta.ByteSize < 1 {
		writeError(w, http.StatusServiceUnavailable, "texture blob size invalid")
		return
	}
	content, err := io.ReadAll(io.LimitReader(file, texturepng.MaxEncodedBytes+1))
	if err != nil || int64(len(content)) != meta.ByteSize {
		writeError(w, http.StatusServiceUnavailable, "texture blob read failed")
		return
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != digest {
		writeError(w, http.StatusServiceUnavailable, "texture blob integrity failed")
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
