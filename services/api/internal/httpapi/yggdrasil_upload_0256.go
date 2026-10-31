package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

// The native authlib-injector skin upload protocol uses Minecraft access tokens,
// not Launcher admin tokens. Ownership and project permissions are checked
// again in the transactional repository, independently of supplied path UUID.
func (s Server) yggdrasilTextureWrite0256(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(raw, "Bearer ") {
		writeYggdrasilError119(w, http.StatusUnauthorized, "Minecraft access token required")
		return
	}
	_, profile, user, err := s.validateMinecraftToken119(strings.TrimSpace(strings.TrimPrefix(raw, "Bearer ")))
	if err != nil || profile.Issuer != "launcher" || profile.Realm != "local" ||
		minecraftID119(profile.UUID) != minecraftID119(r.PathValue("uuid")) {
		writeYggdrasilError119(w, http.StatusUnauthorized, "Invalid token or profile")
		return
	}
	kind := r.PathValue("kind")
	if kind != "skin" && kind != "cape" {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid texture type")
		return
	}
	repo, ok := s.Repo.(repository.TextureUploadRepository0252)
	if !ok || s.Storage == nil {
		writeYggdrasilError119(w, http.StatusServiceUnavailable, "Texture storage unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	selectionRepo, ok := s.textureRepository0251()
	if !ok {
		writeYggdrasilError119(w, http.StatusServiceUnavailable, "Texture database unavailable")
		return
	}
	assigned, err := selectionRepo.ListTextureAssignments0251(ctx, profile)
	if err != nil {
		writeYggdrasilError119(w, http.StatusServiceUnavailable, "Texture database unavailable")
		return
	}
	revision := int64(0)
	for _, item := range assigned {
		if item.Kind == kind && item.ProjectID == "" {
			revision = item.Revision
			break
		}
	}
	if r.Method == http.MethodDelete {
		if revision > 0 {
			svc, ok := s.Repo.(repository.TextureServiceRepository0255)
			if !ok {
				writeYggdrasilError119(w, http.StatusServiceUnavailable, "Texture service unavailable")
				return
			}
			_, err = svc.ClearTexture0255(ctx, profile, kind, revision, false)
			if err != nil {
				writeYggdrasilTextureError0256(w, err)
				return
			}
		}
		s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("authlib-texture-reset"), Actor: user.Email, Action: "texture:authlib:reset", Target: profile.UUID + ":" + kind, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.ContentLength > maxMultipartTexture0252 {
		writeYggdrasilError119(w, http.StatusRequestEntityTooLarge, "PNG too large")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartTexture0252)
	mr, err := r.MultipartReader()
	if err != nil {
		writeYggdrasilError119(w, http.StatusBadRequest, "multipart/form-data required")
		return
	}
	var file []byte
	modelName := "classic"
	seenFile, seenModel := false, false
	for i := 0; i < 4; i++ {
		part, nextErr := mr.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			writeYggdrasilError119(w, http.StatusBadRequest, "Invalid multipart request")
			return
		}
		name := part.FormName()
		switch name {
		case "file":
			if seenFile || !strings.EqualFold(part.Header.Get("Content-Type"), "image/png") {
				part.Close()
				writeYggdrasilError119(w, http.StatusBadRequest, "Single image/png file required")
				return
			}
			seenFile = true
			file, err = io.ReadAll(io.LimitReader(part, texturepng.MaxEncodedBytes+1))
			if err != nil || len(file) > texturepng.MaxEncodedBytes {
				part.Close()
				writeYggdrasilError119(w, http.StatusRequestEntityTooLarge, "PNG exceeds limit")
				return
			}
		case "model":
			if seenModel || kind == "cape" {
				part.Close()
				writeYggdrasilError119(w, http.StatusBadRequest, "Invalid model field")
				return
			}
			seenModel = true
			b, readErr := io.ReadAll(io.LimitReader(part, 16))
			if readErr != nil || len(b) >= 16 {
				part.Close()
				writeYggdrasilError119(w, http.StatusBadRequest, "Invalid model")
				return
			}
			if string(b) == "slim" {
				modelName = "slim"
			} else if string(b) != "" {
				part.Close()
				writeYggdrasilError119(w, http.StatusBadRequest, "Model must be slim or empty")
				return
			}
		default:
			part.Close()
			writeYggdrasilError119(w, http.StatusBadRequest, "Unknown multipart field")
			return
		}
		part.Close()
		if i == 3 {
			writeYggdrasilError119(w, http.StatusBadRequest, "Too many multipart parts")
			return
		}
	}
	if !seenFile || len(file) == 0 {
		writeYggdrasilError119(w, http.StatusBadRequest, "PNG file required")
		return
	}
	normalized, err := texturepng.Process(bytes.NewReader(file), kind, modelName)
	if err != nil {
		writeYggdrasilError119(w, http.StatusUnprocessableEntity, "Invalid Minecraft PNG")
		return
	}
	staged := repository.VerifiedTexture0252{Digest: normalized.Digest, Width: normalized.Width, Height: normalized.Height,
		Size: int64(len(normalized.PNG)), Driver: s.Storage.Driver(), ObjectKey: "texture-blobs/sha256/" + normalized.Digest[:2] + "/" + normalized.Digest + ".png",
		Kind: kind, Model: modelName, Visibility: "public", ExpectedRevision: revision, Source: "managed-upload"}
	sr, ok := s.Repo.(interface {
		StageTextureUpload0253(context.Context, model.MinecraftProfile, repository.VerifiedTexture0252) error
	})
	if !ok {
		writeYggdrasilError119(w, http.StatusServiceUnavailable, "Texture staging unavailable")
		return
	}
	if err = sr.StageTextureUpload0253(ctx, profile, staged); err != nil {
		writeYggdrasilTextureError0256(w, err)
		return
	}
	key, size, err := storage.PutTextureImmutable0253(ctx, s.Storage, normalized.Digest, normalized.PNG)
	if err != nil {
		writeYggdrasilError119(w, http.StatusServiceUnavailable, "Texture storage write failed")
		return
	}
	staged.ObjectKey = key
	staged.Size = size
	if _, err = repo.UploadTexture0252(ctx, profile, staged); err != nil {
		writeYggdrasilTextureError0256(w, err)
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: bridgeAuditID910("authlib-texture-upload"), Actor: user.Email, Action: "texture:authlib:upload", Target: profile.UUID + ":" + kind, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	w.WriteHeader(http.StatusNoContent)
}
func writeYggdrasilTextureError0256(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, repository.ErrTextureRevisionConflict0251):
		status = http.StatusConflict
	case errors.Is(err, repository.ErrTextureCapeDenied0251), errors.Is(err, repository.ErrTextureUploadDenied0252):
		status = http.StatusForbidden
	case errors.Is(err, repository.ErrTextureUploadLimit0252):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, repository.ErrNotFound):
		status = http.StatusUnauthorized
	}
	writeYggdrasilError119(w, status, http.StatusText(status))
}

// Batch profile lookup is bounded and never returns private user information.
func (s Server) yggdrasilBatchProfiles0256(w http.ResponseWriter, r *http.Request) {
	repo, err := s.minecraftRepo119()
	if err != nil {
		writeYggdrasilError119(w, http.StatusServiceUnavailable, "Minecraft repository unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var names []string
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&names); err != nil || len(names) > 100 {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid profile lookup request")
		return
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeYggdrasilError119(w, http.StatusBadRequest, "Invalid profile lookup request")
		return
	}
	profiles := make([]map[string]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		if len(name) < 3 || len(name) > 16 || strings.TrimSpace(name) != name {
			writeYggdrasilError119(w, http.StatusBadRequest, "Invalid profile name")
			return
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		profile, err := repo.GetMinecraftProfileByName(name)
		if err == nil && profile.Issuer == "launcher" && profile.Realm == "local" {
			profiles = append(profiles, map[string]string{"id": minecraftID119(profile.UUID), "name": profile.Name})
		}
	}
	writeJSON(w, http.StatusOK, profiles)
}
