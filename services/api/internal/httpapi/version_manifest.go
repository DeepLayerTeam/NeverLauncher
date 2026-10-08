package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type versionManifestRequest struct {
	Minecraft   model.MinecraftInfo `json:"minecraft"`
	Runtime     model.RuntimeInfo   `json:"runtime"`
	Directories model.Directories   `json:"directories"`
}

func (s Server) adminVersionManifestUpdate(w http.ResponseWriter, r *http.Request) {
	projectID, versionID := r.PathValue("projectId"), r.PathValue("versionId")
	unlock, lockErr := s.lockPackageMutation(r.Context(), "package:"+versionID)
	if lockErr != nil {
		writeError(w, http.StatusConflict, "package mutation already in progress: "+lockErr.Error())
		return
	}
	defer unlock()
	versions, err := s.Repo.ListVersions(projectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	var release *model.ReleaseVersion
	for i := range versions {
		if versions[i].ID == versionID {
			release = &versions[i]
			break
		}
	}
	if release == nil {
		writeError(w, http.StatusNotFound, "версия не найдена")
		return
	}
	if release.Status == "published" {
		writeError(w, http.StatusConflict, "published manifest immutable; создайте новую версию")
		return
	}
	var req versionManifestRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if _, enabled, validationErr := compatibilityMetadataPath(req.Minecraft, req.Runtime); validationErr != nil {
		writeError(w, http.StatusBadRequest, validationErr.Error())
		return
	} else if enabled && strings.TrimSpace(req.Minecraft.Version) == "" {
		writeError(w, http.StatusBadRequest, "Compatibility Engine требует minecraft.version")
		return
	}
	manifest := release.Manifest
	manifest.Minecraft = req.Minecraft
	manifest.Runtime = req.Runtime
	manifest.Directories = req.Directories
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	manifest.Signature = nil
	updated, err := s.Repo.UpdateVersionManifest(projectID, versionID, manifest)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "manifest:update", versionID)
	writeJSON(w, http.StatusOK, updated)
}

func compatibilityMetadataPath(minecraft model.MinecraftInfo, runtime model.RuntimeInfo) (string, bool, error) {
	strategy := strings.ToLower(strings.TrimSpace(runtime.Launch.ClasspathStrategy))
	if strategy != "compatibility" && strategy != "mojang" {
		return "", false, nil
	}
	version := strings.TrimSpace(minecraft.Version)
	if version == "" || version == "." || version == ".." || strings.ContainsAny(version, `/\`) {
		return "", true, errors.New("Совместимость Движок: Minecraft.версия должен быть безопасным версия ID")
	}
	metadataPath := strings.TrimSpace(runtime.Launch.VersionMetadataPath)
	if metadataPath == "" {
		metadataPath = fmt.Sprintf("versions/%s/%s.json", version, version)
	}
	normalized := strings.ReplaceAll(metadataPath, `\`, "/")
	clean := path.Clean(normalized)
	if strings.HasPrefix(normalized, "/") || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != normalized {
		return "", true, fmt.Errorf("Совместимость Движок: небезопасный versionMetadataPath %q", metadataPath)
	}
	if !strings.HasSuffix(strings.ToLower(clean), ".json") {
		return "", true, errors.New("Совместимость Движок: versionMetadataPath должен указывать на JSON")
	}
	return clean, true, nil
}

func validateCompatibilityManifest(manifest model.Manifest) error {
	metadataPath, enabled, err := compatibilityMetadataPath(manifest.Minecraft, manifest.Runtime)
	if err != nil || !enabled {
		return err
	}
	for _, file := range manifest.Files {
		if strings.ReplaceAll(file.Path, `\`, "/") == metadataPath && file.Required {
			return nil
		}
	}
	return fmt.Errorf("Совместимость Движок: подписанный релиз не содержит обязательный метаданные файл %s", metadataPath)
}
