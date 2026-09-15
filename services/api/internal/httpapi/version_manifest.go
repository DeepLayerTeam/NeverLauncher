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
	unlock := s.lockPackageMutation()
	defer unlock()
	projectID, versionID := r.PathValue("projectId"), r.PathValue("versionId")
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

func (s Server) publishSigned(projectID, profileID, channel, version string) (model.ReleaseVersion, error) {
	unlock := s.lockPackageMutation()
	defer unlock()
	if profileID == "" {
		profileID = "vanilla"
	}
	if channel == "" {
		channel = "stable"
	}
	if version == "" {
		version = time.Now().UTC().Format("20060102150405")
	}

	versions, err := s.Repo.ListVersions(projectID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	var release *model.ReleaseVersion
	for i := range versions {
		item := &versions[i]
		if item.ProfileID == profileID && item.Channel == channel && item.Version == version {
			release = item
			break
		}
	}
	if release == nil {
		created, createErr := s.Repo.CreateVersion(projectID, profileID, channel, version)
		if createErr != nil {
			return model.ReleaseVersion{}, createErr
		}
		release = &created
	}
	if release.Status == "published" {
		return model.ReleaseVersion{}, errors.New("release уже опубликован; published manifest immutable")
	}

	manifest := release.Manifest
	manifest.SchemaVersion = "1.0"
	manifest.ProjectID = projectID
	manifest.ProfileID = profileID
	manifest.Channel = channel
	manifest.Version = version
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	files, err := s.Repo.ListFiles(projectID, release.ID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	manifest.Files = make([]model.ManifestFile, 0, len(files))
	for _, file := range files {
		manifest.Files = append(manifest.Files, model.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256, URL: file.URL, Required: file.Required, Executable: file.Executable, TargetOS: append([]string(nil), file.TargetOS...)})
	}
	if err = validateCompatibilityManifest(manifest); err != nil {
		return model.ReleaseVersion{}, err
	}
	signed, err := s.signManifest(manifest)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	return s.Repo.PublishVersionWithManifest(projectID, profileID, channel, version, signed)
}

func compatibilityMetadataPath(minecraft model.MinecraftInfo, runtime model.RuntimeInfo) (string, bool, error) {
	strategy := strings.ToLower(strings.TrimSpace(runtime.Launch.ClasspathStrategy))
	if strategy != "compatibility" && strategy != "mojang" {
		return "", false, nil
	}
	version := strings.TrimSpace(minecraft.Version)
	if version == "" || version == "." || version == ".." || strings.ContainsAny(version, `/\`) {
		return "", true, errors.New("Compatibility Engine: minecraft.version должен быть безопасным version id")
	}
	metadataPath := strings.TrimSpace(runtime.Launch.VersionMetadataPath)
	if metadataPath == "" {
		metadataPath = fmt.Sprintf("versions/%s/%s.json", version, version)
	}
	normalized := strings.ReplaceAll(metadataPath, `\`, "/")
	clean := path.Clean(normalized)
	if strings.HasPrefix(normalized, "/") || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != normalized {
		return "", true, fmt.Errorf("Compatibility Engine: небезопасный versionMetadataPath %q", metadataPath)
	}
	if !strings.HasSuffix(strings.ToLower(clean), ".json") {
		return "", true, errors.New("Compatibility Engine: versionMetadataPath должен указывать на JSON")
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
	return fmt.Errorf("Compatibility Engine: signed release не содержит обязательный metadata файл %s", metadataPath)
}
