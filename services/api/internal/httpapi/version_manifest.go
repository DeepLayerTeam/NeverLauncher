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
	Minecraft        *model.MinecraftInfo        `json:"minecraft"`
	Runtime          *model.RuntimeInfo          `json:"runtime"`
	Directories      *model.Directories          `json:"directories"`
	FileRules        *[]model.FileRule           `json:"fileRules,omitempty"`
	ComponentCatalog *model.ComponentCatalog0241 `json:"componentCatalog,omitempty"`
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
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	minecraft := release.Manifest.Minecraft
	runtimeConfig := release.Manifest.Runtime
	if req.Minecraft != nil {
		minecraft = *req.Minecraft
	}
	if req.Runtime != nil {
		runtimeConfig = *req.Runtime
	}
	if _, enabled, validationErr := compatibilityMetadataPath(minecraft, runtimeConfig); validationErr != nil {
		writeError(w, http.StatusBadRequest, validationErr.Error())
		return
	} else if enabled && strings.TrimSpace(minecraft.Version) == "" {
		writeError(w, http.StatusBadRequest, "Compatibility Engine требует minecraft.version")
		return
	}
	manifest := release.Manifest
	manifest.Minecraft = minecraft
	manifest.Runtime = runtimeConfig
	if req.Directories != nil {
		manifest.Directories = *req.Directories
	}
	if req.FileRules != nil {
		manifest.FileRules = *req.FileRules
	}
	if req.ComponentCatalog != nil {
		if manifest.SchemaVersion != model.ManifestSchemaV3 {
			writeError(w, http.StatusBadRequest, "componentCatalog requires a v3 release; create with manifestSchemaVersion=3.0")
			return
		}
		if manifest.ComponentCatalog == nil {
			writeError(w, http.StatusConflict, "release v3 has no validated component catalog")
			return
		}
		revision := manifest.ComponentCatalog.Revision + 1
		if req.ComponentCatalog.SchemaVersion == model.ComponentCatalogSchema0244 {
			manifest.ComponentCatalog = ptrComponentCatalog0241(model.NewComponentCatalog0244(*req.ComponentCatalog, revision))
		} else if req.ComponentCatalog.SchemaVersion == model.ComponentCatalogSchema0243 {
			manifest.ComponentCatalog = ptrComponentCatalog0241(model.NewComponentCatalog0243(*req.ComponentCatalog, revision))
		} else if req.ComponentCatalog.SchemaVersion == model.ComponentCatalogSchema0242 {
			manifest.ComponentCatalog = ptrComponentCatalog0241(model.NewComponentCatalog0242(*req.ComponentCatalog, revision))
		} else if req.ComponentCatalog.SchemaVersion == model.ComponentCatalogSchema0241 {
			manifest.ComponentCatalog = ptrComponentCatalog0241(model.NewComponentCatalog0241(req.ComponentCatalog.Components, revision))
		} else {
			writeError(w, http.StatusBadRequest, "unsupported component catalog schemaVersion")
			return
		}
	}
	if err := model.ValidateManifestSchema(manifest); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
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

func ptrComponentCatalog0241(c model.ComponentCatalog0241) *model.ComponentCatalog0241 { return &c }

func validateCompatibilityManifest(manifest model.Manifest) error {
	if manifest.SchemaVersion == model.ManifestSchemaV2 || manifest.SchemaVersion == model.ManifestSchemaV3 {
		if err := model.ValidatePublishFileOwnership0224(manifest); err != nil {
			return err
		}
		// Drafts may be incomplete, but no package reaches publish with a
		// missing runtime or an invalid effective command line.
		if manifest.Runtime.Java.MajorVersion <= 0 {
			return errors.New("v2 publish requires runtime.java.majorVersion")
		}
		if err := model.ValidateRuntimeConstraints0223(manifest); err != nil {
			return err
		}
	}
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
