package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type packageCreateRequest struct {
	ProjectID             string `json:"projectId"`
	ProfileID             string `json:"profileId"`
	Channel               string `json:"channel"`
	Version               string `json:"version"`
	MinecraftVersion      string `json:"minecraftVersion"`
	Loader                string `json:"loader"`
	ManifestSchemaVersion string `json:"manifestSchemaVersion,omitempty"`
}

type packageActionRequest struct {
	ProjectID string `json:"projectId"`
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
	Version   string `json:"version"`
	ToVersion string `json:"toVersion"`
}

type packageLookup struct {
	Release model.ReleaseVersion
	Files   []model.FileObject
}

func (s Server) packageProductStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"status":        "product-package-pipeline-ready",
		"storageDriver": s.Storage.Driver(),
		"delivery":      s.deliveryPolicyPayload(),
		"realEndpoints": []string{
			"POST /api/v1/packages",
			"POST /api/v1/packages/{packageId}/files",
			"POST /api/v1/packages/{packageId}/validate",
			"POST /api/v1/packages/{packageId}/stage",
			"POST /api/v1/packages/{packageId}/integrity-check",
			"POST /api/v1/packages/{packageId}/runtime-validations/evidence",
			"GET /api/v1/packages/{packageId}/validations",
			"POST /api/v1/packages/{packageId}/publish",
			"POST /api/v1/channels/{channel}/rollback",
			"GET /api/v1/packages/{packageId}",
		},
	}})
}

func (s Server) storageDeliveryPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.deliveryPolicyPayload()})
}

func (s Server) deliveryPolicyPayload() map[string]any {
	mode := firstNonEmpty(strings.TrimSpace(s.Config.StorageDeliveryMode), "reverse-proxy")
	origin := strings.TrimRight(strings.TrimSpace(s.Config.StorageCDNOrigin), "/")
	if mode == "s3-public" && s.Config.StorageS3PublicURL != "" {
		origin = strings.TrimRight(s.Config.StorageS3PublicURL, "/")
	}
	if origin == "" {
		origin = strings.TrimRight(s.Config.PublicURL, "/") + "/api/v1/files"
	}
	return map[string]any{
		"schemaVersion":        apiContractVersion,
		"toolVersion":          s.Version,
		"mode":                 mode,
		"storageDriver":        s.Storage.Driver(),
		"origin":               origin,
		"maxUploadBytes":       s.maxUploadBytes(),
		"urlTemplate":          origin + "/{projectId}/{versionId}/{path}",
		"supportedModes":       []string{"reverse-proxy", "local", "s3-public", "s3-signed-url", "cdn-origin"},
		"integrityPolicy":      []string{"sha256-after-upload", "storage-open-before-validate", "manifest-files-match-storage", "path-traversal-rejected"},
		"immutablePackageKeys": true,
	}
}

func (s Server) maxUploadBytes() int64 {
	if s.Config.StorageMaxUploadBytes > 0 {
		return s.Config.StorageMaxUploadBytes
	}
	return 512 << 20
}

func (s Server) deliveryURL(projectID, versionID, relativePath string) string {
	cleanPath := path.Clean("/" + strings.TrimSpace(relativePath))
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	mode := firstNonEmpty(strings.TrimSpace(s.Config.StorageDeliveryMode), "reverse-proxy")
	origin := ""
	if mode == "cdn-origin" && strings.TrimSpace(s.Config.StorageCDNOrigin) != "" {
		origin = strings.TrimRight(strings.TrimSpace(s.Config.StorageCDNOrigin), "/")
	} else if mode == "s3-public" && strings.TrimSpace(s.Config.StorageS3PublicURL) != "" {
		origin = strings.TrimRight(strings.TrimSpace(s.Config.StorageS3PublicURL), "/")
	}
	if origin != "" {
		return origin + "/" + path.Join(projectID, versionID, cleanPath)
	}
	return fmt.Sprintf("%s/api/v1/files/%s/%s/%s", strings.TrimRight(s.Config.PublicURL, "/"), projectID, versionID, cleanPath)
}

func (s Server) packageCreate(w http.ResponseWriter, r *http.Request) {
	var req packageCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	if req.ProjectID == "" {
		req.ProjectID = r.PathValue("projectId")
	}
	if req.ProfileID == "" {
		req.ProfileID = "vanilla"
	}
	if req.Channel == "" {
		req.Channel = "dev"
	}
	if req.Version == "" {
		req.Version = time.Now().UTC().Format("20060102150405")
	}
	if req.ProjectID == "" {
		writeError(w, http.StatusBadRequest, "projectId обязателен")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", req.ProjectID, "package", "") {
		return
	}
	if _, err := s.Repo.GetProject(req.ProjectID); err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	profiles, _ := s.Repo.ListProfiles(req.ProjectID)
	var selectedProfile model.Profile
	profileExists := false
	for _, profile := range profiles {
		if profile.ID == req.ProfileID {
			selectedProfile = profile
			profileExists = true
			break
		}
	}
	if !profileExists {
		if !s.authorizeProjectAction(w, r, claims, "project:write", req.ProjectID, "profile", req.ProfileID) {
			return
		}
		if _, err := s.Repo.SaveProfile(model.Profile{ID: req.ProfileID, ProjectID: req.ProjectID, Name: req.ProfileID, Loader: firstNonEmpty(req.Loader, "vanilla")}); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if profileExists && selectedProfile.MinecraftVersion != "" {
		game := model.MinecraftInfo{Version: req.MinecraftVersion, Loader: req.Loader, LoaderVersion: selectedProfile.LoaderVersion}
		if err := model.ValidateProfileLaunch0382(model.ProfileSpecOf(selectedProfile), game, 0, false); err != nil {
			writeError(w, 409, err.Error())
			return
		}
	}
	unlockCreate, lockErr := s.lockPackageMutation(r.Context(), "package:"+req.ProjectID+"-"+req.ProfileID+"-"+req.Version)
	if lockErr != nil {
		writeError(w, http.StatusConflict, lockErr.Error())
		return
	}
	defer unlockCreate()
	if req.ManifestSchemaVersion != "" && req.ManifestSchemaVersion != model.ManifestSchemaV2 && req.ManifestSchemaVersion != model.ManifestSchemaV3 {
		writeError(w, http.StatusBadRequest, "unsupported manifestSchemaVersion")
		return
	}
	var release model.ReleaseVersion
	if req.ManifestSchemaVersion == model.ManifestSchemaV3 {
		creator, ok := s.Repo.(interface {
			CreateVersionV3(string, string, string, string) (model.ReleaseVersion, error)
		})
		if !ok {
			writeError(w, http.StatusInternalServerError, "v3 release creation unavailable")
			return
		}
		release, err = creator.CreateVersionV3(req.ProjectID, req.ProfileID, req.Channel, req.Version)
	} else {
		release, err = s.Repo.CreateVersion(req.ProjectID, req.ProfileID, req.Channel, req.Version)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Persist the actual selected Minecraft/loader metadata into the release,
	// not only into the wizard draft. It will be covered by the Ed25519 signature.
	if strings.TrimSpace(req.MinecraftVersion) != "" || strings.TrimSpace(req.Loader) != "" {
		manifest := release.Manifest
		if strings.TrimSpace(req.MinecraftVersion) != "" {
			manifest.Minecraft.Version = strings.TrimSpace(req.MinecraftVersion)
		}
		if strings.TrimSpace(req.Loader) != "" {
			manifest.Minecraft.Loader = strings.TrimSpace(req.Loader)
		}
		if selectedProfile.MinecraftVersion != "" {
			manifest.Minecraft.LoaderVersion = selectedProfile.LoaderVersion
			manifest.Runtime.Java.MajorVersion = selectedProfile.JavaMajor
		}
		release, err = s.Repo.UpdateVersionManifest(release.ProjectID, release.ID, manifest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to store selected Minecraft metadata: "+err.Error())
			return
		}
	}
	s.audit(r, s.adminActor(r), "package:create", release.ID)
	s.packageEvent0206(r, "package.created", "created", release)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": s.packagePayload(release, nil, "created")})
}

func (s Server) packageGet(w http.ResponseWriter, r *http.Request) {
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.packagePayload(lookup.Release, lookup.Files, lookup.Release.Status)})
}

func (s Server) packageUploadFile(w http.ResponseWriter, r *http.Request) {
	lookup, unlock, err := s.lockPackageLookupMutation(r.Context(), r.PathValue("packageId"))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "package не найден")
		} else {
			writeError(w, http.StatusConflict, "package mutation already in progress: "+err.Error())
		}
		return
	}
	defer unlock()
	if lookup.Release.Status == "published" {
		writeError(w, http.StatusConflict, "published release immutable; создайте новую версию")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes())
	if err := r.ParseMultipartForm(s.maxUploadBytes()); err != nil {
		writeError(w, http.StatusBadRequest, "не удалось прочитать multipart-запрос или превышен лимит размера")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "поле file обязательно")
		return
	}
	defer file.Close()
	relativePath := strings.TrimSpace(firstNonEmpty(r.FormValue("path"), header.Filename))
	if relativePath == "" {
		writeError(w, http.StatusBadRequest, "path обязателен")
		return
	}
	payload, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "не удалось прочитать файл")
		return
	}
	sum := sha256.Sum256(payload)
	actualSHA := hex.EncodeToString(sum[:])
	executable, targetOS, metadataErr := releaseFileMetadata(r)
	if metadataErr != nil {
		writeError(w, http.StatusBadRequest, metadataErr.Error())
		return
	}
	if expected := strings.TrimSpace(r.FormValue("sha256")); expected != "" && !strings.EqualFold(expected, actualSHA) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"message": "sha256 не совпадает", "expected": expected, "actual": actualSHA}})
		return
	}
	ownership := strings.TrimSpace(r.FormValue("ownership"))
	if ownership == "" {
		ownership = "required"
	}
	if ownership != "required" && ownership != "managed" && ownership != "optional" {
		writeError(w, http.StatusBadRequest, "file upload permits only required/managed/optional ownership")
		return
	}
	if err := model.ValidateFileOwnership0224(model.Manifest{SchemaVersion: model.ManifestSchemaV2, Files: []model.ManifestFile{{Path: relativePath, Required: ownership != "optional", Ownership: ownership}}}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.beforeStorageWrite0206(r, lookup.Release.ProjectID, lookup.Release.ID, relativePath); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	_, size, err := s.Storage.Save(lookup.Release.ProjectID, lookup.Release.ID, relativePath, bytes.NewReader(payload))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	object := model.FileObject{ID: fmt.Sprintf("file-%d", time.Now().UTC().UnixNano()), ProjectID: lookup.Release.ProjectID, VersionID: lookup.Release.ID, Path: relativePath, Size: size, SHA256: actualSHA, URL: s.deliveryURL(lookup.Release.ProjectID, lookup.Release.ID, relativePath), Required: ownership != "optional", Executable: executable, TargetOS: targetOS, Ownership: ownership}
	saved, err := s.Repo.AddFile(object)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:file:upload", lookup.Release.ID+":"+relativePath)
	s.storageWritten0206(r, saved)
	s.packageEvent0206(r, "package.file-added", relativePath+":"+actualSHA, lookup.Release)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "packageId": lookup.Release.ID, "file": saved, "storageDriver": s.Storage.Driver(), "checksumVerified": true, "status": "uploaded"}})
}

func (s Server) packageValidate(w http.ResponseWriter, r *http.Request) {
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	checks := s.validatePackageFiles(lookup.Release, lookup.Files)
	status := "valid"
	for _, check := range checks {
		if check["status"] != "ok" {
			status = "invalid"
			break
		}
	}
	s.audit(r, s.adminActor(r), "package:validate", lookup.Release.ID)
	s.packageEvent0206(r, "package.validated", status, lookup.Release)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "packageId": lookup.Release.ID, "status": status, "files": len(lookup.Files), "checks": checks}})
}

func (s Server) validatePackageFiles(release model.ReleaseVersion, files []model.FileObject) []map[string]any {
	checks := make([]map[string]any, 0, len(files)+1)
	if len(files) == 0 {
		return []map[string]any{{"id": "files.present", "status": "failed", "message": "package не содержит файлов"}}
	}
	for _, file := range files {
		reader, size, err := s.Storage.Open(release.ProjectID, release.ID, file.Path)
		if err != nil {
			checks = append(checks, map[string]any{"id": file.Path, "status": "failed", "message": err.Error()})
			continue
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, reader)
		_ = reader.Close()
		actual := hex.EncodeToString(h.Sum(nil))
		status := "ok"
		message := "storage object matches manifest metadata"
		if copyErr != nil || size != file.Size || !strings.EqualFold(actual, file.SHA256) {
			status = "failed"
			message = fmt.Sprintf("size/hash mismatch: size=%d expectedSize=%d sha=%s expectedSHA=%s copyErr=%v", size, file.Size, actual, file.SHA256, copyErr)
		}
		checks = append(checks, map[string]any{"id": file.Path, "status": status, "message": message, "size": size, "sha256": actual})
	}
	sort.Slice(checks, func(i, j int) bool { return fmt.Sprint(checks[i]["id"]) < fmt.Sprint(checks[j]["id"]) })
	return checks
}

func (s Server) packageSign(w http.ResponseWriter, r *http.Request) {
	lookup, unlock, err := s.lockPackageLookupMutation(r.Context(), r.PathValue("packageId"))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "package не найден")
		} else {
			writeError(w, http.StatusConflict, "package mutation already in progress: "+err.Error())
		}
		return
	}
	defer unlock()
	// Serialize generation assignment for ALL packages in the same channel,
	// not merely updates to this package ID.
	generationUnlock, generationLockErr := s.lockPackageMutation(r.Context(), "game-generation:"+lookup.Release.ProjectID+":"+lookup.Release.ProfileID+":"+lookup.Release.Channel)
	if generationLockErr != nil {
		writeError(w, http.StatusConflict, generationLockErr.Error())
		return
	}
	defer generationUnlock()
	if lookup.Release.Status == "published" {
		writeError(w, http.StatusConflict, "published release immutable; создайте новую версию")
		return
	}
	checks := s.validatePackageFiles(lookup.Release, lookup.Files)
	for _, check := range checks {
		if check["status"] != "ok" {
			writeJSON(w, http.StatusConflict, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"message": "package validation failed", "checks": checks}})
			return
		}
	}
	manifest := lookup.Release.Manifest
	manifest.Files = manifest.Files[:0]
	for _, file := range lookup.Files {
		manifest.Files = append(manifest.Files, model.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256, URL: file.URL, Required: file.Required, Executable: file.Executable, TargetOS: append([]string(nil), file.TargetOS...), Mirrors: append([]string(nil), file.Mirrors...), Ownership: file.Ownership})
	}
	if guard, ok := s.Repo.(interface {
		VerifyMigrationContentBeforeSign0337(context.Context, string, string, model.Manifest) error
	}); ok {
		if e := guard.VerifyMigrationContentBeforeSign0337(r.Context(), lookup.Release.ProjectID, lookup.Release.ID, manifest); e != nil {
			writeError(w, http.StatusConflict, "migrated content is not verified for signing: "+e.Error())
			return
		}
	}
	if err := validateCompatibilityManifest(manifest); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	generation, generationErr := s.nextGameReleaseGeneration02311(manifest.ProjectID, manifest.ProfileID, manifest.Channel, lookup.Release.ID)
	if generationErr != nil {
		writeError(w, http.StatusConflict, "game release generation: "+generationErr.Error())
		return
	}
	manifest.GameReleaseGeneration = generation
	manifest.RollbackSource = nil // arbitrary historic content is never a rollback without a privileged rollback job
	signed, err := s.signManifest(manifest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось подписать manifest: "+err.Error())
		return
	}
	updated, err := s.Repo.UpdateVersionManifest(lookup.Release.ProjectID, lookup.Release.ID, signed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить подписанный manifest: "+err.Error())
		return
	}
	updated, err = s.Repo.UpdateVersionStatus(updated.ProjectID, updated.ID, "signed")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось сохранить package status: "+err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:sign", lookup.Release.ID)
	s.packageEvent0206(r, "package.signed", updated.Status, updated)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "packageId": updated.ID, "signatureStatus": "verified-ed25519", "algorithm": signed.Signature.Algorithm, "publicKey": signed.Signature.PublicKey, "signedAt": signed.Signature.SignedAt, "status": updated.Status}})
}

func (s Server) packageStage(w http.ResponseWriter, r *http.Request) {
	lookup, unlock, err := s.lockPackageLookupMutation(r.Context(), r.PathValue("packageId"))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "package не найден")
		} else {
			writeError(w, http.StatusConflict, "package mutation already in progress: "+err.Error())
		}
		return
	}
	defer unlock()
	if lookup.Release.Status == "published" {
		writeError(w, http.StatusConflict, "published release immutable; создайте новую версию")
		return
	}
	if err := s.verifyManifestSignature(lookup.Release.Manifest); err != nil {
		writeError(w, http.StatusConflict, "package должен иметь криптографически проверенный Ed25519 manifest перед stage: "+err.Error())
		return
	}
	checks := s.validatePackageFiles(lookup.Release, lookup.Files)
	for _, check := range checks {
		if check["status"] != "ok" {
			writeJSON(w, http.StatusConflict, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"message": "package validation failed", "checks": checks}})
			return
		}
	}
	updated, err := s.Repo.UpdateVersionStatus(lookup.Release.ProjectID, lookup.Release.ID, "staged")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:stage", lookup.Release.ID)
	s.packageEvent0206(r, "package.staged", updated.Status, updated)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.packagePayload(updated, lookup.Files, updated.Status)})
}

func (s Server) packagePublishProduct(w http.ResponseWriter, r *http.Request) {
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	if lookup.Release.Status == "published" {
		writeError(w, http.StatusConflict, "published release immutable; создайте новую версию")
		return
	}
	if err := s.validatePublishEvidence0212(r, lookup); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.verifyManifestSignature(lookup.Release.Manifest); err != nil {
		writeError(w, http.StatusConflict, "publish требует криптографически проверенный Ed25519 manifest: "+err.Error())
		return
	}
	if err := validateCompatibilityManifest(lookup.Release.Manifest); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	checks := s.validatePackageFiles(lookup.Release, lookup.Files)
	for _, check := range checks {
		if check["status"] != "ok" {
			writeJSON(w, http.StatusConflict, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"message": "package validation failed", "checks": checks}})
			return
		}
	}
	// Синхронные запреты расширений выполняются до принятия постоянного задания. После
	// постановки в очередь оно восстанавливаемо, а необратимая фиксация БД защищена fencing.
	if err := s.beforePackagePublish0206(r, lookup.Release); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.beforeReleasePublish0206(r, lookup.Release); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	release, job, pending, err := s.publishDurably0213(r, lookup)
	if err != nil {
		if errors.Is(err, errDurableAuthorizationRevoked0213) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if pending {
		w.Header().Set("Location", "/api/v1/jobs/"+job.ID)
		writeJSON(w, http.StatusAccepted, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"job": job, "status": "publish-queued"}})
		return
	}
	files, _ := s.Repo.ListFiles(release.ProjectID, release.ID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"package": s.packagePayload(release, files, "published"), "job": job}})
}

func (s Server) channelRollbackProduct(w http.ResponseWriter, r *http.Request) {
	s.rollbackExecute0217(w, r)
}

func (s Server) lookupPackage(packageID string) (packageLookup, error) {
	packageID = strings.TrimSpace(packageID)
	if packageID == "" {
		return packageLookup{}, repository.ErrNotFound
	}
	for _, project := range s.Repo.ListProjects() {
		versions, err := s.Repo.ListVersions(project.ID)
		if err != nil {
			continue
		}
		for _, release := range versions {
			if release.ID == packageID || release.Version == packageID {
				files, _ := s.Repo.ListFiles(release.ProjectID, release.ID)
				return packageLookup{Release: release, Files: files}, nil
			}
		}
	}
	return packageLookup{}, repository.ErrNotFound
}

func (s Server) packagePayload(release model.ReleaseVersion, files []model.FileObject, status string) map[string]any {
	if files == nil {
		files, _ = s.Repo.ListFiles(release.ProjectID, release.ID)
	}
	return map[string]any{
		"schemaVersion":         apiContractVersion,
		"manifestSchemaVersion": release.Manifest.SchemaVersion,
		"toolVersion":           s.Version,
		"packageId":             release.ID,
		"projectId":             release.ProjectID,
		"profileId":             release.ProfileID,
		"channel":               release.Channel,
		"version":               release.Version,
		"minecraft":             release.Manifest.Minecraft,
		"status":                status,
		"storageDriver":         s.Storage.Driver(),
		"delivery":              s.deliveryPolicyPayload(),
		"manifestUrl":           fmt.Sprintf("%s/api/v1/projects/%s/profiles/%s/manifest", strings.TrimRight(s.Config.PublicURL, "/"), release.ProjectID, release.ProfileID),
		"files":                 files,
	}
}
