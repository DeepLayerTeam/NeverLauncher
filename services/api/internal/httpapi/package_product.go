package httpapi

import (
	"bytes"
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
	ProjectID        string `json:"projectId"`
	ProfileID        string `json:"profileId"`
	Channel          string `json:"channel"`
	Version          string `json:"version"`
	MinecraftVersion string `json:"minecraftVersion"`
	Loader           string `json:"loader"`
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
	profileExists := false
	for _, profile := range profiles {
		if profile.ID == req.ProfileID {
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
	release, err := s.Repo.CreateVersion(req.ProjectID, req.ProfileID, req.Channel, req.Version)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
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
	if err := s.beforeStorageWrite0206(r, lookup.Release.ProjectID, lookup.Release.ID, relativePath); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	_, size, err := s.Storage.Save(lookup.Release.ProjectID, lookup.Release.ID, relativePath, bytes.NewReader(payload))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	object := model.FileObject{ID: fmt.Sprintf("file-%d", time.Now().UTC().UnixNano()), ProjectID: lookup.Release.ProjectID, VersionID: lookup.Release.ID, Path: relativePath, Size: size, SHA256: actualSHA, URL: s.deliveryURL(lookup.Release.ProjectID, lookup.Release.ID, relativePath), Required: true, Executable: executable, TargetOS: targetOS}
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
		manifest.Files = append(manifest.Files, model.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256, URL: file.URL, Required: file.Required, Executable: file.Executable, TargetOS: append([]string(nil), file.TargetOS...)})
	}
	if err := validateCompatibilityManifest(manifest); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
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
	// Synchronous расширение vetoes запуск до долговременная задача является принят. После
	// enqueue, задача является recoverable и необратимый DB фиксация является ограждённый.
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
	channel := r.PathValue("channel")
	var req packageActionRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	projectID := firstNonEmpty(req.ProjectID, queryDefault(r, "projectId", ""), queryDefault(r, "project", ""))
	profileID := firstNonEmpty(req.ProfileID, queryDefault(r, "profileId", "vanilla"))
	toVersion := firstNonEmpty(req.ToVersion, queryDefault(r, "toVersion", ""))
	if projectID == "" || toVersion == "" {
		writeError(w, http.StatusBadRequest, "projectId и toVersion обязательны")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:publish", projectID, "channel", channel) {
		return
	}
	var target *model.ReleaseVersion
	versions, err := s.Repo.ListVersions(projectID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for i := range versions {
		item := versions[i]
		if item.ProfileID == profileID && item.Channel == channel && item.Version == toVersion {
			target = &item
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "rollback target version не найдена")
		return
	}
	if target.Status != "published" {
		writeError(w, http.StatusConflict, "rollback target должен быть опубликованным immutable release")
		return
	}
	if err := s.verifyManifestSignature(target.Manifest); err != nil {
		writeError(w, http.StatusConflict, "rollback target не имеет криптографически доверенной Ed25519-подписи manifest: "+err.Error())
		return
	}
	targetFiles, err := s.Repo.ListFiles(projectID, target.ID)
	if err != nil || len(targetFiles) == 0 {
		writeError(w, http.StatusConflict, "rollback target не имеет канонических file records для повторной integrity-проверки")
		return
	}

	// Откат является новый неизменяемый релиз, поэтому это получает новый манифест
	// хеш и MUST obtain его собственный валидация свидетельство. Файл записывает точка к
	// уже неизменяемый хранилище объекты цель релиз.
	rollbackVersion := toVersion + "-rollback-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	created, err := s.Repo.CreateVersion(projectID, profileID, channel, rollbackVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	unlockRollback, lockErr := s.lockPackageMutation(r.Context(), "package:"+created.ID)
	if lockErr != nil {
		writeError(w, http.StatusConflict, "rollback package mutation already in progress: "+lockErr.Error())
		return
	}
	rollbackLeaseReleased := false
	defer func() {
		if !rollbackLeaseReleased {
			unlockRollback()
		}
	}()
	for _, source := range targetFiles {
		reader, sourceSize, openErr := s.Storage.Open(projectID, target.ID, source.Path)
		if openErr != nil {
			writeError(w, http.StatusConflict, "rollback source storage object недоступен: "+openErr.Error())
			return
		}
		_, copiedSize, saveErr := s.Storage.Save(projectID, created.ID, source.Path, reader)
		_ = reader.Close()
		if saveErr != nil || copiedSize != sourceSize || copiedSize != source.Size {
			if saveErr == nil {
				saveErr = fmt.Errorf("copied размер=%d исходник размер=%d метаданные размер=%d", copiedSize, sourceSize, source.Size)
			}
			writeError(w, http.StatusInternalServerError, "не удалось материализовать rollback storage object: "+saveErr.Error())
			return
		}
		clone := source
		clone.ID = ""
		clone.VersionID = created.ID
		clone.URL = s.deliveryURL(projectID, created.ID, source.Path)
		if _, err := s.Repo.AddFile(clone); err != nil {
			writeError(w, http.StatusInternalServerError, "не удалось клонировать rollback file metadata: "+err.Error())
			return
		}
	}
	files, err := s.Repo.ListFiles(projectID, created.ID)
	if err != nil || len(files) != len(targetFiles) {
		writeError(w, http.StatusInternalServerError, "rollback file metadata incomplete")
		return
	}
	manifest := target.Manifest
	manifest.Version = rollbackVersion
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	manifest.Signature = nil
	manifest.Files = make([]model.ManifestFile, 0, len(files))
	for _, f := range files {
		manifest.Files = append(manifest.Files, model.ManifestFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256, URL: f.URL, Required: f.Required, Executable: f.Executable, TargetOS: append([]string(nil), f.TargetOS...)})
	}
	if err := validateCompatibilityManifest(manifest); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	signed, err := s.signManifest(manifest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось подписать rollback manifest: "+err.Error())
		return
	}
	updated, err := s.Repo.UpdateVersionManifest(projectID, created.ID, signed)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err = s.Repo.UpdateVersionStatus(projectID, created.ID, "staged")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	lookup := packageLookup{Release: updated, Files: files}
	integrity, err := s.runPackageIntegrityCheck0212(r, lookup)
	if err != nil || integrity.Result != "passed" {
		if err == nil {
			err = errors.New("откат проверка целостности ошибка")
		}
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	lookup.Release.Status = "integrity-passed"

	policy, policyErr := s.Repo.GetProjectValidationPolicy(r.Context(), projectID)
	if policyErr == nil && policy.RequiredLevel == "runtime" {
		s.audit(r, s.adminActor(r), "channel:rollback:validation-required", projectID+":"+profileID+":"+channel+":"+toVersion+"->"+rollbackVersion)
		writeJSON(w, http.StatusAccepted, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "projectId": projectID, "profileId": profileID, "channel": channel, "targetVersion": toVersion, "rollbackVersion": rollbackVersion, "packageId": created.ID, "release": lookup.Release, "integrity": integrity, "requiredValidationLevel": "runtime", "status": "rollback-staged-runtime-validation-required"}})
		return
	}
	if err := s.validatePublishEvidence0212(r, lookup); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.beforeReleasePublish0206(r, lookup.Release); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	// Релиз preparation аренда до долговременный обработчик acquires одинаковый
	// ограждённый пакет область для необратимый публикация фиксация.
	unlockRollback()
	rollbackLeaseReleased = true
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
		writeJSON(w, http.StatusAccepted, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "projectId": projectID, "profileId": profileID, "channel": channel, "targetVersion": toVersion, "rollbackVersion": rollbackVersion, "packageId": created.ID, "job": job, "integrity": integrity, "status": "rollback-publish-queued"}})
		return
	}
	s.audit(r, s.adminActor(r), "channel:rollback", projectID+":"+profileID+":"+channel+":"+toVersion+"->"+rollbackVersion)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "projectId": projectID, "profileId": profileID, "channel": channel, "targetVersion": toVersion, "rollbackVersion": rollbackVersion, "release": release, "job": job, "integrity": integrity, "status": "rolled-back-as-new-validated-immutable-release"}})
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
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"packageId":     release.ID,
		"projectId":     release.ProjectID,
		"profileId":     release.ProfileID,
		"channel":       release.Channel,
		"version":       release.Version,
		"status":        status,
		"storageDriver": s.Storage.Driver(),
		"delivery":      s.deliveryPolicyPayload(),
		"manifestUrl":   fmt.Sprintf("%s/api/v1/projects/%s/profiles/%s/manifest", strings.TrimRight(s.Config.PublicURL, "/"), release.ProjectID, release.ProfileID),
		"files":         files,
	}
}
