package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
		_, _ = s.Repo.SaveProfile(model.Profile{ID: req.ProfileID, ProjectID: req.ProjectID, Name: req.ProfileID, Loader: firstNonEmpty(req.Loader, "vanilla")})
	}
	release, err := s.Repo.CreateVersion(req.ProjectID, req.ProfileID, req.Channel, req.Version)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:create", release.ID)
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
	unlock := s.lockPackageMutation()
	defer unlock()
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
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
	unlock := s.lockPackageMutation()
	defer unlock()
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
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
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "packageId": updated.ID, "signatureStatus": "verified-ed25519", "algorithm": signed.Signature.Algorithm, "publicKey": signed.Signature.PublicKey, "signedAt": signed.Signature.SignedAt, "status": updated.Status}})
}

func (s Server) packageStage(w http.ResponseWriter, r *http.Request) {
	unlock := s.lockPackageMutation()
	defer unlock()
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
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
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.packagePayload(updated, lookup.Files, updated.Status)})
}

func (s Server) packageSmoke(w http.ResponseWriter, r *http.Request) {
	unlock := s.lockPackageMutation()
	defer unlock()
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	if lookup.Release.Status == "published" {
		writeError(w, http.StatusConflict, "published release immutable; создайте новую версию")
		return
	}
	if lookup.Release.Status != "staged" && lookup.Release.Status != "smoke-failed" {
		writeError(w, http.StatusConflict, "package должен быть staged перед smoke-test")
		return
	}
	if err := s.verifyManifestSignature(lookup.Release.Manifest); err != nil {
		writeError(w, http.StatusConflict, "package manifest signature недействительна: "+err.Error())
		return
	}
	checks := s.validatePackageFiles(lookup.Release, lookup.Files)
	status := "smoke-passed"
	for _, check := range checks {
		if check["status"] != "ok" {
			status = "smoke-failed"
		}
	}
	updated, updateErr := s.Repo.UpdateVersionStatus(lookup.Release.ProjectID, lookup.Release.ID, status)
	if updateErr != nil {
		writeError(w, http.StatusInternalServerError, updateErr.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:smoke-test", lookup.Release.ID)
	code := http.StatusOK
	if status == "smoke-failed" {
		code = http.StatusConflict
	}
	writeJSON(w, code, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "packageId": updated.ID, "status": updated.Status, "checks": checks, "desktopConsumePlan": "/api/v1/projects/" + lookup.Release.ProjectID + "/profiles/" + lookup.Release.ProfileID + "/manifest"}})
}

func (s Server) packagePublishProduct(w http.ResponseWriter, r *http.Request) {
	unlock := s.lockPackageMutation()
	defer unlock()
	lookup, err := s.lookupPackage(r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package не найден")
		return
	}
	if lookup.Release.Status == "published" {
		writeError(w, http.StatusConflict, "published release immutable; создайте новую версию")
		return
	}
	if lookup.Release.Status != "smoke-passed" {
		writeError(w, http.StatusConflict, "publish разрешён только после успешного smoke-test")
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
	release, err := s.Repo.PublishVersionWithManifest(lookup.Release.ProjectID, lookup.Release.ProfileID, lookup.Release.Channel, lookup.Release.Version, lookup.Release.Manifest)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "package:publish", release.ID)
	files, _ := s.Repo.ListFiles(release.ProjectID, release.ID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": s.packagePayload(release, files, "published")})
}

func (s Server) channelRollbackProduct(w http.ResponseWriter, r *http.Request) {
	unlock := s.lockPackageMutation()
	defer unlock()
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
	// Immutable rollback никогда не изменяет уже опубликованный target. Вместо
	// этого создаётся новая release-version с тем же проверенным содержимым; URLs
	// остаются привязаны к immutable storage objects исходного target.
	rollbackVersion := toVersion + "-rollback-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	created, err := s.Repo.CreateVersion(projectID, profileID, channel, rollbackVersion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	manifest := target.Manifest
	manifest.Version = rollbackVersion
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	manifest.Signature = nil
	if err := validateCompatibilityManifest(manifest); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	signed, err := s.signManifest(manifest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "не удалось подписать rollback manifest: "+err.Error())
		return
	}
	if _, err := s.Repo.UpdateVersionManifest(projectID, created.ID, signed); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	release, err := s.Repo.PublishVersionWithManifest(projectID, profileID, channel, rollbackVersion, signed)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "channel:rollback", projectID+":"+profileID+":"+channel+":"+toVersion+"->"+rollbackVersion)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "projectId": projectID, "profileId": profileID, "channel": channel, "targetVersion": toVersion, "rollbackVersion": rollbackVersion, "release": release, "status": "rolled-back-as-new-immutable-release"}})
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
