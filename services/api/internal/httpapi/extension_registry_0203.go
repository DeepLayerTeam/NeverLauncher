package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionpackage"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const extensionRegistryMaxUpload0203 = int64(2<<30) + int64(32<<20)

type registryPublisherWrite0203 struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active *bool  `json:"active,omitempty"`
}

type registryPublisherKeyWrite0203 struct {
	PublicKeyBase64 string `json:"publicKeyBase64"`
	Active          *bool  `json:"active,omitempty"`
}

type registryChannelWrite0203 struct {
	Version string `json:"version"`
}

type registryYankWrite0203 struct {
	Reason string `json:"reason"`
}

type registryInstallWrite0203 struct {
	Scope   string `json:"scope"`
	ScopeID string `json:"scopeId,omitempty"`
}

func decodeSingleJSON0203(r *http.Request, out any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func (s Server) extensionRegistryPublishers0203(w http.ResponseWriter, r *http.Request) {
	items, err := s.Repo.ListExtensionRegistryPublishers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "1.0", "items": items}})
}

func (s Server) extensionRegistryPublisherCreate0203(w http.ResponseWriter, r *http.Request) {
	var request registryPublisherWrite0203
	if err := decodeSingleJSON0203(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid publisher payload: "+err.Error())
		return
	}
	active := true
	if request.Active != nil {
		active = *request.Active
	}
	item, err := s.Repo.SaveExtensionRegistryPublisher(r.Context(), model.ExtensionRegistryPublisher{ID: request.ID, Name: request.Name, Active: active})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:registry:publisher:save", item.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"publisher": item}})
}

func (s Server) extensionRegistryPublisherKeys0203(w http.ResponseWriter, r *http.Request) {
	publisherID := strings.ToLower(strings.TrimSpace(r.PathValue("publisherId")))
	items, err := s.Repo.ListExtensionRegistryPublisherKeys(r.Context(), publisherID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range items {
		items[i].PublicKeyBase64 = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"publisherId": publisherID, "items": items}})
}

func (s Server) extensionRegistryPublisherKeyCreate0203(w http.ResponseWriter, r *http.Request) {
	publisherID := strings.ToLower(strings.TrimSpace(r.PathValue("publisherId")))
	var request registryPublisherKeyWrite0203
	if err := decodeSingleJSON0203(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid publisher key payload: "+err.Error())
		return
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.PublicKeyBase64))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "publicKeyBase64 must contain a raw 32-byte Ed25519 public key")
		return
	}
	digest := sha256.Sum256(publicKey)
	active := true
	if request.Active != nil {
		active = *request.Active
	}
	item, err := s.Repo.SaveExtensionRegistryPublisherKey(r.Context(), model.ExtensionRegistryPublisherKey{PublisherID: publisherID, Fingerprint: "sha256:" + hex.EncodeToString(digest[:]), Algorithm: "Ed25519", PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey), Active: active})
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "registry publisher not found")
		return
	}
	if errors.Is(err, repository.ErrConflict) || errors.Is(err, repository.ErrImmutable) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:registry:key:add", publisherID+"/"+item.Fingerprint)
	item.PublicKeyBase64 = ""
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"key": item}})
}

func (s Server) extensionRegistrySearch0203(w http.ResponseWriter, r *http.Request) {
	includeYanked, _ := strconv.ParseBool(strings.TrimSpace(r.URL.Query().Get("includeYanked")))
	items, err := s.Repo.SearchExtensionRegistry(r.Context(), model.ExtensionRegistrySearch{Query: r.URL.Query().Get("q"), Channel: r.URL.Query().Get("channel"), LauncherVersion: r.URL.Query().Get("launcherVersion"), OS: r.URL.Query().Get("os"), Architecture: r.URL.Query().Get("arch"), IncludeYanked: includeYanked})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": "1.0", "count": len(items), "items": items}})
}

func (s Server) extensionRegistryExtension0203(w http.ResponseWriter, r *http.Request) {
	item, err := s.Repo.GetExtensionRegistryExtension(r.Context(), r.PathValue("extensionId"))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "registry extension not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": item})
}

func (s Server) extensionRegistryVersion0203(w http.ResponseWriter, r *http.Request) {
	item, err := s.Repo.GetExtensionRegistryVersion(r.Context(), r.PathValue("extensionId"), r.PathValue("version"))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "registry extension version not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"version": item}})
}

func splitRegistryList0203(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' })
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func copyMultipartArtifact0203(file io.Reader) (string, string, int64, error) {
	tmp, err := os.CreateTemp("", "neverlauncher-registry-*.nlext")
	if err != nil {
		return "", "", 0, err
	}
	path := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(file, extensionRegistryMaxUpload0203+1))
	if err != nil {
		return "", "", size, err
	}
	if size <= 0 || size > extensionRegistryMaxUpload0203 {
		return "", "", size, errors.New(".nlext upload is empty or exceeds registry limit")
	}
	if err := tmp.Sync(); err != nil {
		return "", "", size, err
	}
	if err := tmp.Close(); err != nil {
		return "", "", size, err
	}
	ok = true
	return path, hex.EncodeToString(h.Sum(nil)), size, nil
}

func registryPublicKey0203(key model.ExtensionRegistryPublisherKey) (ed25519.PublicKey, error) {
	if !key.Active || key.RevokedAt != nil || key.Algorithm != "Ed25519" {
		return nil, errors.New("publisher signing key is inactive/revoked")
	}
	raw, err := base64.StdEncoding.DecodeString(key.PublicKeyBase64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("registry contains invalid Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func (s Server) extensionRegistryPublish0203(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, extensionRegistryMaxUpload0203+int64(16<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid registry publish multipart body: "+err.Error())
		return
	}
	file, _, err := r.FormFile("artifact")
	if err != nil {
		writeError(w, http.StatusBadRequest, "publish requires multipart artifact=.nlext")
		return
	}
	defer file.Close()
	tmpPath, uploadSHA, uploadSize, err := copyMultipartArtifact0203(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer os.Remove(tmpPath)
	inspected, err := extensionpackage.InspectSignedFile(tmpPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signed .nlext: "+err.Error())
		return
	}
	publisherID := strings.ToLower(strings.TrimSpace(r.FormValue("publisher")))
	if publisherID == "" {
		publisherID = inspected.Manifest.Publisher
	}
	if publisherID != inspected.Manifest.Publisher {
		writeError(w, http.StatusBadRequest, "publisher field must match neverlauncher-extension.json publisher")
		return
	}
	key, err := s.Repo.GetExtensionRegistryPublisherKey(r.Context(), publisherID, inspected.KeyFingerprint)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusForbidden, "artifact signing key is not trusted for publisher")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	publicKey, err := registryPublicKey0203(key)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	verified, err := extensionpackage.VerifyFile(tmpPath, publicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "artifact signature verification failed: "+err.Error())
		return
	}
	if verified.SHA256 != uploadSHA || verified.Size != uploadSize {
		writeError(w, http.StatusBadRequest, "artifact changed during verification")
		return
	}
	identityHex := strings.TrimPrefix(verified.PackageIdentity, "sha256:")
	storageProject := "neverextensions-registry"
	storageVersion := verified.Manifest.ID + "-" + verified.Manifest.Version
	storagePath := identityHex + ".nlext"
	tmp, err := os.Open(tmpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, storedSize, saveErr := s.Storage.Save(storageProject, storageVersion, storagePath, tmp)
	closeErr := tmp.Close()
	if saveErr != nil {
		writeError(w, http.StatusInternalServerError, "artifact storage failed: "+saveErr.Error())
		return
	}
	if closeErr != nil || storedSize != verified.Size {
		writeError(w, http.StatusInternalServerError, "artifact storage size/close verification failed")
		return
	}
	publication := model.ExtensionRegistryPublication{
		Manifest:    verified.Manifest,
		PublisherID: publisherID,
		Compatibility: model.ExtensionRegistryCompatibility{
			MinNeverLauncher:       strings.TrimSpace(r.FormValue("minNeverLauncher")),
			MaxNeverLauncher:       strings.TrimSpace(r.FormValue("maxNeverLauncher")),
			SupportedOS:            splitRegistryList0203(r.FormValue("os")),
			SupportedArchitectures: splitRegistryList0203(r.FormValue("arch")),
		},
		Artifact: model.ExtensionRegistryArtifact{PackageIdentity: verified.PackageIdentity, ExtensionID: verified.Manifest.ID, Version: verified.Manifest.Version, SHA256: verified.SHA256, Size: verified.Size, StorageProject: storageProject, StorageVersion: storageVersion, StoragePath: storagePath, SignatureKeyFingerprint: verified.KeyFingerprint},
		Channels: splitRegistryList0203(r.FormValue("channels")),
	}
	item, err := s.Repo.PublishExtensionRegistryVersion(r.Context(), publication)
	if errors.Is(err, repository.ErrImmutable) || errors.Is(err, repository.ErrConflict) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "publisher/signing key not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:registry:publish", item.ExtensionID+"@"+item.Version+"#"+item.Artifact.PackageIdentity)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "published", "verified": true, "version": item}})
}

func (s Server) extensionRegistryYank0203(w http.ResponseWriter, r *http.Request) {
	var request registryYankWrite0203
	if err := decodeSingleJSON0203(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid yank payload: "+err.Error())
		return
	}
	item, err := s.Repo.YankExtensionRegistryVersion(r.Context(), r.PathValue("extensionId"), r.PathValue("version"), request.Reason)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "registry version not found")
		return
	}
	if errors.Is(err, repository.ErrImmutable) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:registry:yank", item.ExtensionID+"@"+item.Version+": "+item.YankReason)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "yanked", "version": item}})
}

func (s Server) extensionRegistryChannelSet0203(w http.ResponseWriter, r *http.Request) {
	var request registryChannelWrite0203
	if err := decodeSingleJSON0203(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid channel payload: "+err.Error())
		return
	}
	item, err := s.Repo.SetExtensionRegistryChannel(r.Context(), r.PathValue("extensionId"), r.PathValue("channel"), request.Version)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "registry version not found")
		return
	}
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:registry:channel:set", item.ExtensionID+":"+r.PathValue("channel")+"->"+item.Version)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "updated", "version": item}})
}

func (s Server) extensionRegistryArtifact0203(w http.ResponseWriter, r *http.Request) {
	item, err := s.Repo.GetExtensionRegistryVersion(r.Context(), r.PathValue("extensionId"), r.PathValue("version"))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "registry version not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	reader, size, err := s.Storage.Open(item.Artifact.StorageProject, item.Artifact.StorageVersion, item.Artifact.StoragePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "registry artifact not found in storage")
		return
	}
	defer reader.Close()
	if size != item.Artifact.Size {
		writeError(w, http.StatusInternalServerError, "registry artifact storage size mismatch")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, item.ExtensionID+"-"+item.Version+".nlext"))
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("ETag", `"`+item.Artifact.SHA256+`"`)
	w.Header().Set("X-NeverLauncher-Package-Identity", item.Artifact.PackageIdentity)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, reader)
}

func (s Server) verifiedRegistryArtifactToTemp0203(r *http.Request, item model.ExtensionRegistryVersion) (string, error) {
	reader, size, err := s.Storage.Open(item.Artifact.StorageProject, item.Artifact.StorageVersion, item.Artifact.StoragePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	if size != item.Artifact.Size {
		return "", errors.New("registry artifact storage size mismatch")
	}
	tmp, err := os.CreateTemp("", "neverlauncher-registry-install-*.nlext")
	if err != nil {
		return "", err
	}
	path := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(reader, item.Artifact.Size+1))
	if err != nil {
		return "", err
	}
	if written != item.Artifact.Size || hex.EncodeToString(h.Sum(nil)) != item.Artifact.SHA256 {
		return "", errors.New("registry artifact bytes do not match immutable metadata")
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	key, err := s.Repo.GetExtensionRegistryPublisherKey(r.Context(), item.PublisherID, item.Artifact.SignatureKeyFingerprint)
	if err != nil {
		return "", err
	}
	publicKey, err := registryPublicKey0203(key)
	if err != nil {
		return "", err
	}
	verified, err := extensionpackage.VerifyFile(path, publicKey)
	if err != nil {
		return "", err
	}
	if verified.PackageIdentity != item.Artifact.PackageIdentity || verified.SHA256 != item.Artifact.SHA256 || verified.Manifest.ID != item.ExtensionID || verified.Manifest.Version != item.Version || verified.Manifest.Publisher != item.PublisherID {
		return "", errors.New("verified artifact identity does not match registry version")
	}
	ok = true
	return path, nil
}

func (s Server) extensionRegistryInstall0203(w http.ResponseWriter, r *http.Request) {
	item, err := s.Repo.GetExtensionRegistryVersion(r.Context(), r.PathValue("extensionId"), r.PathValue("version"))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "registry version not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if item.YankedAt != nil {
		writeError(w, http.StatusConflict, "yanked registry version cannot be installed")
		return
	}
	var request registryInstallWrite0203
	if r.ContentLength != 0 {
		if err := decodeSingleJSON0203(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid install payload: "+err.Error())
			return
		}
	}
	install, err := s.lifecycleManager0204().Install(r.Context(), item, lifecycleScopeFromRequest0204(request.Scope, request.ScopeID))
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, ".nlext") || strings.Contains(lower, "signature") || strings.Contains(lower, "package identity") || strings.Contains(lower, "artifact sha") || strings.Contains(lower, "publisher key") {
			writeError(w, http.StatusConflict, "registry artifact verification failed: "+err.Error())
			return
		}
		writeLifecycleError0204(w, err)
		return
	}
	s.audit(r, s.adminActor(r), "extension:lifecycle:install", item.ExtensionID+"@"+item.Version+"#"+item.Artifact.PackageIdentity)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "installed", "verified": true, "enabled": false, "install": install, "artifact": item.Artifact}})
}

// Kept local to the HTTP layer: install Source is informational/auditable and
// is not used as a file-system path.
func registryInstallSource0203(item model.ExtensionRegistryVersion) string {
	return item.PublisherID + "/" + item.ExtensionID + "@" + item.Version + "#" + item.Artifact.PackageIdentity
}
