package httpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// Build workspaces are private to the operator; uploaded bytes are stored in
// content-addressed, non-public storage keys until a build is materialized.
const maxWorkspaceFiles0226 = 25000

func (s Server) workspaceStore0226(w http.ResponseWriter) (repository.BuildWorkspaceStore, bool) {
	store, ok := s.Repo.(repository.BuildWorkspaceStore)
	if !ok {
		writeError(w, 503, "build workspace persistence unavailable")
	}
	return store, ok
}
func (s Server) ownedWorkspace0226(w http.ResponseWriter, r *http.Request, permission string) (repository.BuildWorkspaceStore, repository.BuildWorkspace, bool) {
	store, ok := s.workspaceStore0226(w)
	if !ok {
		return nil, repository.BuildWorkspace{}, false
	}
	ws, err := store.GetBuildWorkspace(r.Context(), r.PathValue("workspaceId"))
	if err != nil {
		writeError(w, 404, "workspace not found")
		return store, ws, false
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return store, ws, false
	}
	if claims.Sub != ws.OwnerID || !s.authorizeClaims(r, claims, permission, ws.ProjectID, "project", ws.ProjectID).Allowed {
		writeError(w, 404, "workspace not found")
		return store, ws, false
	}
	return store, ws, true
}
func readJSON0226(w http.ResponseWriter, r *http.Request, max int64, target any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var tail any
	if err := d.Decode(&tail); err != io.EOF {
		return errors.New("expected exactly one JSON object")
	}
	return nil
}
func (s Server) workspaceCreate0226(w http.ResponseWriter, r *http.Request) {
	store, ok := s.workspaceStore0226(w)
	if !ok {
		return
	}
	var req struct {
		ProjectID, ProfileID, Channel, Version string
		Settings                               repository.BuildSettings
	}
	if err := readJSON0226(w, r, 64<<10, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.ProfileID = strings.TrimSpace(req.ProfileID)
	req.Channel = strings.TrimSpace(req.Channel)
	req.Version = strings.TrimSpace(req.Version)
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if req.ProjectID == "" || req.ProfileID == "" || req.Version == "" {
		writeError(w, 400, "projectId, profileId and version are required")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", req.ProjectID, "project", req.ProjectID) {
		return
	}
	if _, err = s.Repo.GetProject(req.ProjectID); err != nil {
		writeError(w, 404, "project not found")
		return
	}
	snapshot, err := repository.ReadProfileSnapshot(s.Repo, req.ProjectID, req.ProfileID)
	if err != nil {
		writeError(w, 400, "profile not found or invalid: "+err.Error())
		return
	}
	// Server identity is not a user-controlled tool fingerprint.
	if req.Settings.ToolVersions == nil {
		req.Settings.ToolVersions = make(map[string]string)
	}
	if len(req.Settings.ToolVersions) > 32 {
		writeError(w, 400, "too many tools")
		return
	}
	for k, v := range req.Settings.ToolVersions {
		if len(k) == 0 || len(k) > 128 || len(v) == 0 || len(v) > 128 || strings.ContainsAny(k+v, "\x00\r\n") {
			writeError(w, 400, "invalid tool fingerprint")
			return
		}
	}
	req.Settings.ToolVersions["neverlauncher-api"] = s.Version
	if req.Settings.Minecraft.Version == "" {
		writeError(w, 400, "Minecraft version required")
		return
	}
	if req.Settings.Minecraft.Loader == "" {
		req.Settings.Minecraft.Loader = snapshot.Spec.Loader
	}
	if !strings.EqualFold(req.Settings.Minecraft.Loader, snapshot.Spec.Loader) {
		writeError(w, 400, "workspace loader must match the pinned client profile")
		return
	}
	if snapshot.Spec.MinecraftVersion != "" && req.Settings.Minecraft.LoaderVersion != snapshot.Spec.LoaderVersion {
		writeError(w, 409, "profile launch mismatch: exact loaderVersion required")
		return
	}
	if err := model.ValidateProfileLaunch0382(snapshot.Spec, req.Settings.Minecraft, req.Settings.Runtime.Java.MajorVersion, true); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if req.Settings.Runtime.Java.MajorVersion <= 0 {
		writeError(w, 400, "explicit runtime.java.majorVersion required")
		return
	}
	for _, v := range []string{req.ProjectID, req.ProfileID, req.Channel, req.Version} {
		if len(v) > 128 || strings.ContainsAny(v, "/\\\r\n\x00") {
			writeError(w, 400, "invalid workspace scope")
			return
		}
	}
	// Validate runtime and ownership before retaining input settings.
	// Classpath/modulepath entries reference files that have not been imported yet.
	// Validate their syntax and membership after staging against actual hashes.
	preflightRuntime := req.Settings.Runtime
	preflightRuntime.Launch.ClasspathEntries = nil
	preflightRuntime.Launch.ModulepathEntries = nil
	preflightRuntime.Launch.MainModule = ""
	probe := model.Manifest{SchemaVersion: model.ManifestSchemaV2, ProjectID: req.ProjectID, ProfileID: req.ProfileID, ProfileSnapshot: &snapshot, Minecraft: req.Settings.Minecraft, Runtime: preflightRuntime, Directories: req.Settings.Directories, FileRules: req.Settings.FileRules, Files: []model.ManifestFile{}}
	if err = model.ValidateManifestSchema(probe); err != nil {
		writeError(w, 400, "invalid build settings: "+err.Error())
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		writeError(w, 500, "unable to allocate ID")
		return
	}
	ws := repository.BuildWorkspace{ID: "ws-" + hex.EncodeToString(id[:]), ProjectID: req.ProjectID, OwnerID: claims.Sub, ProfileID: req.ProfileID, Channel: req.Channel, Version: req.Version, ProfileRevision: snapshot.Revision, ProfileDigest: snapshot.Digest, Settings: req.Settings, Files: []repository.BuildFile{}}
	saved, err := store.CreateBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, claims.Sub, "build-workspace:create", saved.ID)
	w.Header().Set("Location", "/api/v1/build-workspaces/"+saved.ID)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}
func (s Server) workspaceList0226(w http.ResponseWriter, r *http.Request) {
	store, ok := s.workspaceStore0226(w)
	if !ok {
		return
	}
	projectID := r.URL.Query().Get("projectId")
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", projectID, "project", projectID) {
		return
	}
	rows, err := store.ListBuildWorkspaces(r.Context(), projectID, claims.Sub)
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": rows}})
}
func (s Server) workspaceGet0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if ok {
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": ws})
	}
}
func workspaceObjectPath0226(f repository.BuildFile) string { return "objects/" + f.SHA256 }
func normalizeBuildFile0226(f repository.BuildFile) error {
	if f.Ownership == "" {
		f.Ownership = "required"
	}
	if f.Ownership != "managed" && f.Ownership != "required" && f.Ownership != "optional" {
		return errors.New("only managed/required/optional files can be uploaded")
	}
	m := model.Manifest{SchemaVersion: model.ManifestSchemaV2, Files: []model.ManifestFile{{Path: f.Path, Required: f.Ownership != "optional", Ownership: f.Ownership}}}
	if err := model.ValidateFileOwnership0224(m); err != nil {
		return err
	}
	if len(f.SHA256) != 64 || f.Size < 0 || f.Size > 1<<32 {
		return errors.New("invalid file hash or size")
	}
	return nil
}

// Workspace blobs are encrypted before reaching Local/S3/CDN-configured
// storage. This prevents public-storage configurations from leaking source
// files before publication. The key is domain-separated from the manifest
// Ed25519 signing seed, and AEAD binds project/workspace/content digest.
func (s Server) workspaceCipher0226() (cipher.AEAD, error) {
	key, err := s.manifestSigningPrivateKey()
	if err != nil {
		return nil, err
	}
	seed := key.Seed()
	material := sha256.Sum256(append([]byte("NeverLauncher build workspace encryption v1\x00"), seed...))
	block, err := aes.NewCipher(material[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (s Server) encryptWorkspace0226(ws repository.BuildWorkspace, f repository.BuildFile, plain []byte) ([]byte, error) {
	aead, err := s.workspaceCipher0226()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(ws.ProjectID + "\x00" + ws.ID + "\x00" + f.SHA256)
	sealed := aead.Seal(nil, nonce, plain, aad)
	return append(append([]byte("NLBW1"), nonce...), sealed...), nil
}
func (s Server) readWorkspaceSource0226(ws repository.BuildWorkspace, f repository.BuildFile) ([]byte, error) {
	src, size, err := s.Storage.Open(ws.ProjectID, ws.ID, workspaceObjectPath0226(f))
	if err != nil {
		return nil, err
	}
	defer src.Close()
	aead, err := s.workspaceCipher0226()
	if err != nil {
		return nil, err
	}
	max := f.Size + int64(len("NLBW1")) + int64(aead.NonceSize()+aead.Overhead())
	if size != max {
		return nil, fmt.Errorf("encrypted size mismatch at %s", f.Path)
	}
	raw, err := io.ReadAll(io.LimitReader(src, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != max || !bytes.HasPrefix(raw, []byte("NLBW1")) {
		return nil, errors.New("invalid source blob")
	}
	offset := len("NLBW1")
	nonce := raw[offset : offset+aead.NonceSize()]
	aad := []byte(ws.ProjectID + "\x00" + ws.ID + "\x00" + f.SHA256)
	plain, err := aead.Open(nil, nonce, raw[offset+aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("source authentication failed at %s: %w", f.Path, err)
	}
	sum := sha256.Sum256(plain)
	if int64(len(plain)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
		return nil, fmt.Errorf("source integrity mismatch at %s", f.Path)
	}
	return plain, nil
}
func (s Server) workspaceUpload0226(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "file:write")
	if !ok {
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if ws.State == "built" || ws.PackageID != "" {
		writeError(w, 409, "workspace is locked to a release package; source files and staging are immutable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUploadBytes()+4096)
	if err = r.ParseMultipartForm(s.maxUploadBytes()); err != nil {
		writeError(w, 400, "invalid multipart or file too large")
		return
	}
	var expected int64
	if _, err = fmt.Sscan(r.FormValue("revision"), &expected); err != nil || expected != ws.Revision {
		writeError(w, 409, "workspace revision conflict")
		return
	}
	src, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "file part required")
		return
	}
	defer src.Close()
	file := repository.BuildFile{Path: strings.TrimSpace(r.FormValue("path")), Ownership: strings.TrimSpace(r.FormValue("ownership")), Selected: true}
	if file.Path == "" {
		file.Path = header.Filename
	}
	if file.Ownership == "" {
		file.Ownership = "required"
	}
	file.Executable, file.TargetOS, err = releaseFileMetadata(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if len(ws.Files) >= maxWorkspaceFiles0226 {
		writeError(w, 413, "workspace file limit reached")
		return
	}
	// Hash actual bytes; the browser's hash, if provided, is only an assertion.
	data, err := io.ReadAll(io.LimitReader(src, s.maxUploadBytes()+1))
	if err != nil || int64(len(data)) > s.maxUploadBytes() {
		writeError(w, 413, "file too large")
		return
	}
	file.Size = int64(len(data))
	sum := sha256.Sum256(data)
	file.SHA256 = hex.EncodeToString(sum[:])
	if expectedSHA := r.FormValue("sha256"); expectedSHA != "" && !strings.EqualFold(expectedSHA, file.SHA256) {
		writeError(w, 400, "sha256 mismatch")
		return
	}
	if err = normalizeBuildFile0226(file); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	for _, other := range ws.Files {
		if strings.EqualFold(other.Path, file.Path) && other.Path != file.Path {
			writeError(w, 409, "case-insensitive path collision")
			return
		}
	}
	encrypted, encryptionErr := s.encryptWorkspace0226(ws, file, data)
	if encryptionErr != nil {
		writeError(w, 503, "workspace encryption failed: "+encryptionErr.Error())
		return
	}
	if _, _, err = s.Storage.Save(ws.ProjectID, ws.ID, workspaceObjectPath0226(file), bytes.NewReader(encrypted)); err != nil {
		writeError(w, 503, "storage write failed: "+err.Error())
		return
	}
	replaced := false
	for i, old := range ws.Files {
		if old.Path == file.Path {
			ws.Files[i] = file
			replaced = true
			break
		}
	}
	if !replaced {
		ws.Files = append(ws.Files, file)
	}
	sort.Slice(ws.Files, func(i, j int) bool { return ws.Files[i].Path < ws.Files[j].Path })
	ws.State = "importing"
	ws.BuildDigest = ""
	saved, err := store.SaveBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "build-workspace:import", ws.ID+":"+file.Path)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}
func (s Server) workspaceVerifyFile0226(ws repository.BuildWorkspace, file repository.BuildFile) error {
	_, err := s.readWorkspaceSource0226(ws, file)
	return err
}
func selectedFiles0226(ws repository.BuildWorkspace) []repository.BuildFile {
	out := []repository.BuildFile{}
	for _, f := range ws.Files {
		if f.Selected {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func (s Server) workspaceScan0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	checks := make([]map[string]any, 0, len(ws.Files))
	allOK := true
	for _, f := range ws.Files {
		err := s.workspaceVerifyFile0226(ws, f)
		status := "ok"
		if err != nil {
			status = "failed"
			allOK = false
		}
		checks = append(checks, map[string]any{"path": f.Path, "sha256": f.SHA256, "size": f.Size, "status": status})
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"revision": ws.Revision, "status": map[bool]string{true: "passed", false: "failed"}[allOK], "files": checks}})
}
func (s Server) workspaceDiff0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	baseID := r.URL.Query().Get("baseVersionId")
	old := map[string]model.FileObject{}
	if baseID != "" {
		versions, err := s.Repo.ListVersions(ws.ProjectID)
		if err != nil {
			writeError(w, 503, err.Error())
			return
		}
		found := false
		for _, v := range versions {
			if v.ID == baseID && v.ProfileID == ws.ProfileID && v.Status == "published" {
				found = true
				break
			}
		}
		if !found {
			writeError(w, 400, "base version is not published in this profile")
			return
		}
		files, err := s.Repo.ListFiles(ws.ProjectID, baseID)
		if err != nil {
			writeError(w, 503, err.Error())
			return
		}
		for _, f := range files {
			old[f.Path] = f
		}
	}
	type row struct {
		Path   string `json:"path"`
		Change string `json:"change"`
		OldSHA string `json:"oldSha256,omitempty"`
		NewSHA string `json:"newSha256,omitempty"`
	}
	diff := []row{}
	for _, f := range selectedFiles0226(ws) {
		oldFile, had := old[f.Path]
		change := "added"
		if had {
			if oldFile.SHA256 == f.SHA256 {
				change = "unchanged"
			} else {
				change = "modified"
			}
			delete(old, f.Path)
		}
		diff = append(diff, row{f.Path, change, oldFile.SHA256, f.SHA256})
	}
	for _, f := range old {
		diff = append(diff, row{Path: f.Path, Change: "removed-from-package", OldSHA: f.SHA256})
	}
	sort.Slice(diff, func(i, j int) bool { return diff[i].Path < diff[j].Path })
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": diff, "revision": ws.Revision}})
}
func (s Server) workspaceStage0226(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if ws.State == "built" || ws.PackageID != "" {
		writeError(w, 409, "workspace is locked to a release package; source files and staging are immutable")
		return
	}
	var req struct {
		Revision int64    `json:"revision"`
		Paths    []string `json:"paths"`
	}
	if err := readJSON0226(w, r, 1<<20, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if ws.Revision != req.Revision {
		writeError(w, 409, "workspace revision conflict")
		return
	}
	selected := map[string]bool{}
	for _, p := range req.Paths {
		if selected[p] {
			writeError(w, 400, "duplicate staged path")
			return
		}
		selected[p] = true
	}
	count := 0
	for i := range ws.Files {
		_, ws.Files[i].Selected = selected[ws.Files[i].Path]
		if ws.Files[i].Selected {
			count++
			delete(selected, ws.Files[i].Path)
		}
	}
	if len(selected) != 0 || count == 0 {
		writeError(w, 400, "stage must select existing nonempty files")
		return
	}
	ws.State = "staged"
	ws.BuildDigest = ""
	saved, err := store.SaveBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "build-workspace:stage", ws.ID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}

// buildDigest is stable across servers, timezones, map iteration and transport
// order. Runtime settings and tool versions are part of the input identity.
func buildDigest0226(ws repository.BuildWorkspace) (string, error) {
	basis := struct {
		Schema          string                   `json:"schema"`
		ProjectID       string                   `json:"projectId"`
		ProfileID       string                   `json:"profileId"`
		ProfileDigest   string                   `json:"profileDigest"`
		ProfileRevision int64                    `json:"profileRevision"`
		Channel         string                   `json:"channel"`
		Version         string                   `json:"version"`
		Settings        repository.BuildSettings `json:"settings"`
		Files           []repository.BuildFile   `json:"files"`
	}{"never-build-workspace-v1", ws.ProjectID, ws.ProfileID, ws.ProfileDigest, ws.ProfileRevision, ws.Channel, ws.Version, ws.Settings, selectedFiles0226(ws)}
	b, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func (s Server) workspaceValidate0226(ws repository.BuildWorkspace) (string, error) {
	if ws.State != "staged" && ws.State != "built" {
		return "", errors.New("stage files before validation")
	}
	files := selectedFiles0226(ws)
	if len(files) == 0 {
		return "", errors.New("no files staged")
	}
	snapshot, err := repository.ReadProfileSnapshot(s.Repo, ws.ProjectID, ws.ProfileID)
	if err != nil {
		return "", err
	}
	if snapshot.Digest != ws.ProfileDigest || snapshot.Revision != ws.ProfileRevision {
		return "", errors.New("profile revision changed; create a new workspace")
	}
	manifests := make([]model.ManifestFile, 0, len(files))
	for _, f := range files {
		if err = normalizeBuildFile0226(f); err != nil {
			return "", err
		}
		if err = s.workspaceVerifyFile0226(ws, f); err != nil {
			return "", err
		}
		manifests = append(manifests, model.ManifestFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256, URL: s.deliveryURL(ws.ProjectID, "preview", f.Path), Required: f.Ownership != "optional", Ownership: f.Ownership, Executable: f.Executable, TargetOS: f.TargetOS})
	}
	manifest := model.Manifest{SchemaVersion: model.ManifestSchemaV2, ProjectID: ws.ProjectID, ProfileID: ws.ProfileID, ProfileSnapshot: &snapshot, Channel: ws.Channel, Version: ws.Version, Minecraft: ws.Settings.Minecraft, Runtime: ws.Settings.Runtime, Directories: ws.Settings.Directories, FileRules: ws.Settings.FileRules, Files: manifests}
	if err = validateCompatibilityManifest(manifest); err != nil {
		return "", err
	}
	return buildDigest0226(ws)
}
func (s Server) workspaceValidateHandler0226(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	digest, err := s.workspaceValidate0226(ws)
	if err != nil {
		writeError(w, 409, "build validation failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"valid": true, "buildDigest": digest, "fileCount": len(selectedFiles0226(ws)), "profileRevision": ws.ProfileRevision}})
}
func (s Server) workspaceBuild0226(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	if ws.State == "built" {
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": ws})
		return
	}
	var req struct {
		Revision int64 `json:"revision"`
	}
	if err = readJSON0226(w, r, 4096, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if ws.Revision != req.Revision {
		writeError(w, 409, "workspace revision conflict")
		return
	}
	digest, err := s.workspaceValidate0226(ws)
	if err != nil {
		writeError(w, 409, "cannot build: "+err.Error())
		return
	}
	// Reserve the release identity *before* creating files. Both workspace and
	// package locks protect retries and competing uploads; a foreign package
	// can never be adopted merely because metadata happens to match.
	packageID := ws.ProjectID + "-" + ws.ProfileID + "-" + ws.Version
	packageUnlock, err := s.lockPackageMutation(r.Context(), "package:"+packageID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer packageUnlock()
	if ws.PackageID == "" {
		versions, lookupErr := s.Repo.ListVersions(ws.ProjectID)
		if lookupErr != nil {
			writeError(w, 503, "cannot verify package reservation: "+lookupErr.Error())
			return
		}
		for _, existing := range versions {
			if existing.ID == packageID || (existing.ProfileID == ws.ProfileID && existing.Channel == ws.Channel && existing.Version == ws.Version) {
				writeError(w, 409, "version already belongs to another release operation")
				return
			}
		}
		ws.PackageID = packageID
		ws, err = store.SaveBuildWorkspace(r.Context(), ws)
		if err != nil {
			writeError(w, 409, err.Error())
			return
		}
	}
	if ws.PackageID != packageID {
		writeError(w, 409, "workspace is bound to another package")
		return
	}
	release, err := s.Repo.CreateVersion(ws.ProjectID, ws.ProfileID, ws.Channel, ws.Version)
	if errors.Is(err, repository.ErrConflict) {
		versions, lookupErr := s.Repo.ListVersions(ws.ProjectID)
		if lookupErr != nil {
			writeError(w, 503, lookupErr.Error())
			return
		}
		found := false
		for _, candidate := range versions {
			if candidate.ID == packageID {
				release = candidate
				found = true
				break
			}
		}
		if !found {
			writeError(w, 409, "version exists but is inaccessible")
			return
		}
		if release.ProjectID != ws.ProjectID || release.ProfileID != ws.ProfileID || release.Channel != ws.Channel || release.Version != ws.Version || release.Status != "draft" || release.Manifest.ProfileSnapshot == nil || release.Manifest.ProfileSnapshot.Digest != ws.ProfileDigest || release.Manifest.ProfileSnapshot.Revision != ws.ProfileRevision {
			writeError(w, 409, "existing version does not match pinned workspace")
			return
		}
	} else if err != nil {
		writeError(w, 409, "create package: "+err.Error())
		return
	}
	if release.Manifest.ProfileSnapshot == nil || release.Manifest.ProfileSnapshot.Digest != ws.ProfileDigest || release.Manifest.ProfileSnapshot.Revision != ws.ProfileRevision {
		writeError(w, 409, "release snapshot differs from build workspace; cannot materialize")
		return
	}
	oldFiles, err := s.Repo.ListFiles(ws.ProjectID, release.ID)
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	oldByPath := map[string]model.FileObject{}
	for _, f := range oldFiles {
		oldByPath[f.Path] = f
	}
	selected := selectedFiles0226(ws)
	if len(oldFiles) > len(selected) {
		writeError(w, 409, "package already has external files")
		return
	}
	for _, f := range oldFiles {
		found := false
		for _, candidate := range selected {
			if candidate.Path == f.Path && candidate.SHA256 == f.SHA256 && candidate.Size == f.Size && candidate.Ownership == f.Ownership {
				found = true
				break
			}
		}
		if !found {
			writeError(w, 409, "package has foreign or mutated files")
			return
		}
	}
	for _, f := range selected {
		if _, ok := oldByPath[f.Path]; ok {
			continue
		}
		// Every source is AEAD-authenticated and SHA-256 verified again before copying.
		data, e := s.readWorkspaceSource0226(ws, f)
		if e != nil {
			writeError(w, 409, "source content changed: "+e.Error())
			return
		}
		if e = s.beforeStorageWrite0206(r, ws.ProjectID, release.ID, f.Path); e != nil {
			writeError(w, 409, e.Error())
			return
		}
		_, n, e := s.Storage.Save(ws.ProjectID, release.ID, f.Path, bytes.NewReader(data))
		if e != nil || n != f.Size {
			writeError(w, 503, "cannot store built file")
			return
		}
		object := model.FileObject{ProjectID: ws.ProjectID, VersionID: release.ID, Path: f.Path, Size: f.Size, SHA256: f.SHA256, URL: s.deliveryURL(ws.ProjectID, release.ID, f.Path), Required: f.Ownership != "optional", Ownership: f.Ownership, Executable: f.Executable, TargetOS: f.TargetOS}
		savedObject, addErr := s.Repo.AddFile(object)
		if addErr != nil {
			writeError(w, 503, "cannot index built file: "+addErr.Error())
			return
		}
		s.storageWritten0206(r, savedObject)
	}
	manifest := release.Manifest
	manifest.Minecraft = ws.Settings.Minecraft
	manifest.Runtime = ws.Settings.Runtime
	manifest.Directories = ws.Settings.Directories
	manifest.FileRules = ws.Settings.FileRules
	manifest.Signature = nil
	// The profile snapshot is owned by CreateVersion, never overwritten here.
	if e := model.ValidateManifestSchema(manifest); e != nil {
		writeError(w, 409, e.Error())
		return
	}
	if _, e = s.Repo.UpdateVersionManifest(ws.ProjectID, release.ID, manifest); e != nil {
		writeError(w, 409, "cannot save manifest: "+e.Error())
		return
	}
	ws.State = "built"
	ws.PackageID = release.ID
	ws.BuildDigest = digest
	saved, err := store.SaveBuildWorkspace(r.Context(), ws)
	if err != nil {
		writeError(w, 409, "workspace save failed; retry build: "+err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "build-workspace:build", ws.ID+":"+digest)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}
