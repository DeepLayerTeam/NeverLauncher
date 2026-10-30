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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// factoryReadSource0401 refuses symlinks at every level, rejects changing
// contents, and hashes bytes rather than trusting a CLI-supplied JSON digest.
// The caller holds the workspace mutation lock and re-verifies the entire
// factory plan with the real CLI before reading any output.
func factoryReadSource0401(root string, f struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}, max int64) ([]byte, error) {
	if f.Size < 0 || f.Size > max || len(f.SHA256) != 64 {
		return nil, errors.New("invalid factory output size or SHA-256")
	}
	if f.Path == "" || filepath.IsAbs(f.Path) || strings.ContainsAny(f.Path, "\\\x00") {
		return nil, errors.New("invalid factory output path")
	}
	if stat, err := os.Lstat(root); err != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("invalid factory output root")
	}
	full := root
	for _, part := range strings.Split(f.Path, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("factory output path traversal")
		}
		full = filepath.Join(full, part)
		st, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("factory output contains symlink")
		}
	}
	file, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() != f.Size {
		return nil, errors.New("factory output size/type mismatch")
	}
	b, err := io.ReadAll(io.LimitReader(file, f.Size+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if int64(len(b)) != f.Size || !strings.EqualFold(hex.EncodeToString(sum[:]), f.SHA256) {
		return nil, fmt.Errorf("factory output changed: %s", f.Path)
	}
	return b, nil
}

func factoryPrepareWorkspace0401(ws repository.BuildWorkspace, p factoryPlanView02710, job factoryBuilderJob02710, maxFileBytes int64) (repository.BuildWorkspace, error) {
	if ws.State != "importing" || ws.PackageID != "" || len(ws.Files) > 0 {
		return ws, errors.New("factory delivery requires an empty, unbuilt workspace")
	}
	if p.MinecraftVersion != ws.Settings.Minecraft.Version || p.Loader != ws.Settings.Minecraft.Loader || p.MinecraftVersion != job.Request.Minecraft || p.Loader != job.Request.Loader {
		return ws, errors.New("factory Minecraft/loader differs from pinned workspace")
	}
	if p.Loader != "vanilla" && ((job.Request.Source != "modpack" && p.LoaderVersion != job.Request.LoaderVersion) || p.LoaderVersion != ws.Settings.Minecraft.LoaderVersion) {
		return ws, errors.New("factory loader version differs from pinned workspace")
	}
	if p.Java.Major != ws.Settings.Runtime.Java.MajorVersion {
		return ws, fmt.Errorf("factory requires Java %d, pinned workspace requires Java %d", p.Java.Major, ws.Settings.Runtime.Java.MajorVersion)
	}
	if (ws.Settings.Minecraft.MainClass != "" && ws.Settings.Minecraft.MainClass != p.Launch.MainClass) ||
		(ws.Settings.Runtime.Launch.MainClass != "" && ws.Settings.Runtime.Launch.MainClass != p.Launch.MainClass) ||
		len(ws.Settings.Runtime.Launch.ClasspathEntries) != 0 || len(ws.Settings.Runtime.Launch.ModulepathEntries) != 0 ||
		ws.Settings.Runtime.Launch.MainModule != "" || ws.Settings.Runtime.Launch.OfflineMode {
		return ws, errors.New("workspace has launch overrides incompatible with factory metadata")
	}
	if ws.Settings.Runtime.Launch.ClasspathStrategy != "" && ws.Settings.Runtime.Launch.ClasspathStrategy != "mojang" {
		return ws, errors.New("factory delivery needs Mojang compatibility launch strategy")
	}
	metadata := strings.TrimSpace(p.Launch.ProfilePath)
	if metadata == "" || p.Launch.MainClass == "" || !strings.HasSuffix(metadata, ".json") {
		return ws, errors.New("factory has no executable Minecraft metadata profile")
	}
	if ws.Settings.Runtime.Launch.VersionMetadataPath != "" && ws.Settings.Runtime.Launch.VersionMetadataPath != metadata {
		return ws, errors.New("pinned metadata path does not match factory launcher")
	}
	if len(p.Outputs) == 0 || len(p.Outputs) > maxWorkspaceFiles0226 {
		return ws, errors.New("factory output count exceeds workspace limits")
	}
	osName := strings.SplitN(job.Request.Target, "/", 2)[0]
	if osName == "darwin" {
		osName = "macos"
	}
	if osName != "windows" && osName != "linux" && osName != "macos" {
		return ws, errors.New("unrecognized factory target")
	}
	requested := strings.Split(job.Request.Target, "/")
	if len(requested) != 2 || len(p.Targets) != 1 {
		return ws, errors.New("factory target identity not uniquely pinned")
	}
	targetOS := requested[0]
	if targetOS == "darwin" {
		targetOS = "osx"
	}
	if p.Targets[0].OS != targetOS || p.Targets[0].Arch != requested[1] {
		return ws, errors.New("factory output target differs from requested OS/architecture")
	}
	files := make([]repository.BuildFile, 0, len(p.Outputs))
	seen := map[string]bool{}
	hasMetadata := false
	for _, f := range p.Outputs {
		key := strings.ToLower(f.Path)
		if seen[key] {
			return ws, errors.New("case-insensitive factory output collision")
		}
		seen[key] = true
		if f.Path == metadata {
			hasMetadata = true
		}
		if f.Size < 0 || f.Size > maxFileBytes || len(f.SHA256) != 64 {
			return ws, fmt.Errorf("factory file too large or invalid: %s", f.Path)
		}
		file := repository.BuildFile{Path: f.Path, Size: f.Size, SHA256: strings.ToLower(f.SHA256), Ownership: "required", Selected: true, TargetOS: []string{osName}}
		if err := normalizeBuildFile0226(file); err != nil {
			return ws, fmt.Errorf("factory output %s: %w", f.Path, err)
		}
		files = append(files, file)
	}
	if !hasMetadata {
		return ws, errors.New("factory executable version metadata is absent from verified outputs")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	ws.Files = files
	ws.Settings.Runtime.Launch.ClasspathStrategy = "mojang"
	ws.Settings.Runtime.Launch.VersionMetadataPath = metadata
	ws.State = "importing"
	ws.BuildDigest = ""
	return ws, nil
}

// Factory output moves into encrypted, private Build Workspace storage. The
// entire workspace record commits in one CAS operation after every byte has
// been rechecked and stored, preventing partial, publishable imports.
func (s Server) factoryDeliver0401(w http.ResponseWriter, r *http.Request) {
	store, ws, ok := s.ownedWorkspace0226(w, r, "file:write")
	if !ok {
		return
	}
	factoryStore, ok := store.(repository.FactoryWorkspaceStore0401)
	if !ok {
		writeError(w, 503, "factory workspace persistence unavailable")
		return
	}
	binary, root, err := factoryConfig02710()
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	job, dir, err := factoryRead02710(root, r.PathValue("jobId"))
	if err != nil || job.OwnerID != ws.OwnerID || job.ProjectID != ws.ProjectID || job.WorkspaceID != ws.ID || job.State != "completed" {
		writeError(w, 404, "completed factory job not found")
		return
	}
	var req struct {
		Revision int64 `json:"revision"`
	}
	if err = readJSON0226(w, r, 4096, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	unlock, err := s.lockPackageMutation(r.Context(), "build-workspace:"+ws.ID)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	defer unlock()
	ws, err = store.GetBuildWorkspace(r.Context(), ws.ID)
	if err != nil || ws.Revision != req.Revision {
		writeError(w, 409, "workspace revision conflict")
		return
	}
	p, err := factoryLoadPlan02710(dir)
	if err != nil || job.PlanDigest != p.ReproducibilitySHA256 {
		writeError(w, 409, "factory job output/plan mismatch")
		return
	}
	client := filepath.Join(dir, "client")
	verifyCtx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	// Do not write into a path inside client; a CLI verifier only inspects it.
	if err = factoryInvoke02710(verifyCtx, binary, dir, io.Discard, "runtime", "client-factory", "verify", "--client-dir", client, "--output", filepath.Join(dir, "delivery-verify.json")); err != nil {
		writeError(w, 409, "factory verification failed before delivery")
		return
	}
	var verified factoryPlanView02710
	resultBytes, readErr := os.ReadFile(filepath.Join(dir, "delivery-verify.json"))
	if readErr != nil {
		writeError(w, 409, "factory verify output unreadable")
		return
	}
	err = json.Unmarshal(resultBytes, &verified)
	if err != nil || verified.ReproducibilitySHA256 != p.ReproducibilitySHA256 {
		writeError(w, 409, "verified factory digest changed")
		return
	}
	maxFile := s.maxUploadBytes()
	ws, err = factoryPrepareWorkspace0401(ws, p, job, maxFile)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	for _, file := range ws.Files {
		if err = r.Context().Err(); err != nil {
			writeError(w, 408, "factory transfer cancelled")
			return
		}
		data, readErr := factoryReadSource0401(client, struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		}{file.Path, file.SHA256, file.Size}, maxFile)
		if readErr != nil {
			writeError(w, 409, "factory file validation failed: "+readErr.Error())
			return
		}
		encrypted, encErr := s.encryptWorkspace0226(ws, file, data)
		if encErr != nil {
			writeError(w, 503, "factory source encryption failed")
			return
		}
		if _, _, err = s.Storage.Save(ws.ProjectID, ws.ID, workspaceObjectPath0226(file), bytes.NewReader(encrypted)); err != nil {
			writeError(w, 503, "factory source storage write failed")
			return
		}
	}
	// All objects have been written; independent decryption prevents storage
	// backends that silently truncate or corrupt data from creating a workspace.
	for _, file := range ws.Files {
		if err = s.workspaceVerifyFile0226(ws, file); err != nil {
			writeError(w, 503, "stored factory source failed integrity verification")
			return
		}
	}
	saved, err := factoryStore.SaveFactoryWorkspace0401(r.Context(), ws)
	if err != nil {
		writeError(w, 409, "factory delivery commit failed: "+err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "client-factory:deliver", job.ID+":"+p.ReproducibilitySHA256)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}

// Keep references to both wire constraints and real per-file storage in this
// adapter; no client-supplied manifest or untrusted download URL is accepted.
