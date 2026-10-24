package httpapi

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// This is an execution bridge, not a second Minecraft installer. Every job
// invokes the pinned CLI materializers and CLI verification, never a shell.
// It is disabled unless an operator supplies an absolute CLI binary and a
// private root directory. Requests cannot supply paths, URLs or executables.
var factoryID02710 = regexp.MustCompile(`^[a-f0-9]{32}$`)
var factoryVersion02710 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,95}$`)
var factoryMinecraft02710 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+\- ]{0,95}$`)
var factoryProcesses02710 sync.Map             // job ID -> context.CancelFunc (one API process)
var factorySlots02710 = make(chan struct{}, 2) // bound concurrent build processes

type factoryBuilderRequest02710 struct {
	Source        string `json:"source,omitempty"`
	Minecraft     string `json:"minecraft"`
	Loader        string `json:"loader"`
	LoaderVersion string `json:"loaderVersion"`
	Target        string `json:"target"`
}
type factoryBuilderJob02710 struct {
	ID          string                     `json:"id"`
	WorkspaceID string                     `json:"workspaceId"`
	ProjectID   string                     `json:"projectId"`
	OwnerID     string                     `json:"ownerId"`
	Request     factoryBuilderRequest02710 `json:"request"`
	State       string                     `json:"state"`
	CreatedAt   time.Time                  `json:"createdAt"`
	UpdatedAt   time.Time                  `json:"updatedAt"`
	Error       string                     `json:"error,omitempty"`
	PlanDigest  string                     `json:"planDigest,omitempty"`
	Files       int                        `json:"files"`
}
type factoryPlanView02710 struct {
	ReproducibilitySHA256 string `json:"reproducibilitySha256"`
	MinecraftVersion      string `json:"minecraftVersion"`
	Loader                string `json:"loader"`
	LoaderVersion         string `json:"loaderVersion"`
	Java                  struct {
		Major int `json:"major"`
	} `json:"java"`
	Steps []struct {
		ID      string `json:"id"`
		Adapter string `json:"adapter"`
	} `json:"steps"`
	Sources []struct {
		Path   string `json:"path"`
		Kind   string `json:"kind"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"sources"`
	Outputs []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"outputs"`
	Processors []json.RawMessage `json:"processors"`
}

func factoryConfig02710() (string, string, error) {
	binary := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_FACTORY_CLI"))
	root := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_FACTORY_ROOT"))
	if !filepath.IsAbs(binary) || !filepath.IsAbs(root) {
		return "", "", errors.New("configure absolute NEVERLAUNCHER_FACTORY_CLI and NEVERLAUNCHER_FACTORY_ROOT")
	}
	stat, err := os.Stat(binary)
	if err != nil || stat.IsDir() || stat.Mode()&0111 == 0 {
		return "", "", errors.New("Client Factory CLI executable unavailable")
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return "", "", err
	}
	if stat, err = os.Lstat(root); err != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0022 != 0 {
		return "", "", errors.New("Client Factory root must be a private directory, not a symlink")
	}
	return binary, root, nil
}
func factoryJobPath02710(root, id string) (string, error) {
	if !factoryID02710.MatchString(id) {
		return "", errors.New("invalid job ID")
	}
	return filepath.Join(root, "jobs", id), nil
}
func factorySave02710(dir string, job factoryBuilderJob02710) error {
	job.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "job.json.tmp")
	if err = os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "job.json"))
}
func factoryRead02710(root, id string) (factoryBuilderJob02710, string, error) {
	var job factoryBuilderJob02710
	dir, err := factoryJobPath02710(root, id)
	if err != nil {
		return job, "", err
	}
	b, err := os.ReadFile(filepath.Join(dir, "job.json"))
	if err != nil {
		return job, "", err
	}
	err = json.Unmarshal(b, &job)
	if err != nil {
		return job, "", err
	}
	if job.ID != id {
		return job, "", errors.New("job identity mismatch")
	}
	// A process crash cannot leave an indefinitely "running" job in the UI.
	if job.State == "running" || job.State == "verifying" || job.State == "queued" {
		if _, live := factoryProcesses02710.Load(id); !live && (job.State != "queued" || time.Since(job.UpdatedAt) > time.Minute) {
			job.State = "interrupted"
			job.Error = "Worker interrupted; create a new job. Partial output is not publishable."
		}
	}
	return job, dir, nil
}
func factoryMutableSelector02710(version string) bool {
	value := strings.ToLower(strings.TrimSpace(version))
	return value == "latest" || value == "stable" || value == "recommended" || strings.HasPrefix(value, "latest-") || strings.HasPrefix(value, "recommended-")
}
func factoryValidateRequest02710(r factoryBuilderRequest02710) error {
	if factoryMutableSelector02710(r.Minecraft) || strings.Contains(r.Minecraft, "..") || !factoryMinecraft02710.MatchString(r.Minecraft) {
		return errors.New("select an exact Minecraft version (no mutable selectors)")
	}
	switch r.Loader {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		return errors.New("unsupported loader")
	}
	if r.Loader != "vanilla" && (factoryMutableSelector02710(r.LoaderVersion) || strings.Contains(r.LoaderVersion, "..") || !factoryVersion02710.MatchString(r.LoaderVersion)) {
		return errors.New("enter an exact loader version")
	}
	if r.Target != "windows/x86_64" && r.Target != "windows/x86" && r.Target != "linux/x86_64" && r.Target != "linux/aarch64" && r.Target != "darwin/x86_64" && r.Target != "darwin/aarch64" {
		return errors.New("unsupported target")
	}
	return nil
}
func factoryCleanEnv02710(dir string) []string {
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + filepath.Join(dir, "tmp"), "LANG=C.UTF-8"}
	// Explicitly selected proxy / certificate configuration, not parent tokens.
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

type factoryLimitedLog02710 struct {
	dest      io.Writer
	remaining int64
}

func (l *factoryLimitedLog02710) Write(b []byte) (int, error) {
	n := len(b)
	if l.remaining > 0 {
		part := b
		if int64(len(part)) > l.remaining {
			part = part[:int(l.remaining)]
		}
		written, err := l.dest.Write(part)
		l.remaining -= int64(written)
		if err != nil {
			return written, err
		}
	}
	return n, nil
}
func factoryInvoke02710(ctx context.Context, binary, dir string, log io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Env = factoryCleanEnv02710(dir)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Client Factory execution failed: %w", err)
	}
	return nil
}
func factoryLoadPlan02710(dir string) (factoryPlanView02710, error) {
	var p factoryPlanView02710
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(b, &p)
	if err != nil {
		return p, err
	}
	if len(p.ReproducibilitySHA256) != 64 || len(p.Outputs) == 0 {
		return p, errors.New("incomplete CLI InstallPlan")
	}
	return p, nil
}
func factoryRun02710(binary, root string, job factoryBuilderJob02710) {
	dir, _ := factoryJobPath02710(root, job.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Minute)
	factoryProcesses02710.Store(job.ID, cancel)
	defer func() { cancel(); factoryProcesses02710.Delete(job.ID) }()
	select {
	case factorySlots02710 <- struct{}{}:
		defer func() { <-factorySlots02710 }()
	case <-ctx.Done():
		job.State = "cancelled"
		job.Error = ctx.Err().Error()
		_ = factorySave02710(dir, job)
		return
	}
	if err := ctx.Err(); err != nil {
		job.State = "cancelled"
		job.Error = err.Error()
		_ = factorySave02710(dir, job)
		return
	}
	job.State = "running"
	_ = factorySave02710(dir, job)
	_ = os.Mkdir(filepath.Join(dir, "tmp"), 0700)
	logfile, err := os.OpenFile(filepath.Join(dir, "execution.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		job.State = "failed"
		job.Error = "cannot open execution journal"
		_ = factorySave02710(dir, job)
		return
	}
	defer logfile.Close()
	log := &factoryLimitedLog02710{dest: logfile, remaining: 2 << 20}
	args := []string{"runtime", "client-factory", "build", "--loader", job.Request.Loader, "--minecraft", job.Request.Minecraft, "--client-dir", filepath.Join(dir, "client"), "--target", job.Request.Target, "--workers", "6", "--processor-timeout", "15m", "--strict-upstream", "true", "--output", filepath.Join(dir, "plan.json")}
	if job.Request.Loader != "vanilla" {
		args = append(args, "--loader-version", job.Request.LoaderVersion)
	}
	if sandbox := os.Getenv("NEVERLAUNCHER_FACTORY_SANDBOX"); sandbox == "required" {
		args = append(args, "--processor-sandbox", "required")
	}
	if java := os.Getenv("NEVERLAUNCHER_FACTORY_JAVA"); filepath.IsAbs(java) {
		args = append(args, "--java", java)
	}
	if job.Request.Source == "modpack" {
		args = []string{"runtime", "client-factory", "import-modpack", "--file", filepath.Join(dir, "source.zip"), "--client-dir", filepath.Join(dir, "client"), "--target", job.Request.Target, "--workers", "6", "--processor-timeout", "15m", "--distribution", "local", "--output", filepath.Join(dir, "import-result.json"), "--report", filepath.Join(dir, "import-report.json")}
		if sandbox := os.Getenv("NEVERLAUNCHER_FACTORY_SANDBOX"); sandbox == "required" {
			args = append(args, "--processor-sandbox", "required")
		}
		if java := os.Getenv("NEVERLAUNCHER_FACTORY_JAVA"); filepath.IsAbs(java) {
			args = append(args, "--java", java)
		}
	}
	if err = factoryInvoke02710(ctx, binary, dir, log, args...); err == nil {
		job.State = "verifying"
		_ = factorySave02710(dir, job)
		err = factoryInvoke02710(ctx, binary, dir, log, "runtime", "client-factory", "verify", "--client-dir", filepath.Join(dir, "client"), "--output", filepath.Join(dir, "verified-plan.json"))
	}
	if err == nil && job.Request.Source == "modpack" {
		// Import emits a report, not a factory plan. The verified CLI plan is
		// the only authoritative result, and must match this workspace.
		b, e := os.ReadFile(filepath.Join(dir, "verified-plan.json"))
		if e != nil {
			err = e
		} else {
			err = os.WriteFile(filepath.Join(dir, "plan.json"), b, 0600)
		}
	}
	if err == nil {
		var p factoryPlanView02710
		p, err = factoryLoadPlan02710(dir)
		if err == nil {
			if p.MinecraftVersion != job.Request.Minecraft || p.Loader != job.Request.Loader || (job.Request.LoaderVersion != "" && p.LoaderVersion != job.Request.LoaderVersion) {
				err = errors.New("imported modpack does not match pinned Minecraft/loader workspace identity")
			} else {
				job.PlanDigest = p.ReproducibilitySHA256
				job.Files = len(p.Outputs)
			}
		}
	}
	if err != nil {
		job.State = "failed"
		if errors.Is(ctx.Err(), context.Canceled) {
			job.State = "cancelled"
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			job.Error = "build timed out"
		} else {
			job.Error = err.Error()
		}
	}
	if err == nil {
		job.State = "completed"
	}
	_ = factorySave02710(dir, job)
}
func factoryResult02710(w http.ResponseWriter, data any) {
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": data})
}
func (s Server) factoryCreate02710(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	binary, root, err := factoryConfig02710()
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	if ws.State == "built" {
		writeError(w, 409, "cannot start factory after workspace is built")
		return
	}
	var req factoryBuilderRequest02710
	if err = readJSON0226(w, r, 4096, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.Minecraft != ws.Settings.Minecraft.Version || req.Loader != ws.Settings.Minecraft.Loader {
		writeError(w, 409, "requested Minecraft and loader must match the pinned Build Workspace")
		return
	}
	if ws.Settings.Minecraft.LoaderVersion != "" && req.Loader != "vanilla" && req.LoaderVersion != ws.Settings.Minecraft.LoaderVersion {
		writeError(w, 409, "loader version differs from pinned Build Workspace")
		return
	}
	if req.Source != "" && req.Source != "minecraft" {
		writeError(w, 400, "modpack requires multipart upload")
		return
	}
	if err = factoryValidateRequest02710(req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	entries, listErr := os.ReadDir(filepath.Join(root, "jobs"))
	if listErr != nil && !errors.Is(listErr, os.ErrNotExist) {
		writeError(w, 503, "cannot inspect Client Factory storage")
		return
	}
	ownJobs := 0
	for _, entry := range entries {
		if !entry.IsDir() || !factoryID02710.MatchString(entry.Name()) {
			continue
		}
		existing, _, e := factoryRead02710(root, entry.Name())
		if e == nil && existing.OwnerID == ws.OwnerID && existing.WorkspaceID == ws.ID {
			ownJobs++
		}
	}
	if ownJobs >= 20 {
		writeError(w, 429, "job quota reached (20); delete completed jobs")
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		writeError(w, 503, "cannot generate job ID")
		return
	}
	job := factoryBuilderJob02710{ID: hex.EncodeToString(id[:]), WorkspaceID: ws.ID, ProjectID: ws.ProjectID, OwnerID: ws.OwnerID, Request: req, State: "queued", CreatedAt: time.Now().UTC()}
	dir, _ := factoryJobPath02710(root, job.ID)
	if err = os.MkdirAll(filepath.Dir(dir), 0700); err == nil {
		err = os.Mkdir(dir, 0700)
	}
	if err == nil {
		err = factorySave02710(dir, job)
	}
	if err != nil {
		writeError(w, 503, "cannot create job: "+err.Error())
		return
	}
	s.audit(r, ws.OwnerID, "client-factory:build", ws.ID+":"+job.ID)
	go factoryRun02710(binary, root, job)
	factoryResult02710(w, job)
}
func (s Server) factoryOwnedJob02710(w http.ResponseWriter, r *http.Request) (factoryBuilderJob02710, string, string, string, bool) {
	var zero factoryBuilderJob02710
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return zero, "", "", "", false
	}
	binary, root, err := factoryConfig02710()
	if err != nil {
		writeError(w, 503, err.Error())
		return zero, "", "", "", false
	}
	job, dir, err := factoryRead02710(root, r.PathValue("jobId"))
	if err != nil || job.WorkspaceID != ws.ID || job.ProjectID != ws.ProjectID || job.OwnerID != ws.OwnerID {
		writeError(w, 404, "factory job not found")
		return zero, "", "", "", false
	}
	return job, dir, binary, root, true
}
func (s Server) factoryGet02710(w http.ResponseWriter, r *http.Request) {
	job, dir, _, _, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	log, err := os.ReadFile(filepath.Join(dir, "execution.log"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, 503, "cannot read execution log")
		return
	}
	if len(log) > 24<<10 {
		log = log[len(log)-(24<<10):]
	}
	data := map[string]any{"job": job, "log": string(log)}
	if job.Request.Source == "modpack" {
		if report, e := os.ReadFile(filepath.Join(dir, "import-report.json")); e == nil && len(report) < 512<<10 {
			var parsed any
			if json.Unmarshal(report, &parsed) == nil {
				data["importReport"] = parsed
			}
		}
	}
	if job.State == "completed" {
		if plan, err := factoryLoadPlan02710(dir); err == nil {
			data["plan"] = plan
		}
	}
	factoryResult02710(w, data)
}
func (s Server) factoryCancel02710(w http.ResponseWriter, r *http.Request) {
	job, _, _, _, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	if cancel, exists := factoryProcesses02710.Load(job.ID); exists {
		cancel.(context.CancelFunc)()
		factoryResult02710(w, map[string]string{"status": "cancellation_requested"})
		return
	}
	writeError(w, 409, "worker is not running")
}
func (s Server) factoryDiff02710(w http.ResponseWriter, r *http.Request) {
	job, dir, _, root, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	if job.State != "completed" {
		writeError(w, 409, "build not verified")
		return
	}
	current, err := factoryLoadPlan02710(dir)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	prior := map[string]string{}
	base := r.URL.Query().Get("baseJob")
	if base != "" {
		old, oldDir, e := factoryRead02710(root, base)
		if e != nil || old.State != "completed" || old.OwnerID != job.OwnerID || old.ProjectID != job.ProjectID || old.WorkspaceID != job.WorkspaceID {
			writeError(w, 404, "base job not found")
			return
		}
		p, e := factoryLoadPlan02710(oldDir)
		if e != nil {
			writeError(w, 409, e.Error())
			return
		}
		for _, f := range p.Outputs {
			prior[f.Path] = f.SHA256
		}
	}
	changes := make([]map[string]string, 0)
	for _, f := range current.Outputs {
		status := "added"
		if digest, exists := prior[f.Path]; exists {
			if digest == f.SHA256 {
				status = "unchanged"
			} else {
				status = "modified"
			}
		}
		changes = append(changes, map[string]string{"path": f.Path, "change": status, "sha256": f.SHA256})
		delete(prior, f.Path)
	}
	for path := range prior {
		changes = append(changes, map[string]string{"path": path, "change": "removed"})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i]["path"] < changes[j]["path"] })
	factoryResult02710(w, map[string]any{"items": changes, "baseJob": base})
}
func factoryVerifyArtifact02710(root, path, digest string) (string, error) {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || strings.Contains(path, "\x00") {
		return "", errors.New("invalid artifact path")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("unsafe artifact path")
		}
	}
	full := filepath.Join(root, filepath.FromSlash(path))
	stat, err := os.Lstat(full)
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() {
		return "", errors.New("non-regular artifact")
	}
	file, err := os.Open(full)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return "", fmt.Errorf("artifact %s checksum mismatch", path)
	}
	return full, nil
}
func (s Server) factoryExport02710(w http.ResponseWriter, r *http.Request) {
	job, dir, binary, _, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	if job.State != "completed" {
		writeError(w, 409, "only verified jobs can be exported")
		return
	}
	p, err := factoryLoadPlan02710(dir)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	client := filepath.Join(dir, "client")
	// Re-run the CLI's complete verifier before serving any bytes.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	if err = factoryInvoke02710(ctx, binary, dir, io.Discard, "runtime", "client-factory", "verify", "--client-dir", client, "--output", filepath.Join(dir, "export-verification.json")); err != nil {
		writeError(w, 409, "runtime integrity verification failed")
		return
	}
	paths := make([]string, 0, len(p.Outputs))
	sha := map[string]string{}
	for _, f := range p.Outputs {
		paths = append(paths, f.Path)
		sha[f.Path] = f.SHA256
	}
	paths = append(paths, ".neverlauncher/install-plan.json")
	sha[".neverlauncher/install-plan.json"] = "" // verifier checked the canonical lockfile
	sort.Strings(paths)
	// Verify paths before any response bytes are written. Avoid symlink traversal
	// through ancestors (which Lstat on the leaf alone would not detect).
	for _, path := range paths {
		full := client
		for _, part := range strings.Split(path, "/") {
			full = filepath.Join(full, part)
			st, e := os.Lstat(full)
			if e != nil || st.Mode()&os.ModeSymlink != 0 {
				writeError(w, 409, "unsafe artifact in output tree")
				return
			}
		}
		if sha[path] != "" {
			if _, err = factoryVerifyArtifact02710(client, path, sha[path]); err != nil {
				writeError(w, 409, err.Error())
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=neverlauncher-client-%s.zip", job.ID))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	archive := zip.NewWriter(w)
	for _, path := range paths {
		if err = r.Context().Err(); err != nil {
			break
		}
		file, e := os.Open(filepath.Join(client, filepath.FromSlash(path)))
		if e != nil {
			err = e
			break
		}
		entry, e := archive.Create(path)
		if e == nil {
			_, e = io.Copy(entry, file)
		}
		_ = file.Close()
		if e != nil {
			err = e
			break
		}
	}
	_ = archive.Close()
	if err == nil {
		s.audit(r, job.OwnerID, "client-factory:export", job.ID)
	}
}

// Lists durable jobs after browser refresh or an API restart. No directory
// listing is exposed: only jobs owned by this operator and workspace appear.
func (s Server) factoryList02710(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	_, root, err := factoryConfig02710()
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	entries, err := os.ReadDir(filepath.Join(root, "jobs"))
	if errors.Is(err, os.ErrNotExist) {
		factoryResult02710(w, map[string]any{"items": []factoryBuilderJob02710{}})
		return
	}
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	items := make([]factoryBuilderJob02710, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !factoryID02710.MatchString(entry.Name()) {
			continue
		}
		job, _, e := factoryRead02710(root, entry.Name())
		if e == nil && job.OwnerID == ws.OwnerID && job.ProjectID == ws.ProjectID && job.WorkspaceID == ws.ID {
			items = append(items, job)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	if len(items) > 30 {
		items = items[:30]
	}
	factoryResult02710(w, map[string]any{"items": items})
}

// Only inactive jobs can be deleted. Removal reclaims large client trees and
// makes job quotas sustainable without allowing removal of running outputs.
func (s Server) factoryDelete02710(w http.ResponseWriter, r *http.Request) {
	job, dir, _, _, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	if _, running := factoryProcesses02710.Load(job.ID); running || !endedFactoryJob02710(job.State) {
		writeError(w, 409, "cancel and finish the worker before deleting its output")
		return
	}
	if job.State == "interrupted" {
		writeError(w, 409, "interrupted worker requires operator cleanup")
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		writeError(w, 503, "unable to remove completed build")
		return
	}
	s.audit(r, job.OwnerID, "client-factory:delete", job.ID)
	factoryResult02710(w, map[string]string{"deleted": job.ID})
}
func endedFactoryJob02710(state string) bool {
	return state == "completed" || state == "failed" || state == "cancelled" || state == "interrupted"
}

// Receive the archive with a strict bound; the real CLI parses and validates
// CurseForge/Modrinth ZIP contents. Upload never trusts browser file paths.
func (s Server) factoryModpackCreate02710(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	if ws.State == "built" {
		writeError(w, 409, "workspace is immutable")
		return
	}
	binary, root, err := factoryConfig02710()
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
	if err = r.ParseMultipartForm(8 << 20); err != nil {
		writeError(w, 413, "invalid or oversized modpack archive")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "modpack archive required")
		return
	}
	defer file.Close()
	extension := strings.ToLower(filepath.Ext(header.Filename))
	if extension != ".mrpack" && extension != ".zip" {
		writeError(w, 400, "only .mrpack or CurseForge ZIP supported")
		return
	}
	req := factoryBuilderRequest02710{Minecraft: ws.Settings.Minecraft.Version, Loader: ws.Settings.Minecraft.Loader, LoaderVersion: ws.Settings.Minecraft.LoaderVersion, Target: r.FormValue("target"), Source: "modpack"}
	// Imported packs determine their exact loader from the archive. A pinned
	// workspace without a loader version is valid and checked after install.
	if req.Loader != "vanilla" && req.LoaderVersion == "" { // validate only the target and pinned MC/loader here
		if !factoryMinecraft02710.MatchString(req.Minecraft) || factoryMutableSelector02710(req.Minecraft) {
			writeError(w, 409, "workspace Minecraft version must be exact")
			return
		}
		if req.Target != "linux/x86_64" && req.Target != "windows/x86_64" && req.Target != "windows/x86" && req.Target != "linux/aarch64" && req.Target != "darwin/x86_64" && req.Target != "darwin/aarch64" {
			writeError(w, 400, "unsupported target")
			return
		}
	} else if err = factoryValidateRequest02710(req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	entries, _ := os.ReadDir(filepath.Join(root, "jobs"))
	own := 0
	for _, entry := range entries {
		if !entry.IsDir() || !factoryID02710.MatchString(entry.Name()) {
			continue
		}
		j, _, e := factoryRead02710(root, entry.Name())
		if e == nil && j.OwnerID == ws.OwnerID && j.WorkspaceID == ws.ID {
			own++
		}
	}
	if own >= 20 {
		writeError(w, 429, "job quota reached")
		return
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		writeError(w, 503, "cannot allocate job")
		return
	}
	job := factoryBuilderJob02710{ID: hex.EncodeToString(random[:]), WorkspaceID: ws.ID, ProjectID: ws.ProjectID, OwnerID: ws.OwnerID, Request: req, State: "queued", CreatedAt: time.Now().UTC()}
	dir, _ := factoryJobPath02710(root, job.ID)
	if err = os.MkdirAll(filepath.Dir(dir), 0700); err == nil {
		err = os.Mkdir(dir, 0700)
	}
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	dst, e := os.OpenFile(filepath.Join(dir, "source.zip"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		writeError(w, 503, "cannot store uploaded modpack")
		return
	}
	var size int64
	size, e = io.Copy(dst, io.LimitReader(file, 128<<20))
	_ = dst.Close()
	if e != nil || size < 4 || size >= 128<<20 {
		_ = os.RemoveAll(dir)
		writeError(w, 413, "modpack too large or invalid")
		return
	}
	signature, e := os.Open(filepath.Join(dir, "source.zip"))
	if e != nil {
		writeError(w, 503, "cannot read uploaded modpack")
		return
	}
	headerBytes := make([]byte, 4)
	_, e = io.ReadFull(signature, headerBytes)
	_ = signature.Close()
	if e != nil || !strings.HasPrefix(string(headerBytes), "PK") {
		_ = os.RemoveAll(dir)
		writeError(w, 400, "invalid ZIP signature")
		return
	}
	if err = factorySave02710(dir, job); err != nil {
		_ = os.RemoveAll(dir)
		writeError(w, 503, "cannot save modpack job")
		return
	}
	s.audit(r, ws.OwnerID, "client-factory:modpack-import", ws.ID+":"+job.ID)
	go factoryRun02710(binary, root, job)
	factoryResult02710(w, job)
}
