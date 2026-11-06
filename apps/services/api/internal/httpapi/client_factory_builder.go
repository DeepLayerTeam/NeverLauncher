package httpapi

import (
	"archive/zip"
	"bytes"
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

// Это мост выполнения, а не второй установщик Minecraft. Каждая задача вызывает
// закреплённые CLI-материализаторы и проверку CLI, но никогда оболочку. Функция
// отключена, пока оператор не задаст абсолютный путь к CLI и закрытый корневой
// каталог. Запросы не могут задавать пути, URL или исполняемые файлы.
var factoryID02710 = regexp.MustCompile(`^[a-f0-9]{32}$`)
var factoryVersion02710 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,95}$`)
var factoryMinecraft02710 = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+\- ]{0,95}$`)
var factoryProcesses02710 sync.Map             // ID задания → context.CancelFunc (в рамках одного процесса API)
var factorySlots02710 = make(chan struct{}, 2) // ограничение числа параллельных процессов сборки

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
	Targets []struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"targets"`
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
	Launch     struct {
		ProfilePath string `json:"profilePath"`
		MainClass   string `json:"mainClass"`
	} `json:"launch"`
}

func factoryConfig02710() (string, string, error) {
	binary := strings.TrimSpace(os.Getenv("LAUNCHER_FACTORY_CLI"))
	root := strings.TrimSpace(os.Getenv("LAUNCHER_FACTORY_ROOT"))
	if !filepath.IsAbs(binary) || !filepath.IsAbs(root) {
		return "", "", errors.New("Настройте абсолютные пути LAUNCHER_FACTORY_CLI и LAUNCHER_FACTORY_ROOT")
	}
	stat, err := os.Stat(binary)
	if err != nil || stat.IsDir() || stat.Mode()&0111 == 0 {
		return "", "", errors.New("Недоступно: «исполняемый файл командной строки фабрики клиента»")
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return "", "", err
	}
	if stat, err = os.Lstat(root); err != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0022 != 0 {
		return "", "", errors.New("Client Factory root: требуется «закрытый каталог, не символическая ссылка»")
	}
	return binary, root, nil
}
func factoryJobPath02710(root, id string) (string, error) {
	if !factoryID02710.MatchString(id) {
		return "", errors.New("Некорректное значение: идентификатор задания")
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
		return job, "", errors.New("Несовпадение: «идентификатор задания»")
	}
	// Сбой процесса не должен навсегда оставлять задачу в состоянии «выполняется»
	// в интерфейсе.
	if job.State == "running" || job.State == "verifying" || job.State == "queued" {
		if _, live := factoryProcesses02710.Load(id); !live && (job.State != "queued" || time.Since(job.UpdatedAt) > time.Minute) {
			job.State = "interrupted"
			job.Error = "Обработчик прервал работу; создайте новое задание. Частичный результат нельзя публиковать."
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
		return errors.New("Выберите точную версию Minecraft (изменяемые селекторы не допускаются)")
	}
	switch r.Loader {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		return errors.New("Не поддерживается: загрузчик")
	}
	if r.Loader != "vanilla" && (factoryMutableSelector02710(r.LoaderVersion) || strings.Contains(r.LoaderVersion, "..") || !factoryVersion02710.MatchString(r.LoaderVersion)) {
		return errors.New("Введите точную версию загрузчика")
	}
	if r.Target != "windows/x86_64" && r.Target != "windows/x86" && r.Target != "linux/x86_64" && r.Target != "linux/aarch64" && r.Target != "darwin/x86_64" && r.Target != "darwin/aarch64" {
		return errors.New("Не поддерживается: цель")
	}
	return nil
}
func factoryCleanEnv02710(dir string) []string {
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + filepath.Join(dir, "tmp"), "LANG=C.UTF-8"}
	// Явно выбранная конфигурация прокси и сертификатов, а не унаследованные токены.
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
		return fmt.Errorf("Ошибка выполнения Client Factory: %w", err)
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
		return p, errors.New("Неполные данные: CLI InstallPlan")
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
		job.Error = "Не удалось открыть журнал выполнения"
		_ = factorySave02710(dir, job)
		return
	}
	defer logfile.Close()
	log := &factoryLimitedLog02710{dest: logfile, remaining: 2 << 20}
	args := []string{"runtime", "client-factory", "build", "--loader", job.Request.Loader, "--minecraft", job.Request.Minecraft, "--client-dir", filepath.Join(dir, "client"), "--target", job.Request.Target, "--workers", "6", "--processor-timeout", "15m", "--strict-upstream", "true", "--output", filepath.Join(dir, "plan.json")}
	if job.Request.Loader != "vanilla" {
		args = append(args, "--loader-version", job.Request.LoaderVersion)
	}
	if sandbox := os.Getenv("LAUNCHER_FACTORY_SANDBOX"); sandbox == "required" {
		args = append(args, "--processor-sandbox", "required")
	}
	if java := os.Getenv("LAUNCHER_FACTORY_JAVA"); filepath.IsAbs(java) {
		args = append(args, "--java", java)
	}
	if job.Request.Source == "modpack" {
		args = []string{"runtime", "client-factory", "import-modpack", "--file", filepath.Join(dir, "source.zip"), "--client-dir", filepath.Join(dir, "client"), "--target", job.Request.Target, "--workers", "6", "--processor-timeout", "15m", "--distribution", "local", "--output", filepath.Join(dir, "import-result.json"), "--report", filepath.Join(dir, "import-report.json")}
		if sandbox := os.Getenv("LAUNCHER_FACTORY_SANDBOX"); sandbox == "required" {
			args = append(args, "--processor-sandbox", "required")
		}
		if java := os.Getenv("LAUNCHER_FACTORY_JAVA"); filepath.IsAbs(java) {
			args = append(args, "--java", java)
		}
	}
	if err = factoryInvoke02710(ctx, binary, dir, log, args...); err == nil {
		job.State = "verifying"
		_ = factorySave02710(dir, job)
		err = factoryInvoke02710(ctx, binary, dir, log, "runtime", "client-factory", "verify", "--client-dir", filepath.Join(dir, "client"), "--output", filepath.Join(dir, "verified-plan.json"))
	}
	if err == nil && job.Request.Source == "modpack" {
		// Импорт создаёт отчёт, а не план фабрики. Единственным авторитетным
		// результатом является проверенный план CLI, который должен соответствовать
		// этому рабочему пространству.
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
				err = errors.New("«импортированный набор модов» не совпадает с «закреплённая идентичность рабочей области Minecraft и загрузчика»")
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
			job.Error = "Превышено время ожидания сборки"
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
		writeError(w, 409, "Нельзя запускать Client Factory после завершения сборки рабочей области")
		return
	}
	var req factoryBuilderRequest02710
	if err = readJSON0226(w, r, 4096, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.Minecraft != ws.Settings.Minecraft.Version || req.Loader != ws.Settings.Minecraft.Loader {
		writeError(w, 409, "Запрошенные версии Minecraft и загрузчика должны соответствовать закреплённой рабочей области сборки")
		return
	}
	if ws.Settings.Minecraft.LoaderVersion != "" && req.Loader != "vanilla" && req.LoaderVersion != ws.Settings.Minecraft.LoaderVersion {
		writeError(w, 409, "Версия загрузчика отличается от закреплённой версии в рабочей области сборки")
		return
	}
	if req.Source != "" && req.Source != "minecraft" {
		writeError(w, 400, "Для модпака необходима составная загрузка (multipart)")
		return
	}
	if err = factoryValidateRequest02710(req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	entries, listErr := os.ReadDir(filepath.Join(root, "jobs"))
	if listErr != nil && !errors.Is(listErr, os.ErrNotExist) {
		writeError(w, 503, "Не удалось проверить хранилище Client Factory")
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
		writeError(w, 429, "Достигнут лимит заданий (20); удалите завершённые задания")
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		writeError(w, 503, "Не удалось создать идентификатор задания")
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
		writeError(w, 503, "Не удалось создать задание: "+err.Error())
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
		writeError(w, 404, "Задание фабрики сборок не найдено")
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
		writeError(w, 503, "Не удалось прочитать журнал выполнения")
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
	writeError(w, 409, "Рабочий процесс не запущен")
}
func (s Server) factoryDiff02710(w http.ResponseWriter, r *http.Request) {
	job, dir, _, root, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	if job.State != "completed" {
		writeError(w, 409, "Сборка не прошла проверку")
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
			writeError(w, 404, "Базовое задание не найдено")
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
		return "", errors.New("Некорректное значение: путь к артефакту")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("Небезопасное значение: путь к артефакту")
		}
	}
	full := filepath.Join(root, filepath.FromSlash(path))
	stat, err := os.Lstat(full)
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() {
		return "", errors.New("Артефакт не является обычным файлом")
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
		return "", fmt.Errorf("Несовпадение: «контрольная сумма артефакта %s»", path)
	}
	return full, nil
}

// factoryPackageVerified0280 записывает временный архив до отправки ответа. Помимо проверки
// CLI, при копировании хешируйте каждый файл, чтобы не выдать частично сформированный или
// незаметно изменённый ZIP при параллельном редактировании.
func factoryPackageVerified0280(jobDir, client string, p factoryPlanView02710) (string, error) {
	const maxExportBytes int64 = 8 << 30
	paths := make([]string, 0, len(p.Outputs)+1)
	expected := map[string]struct {
		digest string
		size   int64
	}{}
	var total int64
	for _, f := range p.Outputs {
		if f.Size < 0 || f.Size > maxExportBytes-total || len(f.SHA256) != 64 {
			return "", errors.New("Экспорт превышает проверенный лимит размера или содержит недопустимый файл")
		}
		if _, exists := expected[f.Path]; exists {
			return "", errors.New("Обнаружен дубликат: «запись экспорта»")
		}
		expected[f.Path] = struct {
			digest string
			size   int64
		}{f.SHA256, f.Size}
		paths = append(paths, f.Path)
		total += f.Size
	}
	paths = append(paths, ".launcher/install-plan.json")
	sort.Strings(paths)
	archiveFile, err := os.CreateTemp(jobDir, "client-export-*.zip")
	if err != nil {
		return "", err
	}
	name := archiveFile.Name()
	success := false
	defer func() {
		_ = archiveFile.Close()
		if !success {
			_ = os.Remove(name)
		}
	}()
	archive := zip.NewWriter(archiveFile)
	for _, path := range paths {
		// Ни файл, ни один каталог на пути к нему не могут быть символическими
		// ссылками.
		if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
			return "", errors.New("Небезопасное значение: путь вывода")
		}
		full := client
		for _, part := range strings.Split(path, "/") {
			if part == "" || part == "." || part == ".." {
				return "", errors.New("Небезопасное значение: «выходной компонент»")
			}
			full = filepath.Join(full, part)
			st, e := os.Lstat(full)
			if e != nil {
				return "", e
			}
			if st.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("В дереве результатов обнаружена символьная ссылка")
			}
		}
		file, e := os.Open(full)
		if e != nil {
			return "", e
		}
		stat, e := file.Stat()
		if e != nil || !stat.Mode().IsRegular() {
			file.Close()
			return "", errors.New("Выходной объект не является обычным файлом")
		}
		if exp, ok := expected[path]; ok && stat.Size() != exp.size {
			file.Close()
			return "", errors.New("Обнаружено изменение: «размер экспортируемого файла»")
		}
		if path == ".launcher/install-plan.json" && (stat.Size() > 8<<20 || total+stat.Size() > maxExportBytes) {
			file.Close()
			return "", errors.New("Превышен допустимый размер: InstallPlan")
		}
		entry, e := archive.Create(path)
		if e != nil {
			file.Close()
			return "", e
		}
		digest := sha256.New()
		copyDest := io.MultiWriter(entry, digest)
		var planCopy bytes.Buffer
		expectedFile, tracked := expected[path]
		if !tracked {
			copyDest = io.MultiWriter(entry, digest, &planCopy)
		}
		var copied int64
		if tracked {
			copied, e = io.CopyN(copyDest, file, expectedFile.size)
			if e == nil {
				var extra [1]byte
				n, peekErr := file.Read(extra[:])
				if n != 0 || (peekErr != nil && peekErr != io.EOF) {
					e = errors.New("Экспортируемый файл увеличился во время упаковки")
				}
			}
		} else {
			copied, e = io.Copy(copyDest, io.LimitReader(file, 8<<20+1))
			if e == nil && copied > 8<<20 {
				e = errors.New("InstallPlan превысил ограничение размера при копировании")
			}
		}
		closeErr := file.Close()
		if e != nil {
			return "", e
		}
		if closeErr != nil {
			return "", closeErr
		}
		if tracked && (copied != expectedFile.size || hex.EncodeToString(digest.Sum(nil)) != expectedFile.digest) {
			return "", errors.New("Содержимое экспорта изменилось во время упаковки")
		}
		if !tracked {
			var locked struct {
				ReproducibilitySHA256 string `json:"reproducibilitySha256"`
			}
			if json.Unmarshal(planCopy.Bytes(), &locked) != nil || locked.ReproducibilitySHA256 != p.ReproducibilitySHA256 {
				return "", errors.New("Идентификатор InstallPlan изменился при копировании")
			}
		}
	}
	if err = archive.Close(); err != nil {
		return "", err
	}
	if err = archiveFile.Sync(); err != nil {
		return "", err
	}
	if err = archiveFile.Close(); err != nil {
		return "", err
	}
	success = true
	return name, nil
}
func (s Server) factoryExport02710(w http.ResponseWriter, r *http.Request) {
	job, dir, binary, _, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	if job.State != "completed" {
		writeError(w, 409, "Экспортировать можно только проверенные задания")
		return
	}
	p, err := factoryLoadPlan02710(dir)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	client := filepath.Join(dir, "client")
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	verifiedPath := filepath.Join(dir, "export-verification.json")
	if err = factoryInvoke02710(ctx, binary, dir, io.Discard, "runtime", "client-factory", "verify", "--client-dir", client, "--output", verifiedPath); err != nil {
		writeError(w, 409, "Проверка целостности Runtime завершилась ошибкой")
		return
	}
	verified, err := os.ReadFile(verifiedPath)
	if err != nil {
		writeError(w, 409, "Не удалось проверить подтверждённый план")
		return
	}
	var result factoryPlanView02710
	if json.Unmarshal(verified, &result) != nil || result.ReproducibilitySHA256 != p.ReproducibilitySHA256 {
		writeError(w, 409, "InstallPlan изменился после проверки задания")
		return
	}
	zipPath, err := factoryPackageVerified0280(dir, client, result)
	if err != nil {
		writeError(w, 409, "Не удалось проверить целостность или упаковать экспорт: "+err.Error())
		return
	}
	defer os.Remove(zipPath)
	file, err := os.Open(zipPath)
	if err != nil {
		writeError(w, 503, "Не удалось открыть проверенный экспорт")
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		writeError(w, 503, "Не удалось получить сведения о проверенном экспорте")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=launcher-client-%s.zip", job.ID))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Launcher-Distribution", "local-only; publication requires permission gates and signed runtime certification")
	http.ServeContent(w, r, "client.zip", stat.ModTime(), file)
	s.audit(r, job.OwnerID, "client-factory:export", job.ID)
}

// Перечисляет сохранённые задачи после обновления страницы или перезапуска API.
// Список каталогов не раскрывается: видны только задачи этого оператора и
// рабочего пространства.
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

// Удалять можно только неактивные задачи. Очистка освобождает большие деревья
// клиентов и позволяет соблюдать квоты без удаления результатов выполняющихся
// заданий.
func (s Server) factoryDelete02710(w http.ResponseWriter, r *http.Request) {
	job, dir, _, _, ok := s.factoryOwnedJob02710(w, r)
	if !ok {
		return
	}
	if _, running := factoryProcesses02710.Load(job.ID); running || !endedFactoryJob02710(job.State) {
		writeError(w, 409, "Перед удалением результата отмените работу процесса и дождитесь его завершения")
		return
	}
	if job.State == "interrupted" {
		writeError(w, 409, "Прерванный рабочий процесс требует очистки администратором")
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		writeError(w, 503, "Не удалось удалить завершённую сборку")
		return
	}
	s.audit(r, job.OwnerID, "client-factory:delete", job.ID)
	factoryResult02710(w, map[string]string{"deleted": job.ID})
}
func endedFactoryJob02710(state string) bool {
	return state == "completed" || state == "failed" || state == "cancelled" || state == "interrupted"
}

// Принимайте архив с жёстким ограничением размера; настоящий CLI разбирает и
// проверяет содержимое ZIP CurseForge/Modrinth. Загрузка никогда не доверяет
// путям файлов из браузера.
func (s Server) factoryModpackCreate02710(w http.ResponseWriter, r *http.Request) {
	_, ws, ok := s.ownedWorkspace0226(w, r, "release:prepare")
	if !ok {
		return
	}
	if ws.State == "built" {
		writeError(w, 409, "Рабочая область не допускает изменений")
		return
	}
	binary, root, err := factoryConfig02710()
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
	if err = r.ParseMultipartForm(8 << 20); err != nil {
		writeError(w, 413, "Некорректный или слишком большой архив модпака")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "Требуется архив модпака")
		return
	}
	defer file.Close()
	extension := strings.ToLower(filepath.Ext(header.Filename))
	if extension != ".mrpack" && extension != ".zip" {
		writeError(w, 400, "Поддерживаются только .mrpack или ZIP CurseForge")
		return
	}
	req := factoryBuilderRequest02710{Minecraft: ws.Settings.Minecraft.Version, Loader: ws.Settings.Minecraft.Loader, LoaderVersion: ws.Settings.Minecraft.LoaderVersion, Target: r.FormValue("target"), Source: "modpack"}
	// Импортируемые наборы определяют точный загрузчик по архиву. Закреплённое
	// рабочее пространство без версии загрузчика допустимо и проверяется после
	// установки.
	if req.Loader != "vanilla" && req.LoaderVersion == "" { // здесь проверяются только целевой объект и закреплённые версии Minecraft/загрузчика
		if !factoryMinecraft02710.MatchString(req.Minecraft) || factoryMutableSelector02710(req.Minecraft) {
			writeError(w, 409, "Версия Minecraft в рабочей области должна быть указана точно")
			return
		}
		if req.Target != "linux/x86_64" && req.Target != "windows/x86_64" && req.Target != "windows/x86" && req.Target != "linux/aarch64" && req.Target != "darwin/x86_64" && req.Target != "darwin/aarch64" {
			writeError(w, 400, "Неподдерживаемая целевая платформа")
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
		writeError(w, 429, "Достигнут лимит заданий")
		return
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		writeError(w, 503, "Не удалось выделить задание")
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
		writeError(w, 503, "Не удалось сохранить загруженный модпак")
		return
	}
	var size int64
	size, e = io.Copy(dst, io.LimitReader(file, 128<<20))
	_ = dst.Close()
	if e != nil || size < 4 || size >= 128<<20 {
		_ = os.RemoveAll(dir)
		writeError(w, 413, "Модпак слишком большой или некорректный")
		return
	}
	signature, e := os.Open(filepath.Join(dir, "source.zip"))
	if e != nil {
		writeError(w, 503, "Не удалось прочитать загруженный модпак")
		return
	}
	headerBytes := make([]byte, 4)
	_, e = io.ReadFull(signature, headerBytes)
	_ = signature.Close()
	if e != nil || !strings.HasPrefix(string(headerBytes), "PK") {
		_ = os.RemoveAll(dir)
		writeError(w, 400, "Некорректная сигнатура ZIP")
		return
	}
	if err = factorySave02710(dir, job); err != nil {
		_ = os.RemoveAll(dir)
		writeError(w, 503, "Не удалось сохранить задание модпака")
		return
	}
	s.audit(r, ws.OwnerID, "client-factory:modpack-import", ws.ID+":"+job.ID)
	go factoryRun02710(binary, root, job)
	factoryResult02710(w, job)
}
