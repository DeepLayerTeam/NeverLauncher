package httpapi

// Отчёты игроков в поддержку намеренно компактны и машиночитаемы. Произвольные
// журналы, пути, URL, имена пользователей и учётные данные не принимаются.
import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type playerSupportEvent03510 struct {
	Code  string `json:"code"`
	Count uint32 `json:"count"`
}
type playerSupportReport03510 struct {
	SchemaVersion   string                    `json:"schemaVersion"`
	LauncherVersion string                    `json:"launcherVersion"`
	GeneratedAtUnix uint64                    `json:"generatedAtUnix"`
	OS              string                    `json:"os"`
	Arch            string                    `json:"arch"`
	Stage           string                    `json:"stage"`
	Events          []playerSupportEvent03510 `json:"events"`
}
type submittedSupportReport03510 struct {
	Consent bool                     `json:"consent"`
	Report  playerSupportReport03510 `json:"report"`
}
type storedSupportReport03510 struct {
	ID         string                   `json:"id"`
	ReceivedAt string                   `json:"receivedAt"`
	Report     playerSupportReport03510 `json:"report"`
}

var allowedSupportCodes03510 = map[string]bool{"signature": true, "offline-cache": true, "download": true, "authentication": true, "integrity": true, "runtime": true, "recovery": true, "permission": true, "other-error": true, "other": true}
var allowedSupportStages03510 = map[string]bool{"idle": true, "ready": true, "installing": true, "checking": true, "running": true, "failed": true, "downloading": true, "staged": true, "verifying": true, "launching": true, "other": true}

func safeSupportVersion03510(s string) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}
func validateSupport03510(v playerSupportReport03510) error {
	if v.SchemaVersion != "1.1" || !safeSupportVersion03510(v.LauncherVersion) {
		return errors.New("Неподдерживаемая версия диагностики")
	}
	if !allowedSupportStages03510[v.Stage] || len(v.Events) > 10 {
		return errors.New("Некорректное значение: «diagnostic stage/events»")
	}
	if !map[string]bool{"windows": true, "linux": true, "macos": true, "android": true, "ios": true, "unknown": true}[v.OS] {
		return errors.New("Некорректная операционная система")
	}
	if !map[string]bool{"x86": true, "x86_64": true, "aarch64": true, "arm": true, "unknown": true}[v.Arch] {
		return errors.New("Недопустимая архитектура")
	}
	var total uint64
	seen := map[string]bool{}
	for _, e := range v.Events {
		if !allowedSupportCodes03510[e.Code] || e.Count == 0 || e.Count > 80 || seen[e.Code] {
			return errors.New("Некорректная классификация события")
		}
		seen[e.Code] = true
		total += uint64(e.Count)
	}
	if total > 80 {
		return errors.New("Слишком много диагностических событий")
	}
	if v.GeneratedAtUnix == 0 {
		return errors.New("Отсутствует время диагностического события")
	}
	return nil
}
func (s Server) supportReportsDir03510() string {
	return filepath.Join(s.operationsBackupRoot880(), "support-reports")
}
func readSupportReport03510(path string) (storedSupportReport03510, error) {
	var report storedSupportReport03510
	file, e := os.Open(path)
	if e != nil {
		return report, e
	}
	defer file.Close()
	e = json.NewDecoder(io.LimitReader(file, 16385)).Decode(&report)
	if e != nil {
		return report, e
	}
	return report, validateSupport03510(report.Report)
}
func (s Server) playerSupportSubmit03510(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	defer r.Body.Close()
	var submitted submittedSupportReport03510
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if e := dec.Decode(&submitted); e != nil || !submitted.Consent {
		writeError(w, http.StatusBadRequest, "Необходимо явное согласие и корректные диагностические данные")
		return
	}
	var extra any
	if e := dec.Decode(&extra); e != io.EOF {
		writeError(w, http.StatusBadRequest, "Неожиданные данные после диагностического содержимого")
		return
	}
	if e := validateSupport03510(submitted.Report); e != nil {
		writeError(w, http.StatusBadRequest, "Неподдерживаемые или небезопасные диагностические данные")
		return
	}
	dir := s.supportReportsDir03510()
	if e := os.MkdirAll(dir, 0700); e != nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище обращений поддержки недоступно")
		return
	}
	if meta, e := os.Lstat(dir); e != nil || !meta.IsDir() || meta.Mode()&os.ModeSymlink != 0 {
		writeError(w, http.StatusServiceUnavailable, "Хранилище обращений поддержки недоступно")
		return
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) >= 1000 {
		writeError(w, http.StatusServiceUnavailable, "Исчерпана ёмкость хранилища обращений в поддержку")
		return
	}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		writeError(w, http.StatusServiceUnavailable, "Не удалось выделить идентификатор обращения в поддержку")
		return
	}
	id := hex.EncodeToString(random[:])
	report := storedSupportReport03510{ID: id, ReceivedAt: time.Now().UTC().Format(time.RFC3339), Report: submitted.Report}
	data, e := json.Marshal(report)
	if e != nil {
		writeError(w, http.StatusInternalServerError, "Сериализация обращения в поддержку недоступна")
		return
	}
	file, e := os.CreateTemp(dir, ".support-*")
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище обращений поддержки недоступно")
		return
	}
	temp := file.Name()
	defer os.Remove(temp)
	if e = file.Chmod(0600); e == nil {
		_, e = file.Write(data)
	}
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(temp, filepath.Join(dir, id+".json"))
	}
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище обращений поддержки недоступно")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "received", "message": "Отчёт отправлен с явного согласия пользователя"})
}
func (s Server) operatorSupportList03510(w http.ResponseWriter, r *http.Request) {
	entries, e := os.ReadDir(s.supportReportsDir03510())
	if os.IsNotExist(e) {
		writeJSON(w, http.StatusOK, map[string]any{"items": []storedSupportReport03510{}})
		return
	}
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "Хранилище обращений поддержки недоступно")
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
	items := make([]storedSupportReport03510, 0)
	for _, entry := range entries {
		if len(items) >= 100 {
			break
		}
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") || len(name) != 37 {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
			continue
		}
		item, e := readSupportReport03510(filepath.Join(s.supportReportsDir03510(), name))
		if e == nil && item.ID == id {
			items = append(items, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
