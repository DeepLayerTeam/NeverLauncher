// Package gravitdetector анализирует недоверенный ZIP установки Gravit без распаковки на
// диск, интерпретации class-файлов, выполнения JAR или вывода секретов.
package gravitdetector

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

const MaxArchiveBytes = inv.MaxSourceBytes
const maxConfigBytes = uint64(inv.MaxConfigBytes)
const maxJarBytes = 256 << 20

var versionPattern = regexp.MustCompile(`(?:^|[^0-9])(?:v)?(5\.[0-9]{1,2}\.[0-9]{1,3})(?:[^0-9]|$)`)

type Finding struct {
	Code      string `json:"code"`
	Severity  string `json:"severity"` // info | manual | blocked
	Component string `json:"component"`
	Path      string `json:"path,omitempty"`
	Message   string `json:"message"`
}
type Component struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Status string `json:"status"` // recognized | manual | blocked
	Type   string `json:"type,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}
type Report struct {
	Format           string         `json:"format"`
	SourceSHA256     string         `json:"sourceSha256"`
	SourceBytes      int64          `json:"sourceBytes"`
	FilesSHA256      string         `json:"filesSha256"`
	Categories       map[string]int `json:"categories"`
	SourceTotalBytes int64          `json:"sourceTotalBytes"`
	ServerJarSHA256  string         `json:"serverJarSha256,omitempty"`
	SourceEntries    int            `json:"sourceEntries"`
	ClaimedVersion   string         `json:"claimedVersion,omitempty"`
	DetectedVersion  string         `json:"detectedVersion,omitempty"`
	VersionEvidence  string         `json:"versionEvidence"` // проверка подписанного происхождения исходного проекта не входит в область этой операции
	VersionStatus    string         `json:"versionStatus"`   // recognized | unverified | unsupported | conflict
	Status           string         `json:"status"`          // ручной режим или блокировка; совместимость с рабочей средой не предполагается автоматически
	CutoverAllowed   bool           `json:"cutoverAllowed"`
	Components       []Component    `json:"components"`
	Findings         []Finding      `json:"findings"`
	Summary          map[string]int `json:"summary"`
}

func (r *Report) finding(code, severity, kind, file, message string) {
	r.Findings = append(r.Findings, Finding{code, severity, kind, file, message})
}
func recognizedVersion(v string) bool {
	m := versionPattern.FindStringSubmatch(v)
	if len(m) != 2 || strings.TrimPrefix(v, "v") != m[1] {
		return false
	}
	p := strings.Split(m[1], ".")
	patch, e := strconv.Atoi(p[2])
	return e == nil && p[0] == "5" && p[1] == "7" && patch <= 13
}

// Assess сохранён для внутрипроцессных вызовов с уже буферизованным архивом.
// Промышленные HTTP-загрузки используют AssessReader, чтобы не буферизовать
// большие модпаки.
func Assess(source []byte, claimedVersion string) (Report, error) {
	hash := sha256.Sum256(source)
	return AssessReader(context.Background(), bytes.NewReader(source), int64(len(source)), hex.EncodeToString(hash[:]), claimedVersion)
}

// AssessReader проверяет тот же формат ZIP и ограничения, что и полная
// инвентаризация источника. Он сверяет SHA-256 вызывающей стороны, CRC и пути всех
// элементов до разбора конфигураций и никогда не выполняет переданные JAR.
func AssessReader(ctx context.Context, src io.ReaderAt, size int64, digest, claimedVersion string) (Report, error) {
	if len(claimedVersion) > 40 || strings.ContainsAny(claimedVersion, "\n\r\t") {
		return Report{}, errors.New("Некорректное значение: «claimed Gravit version»")
	}
	snapshot, err := inv.ValidateSource(ctx, src, size, digest)
	if err != nil {
		return Report{}, fmt.Errorf("Некорректное значение: исходный ZIP-архив Gravit: %w", err)
	}
	fileList, err := json.Marshal(snapshot.Files)
	if err != nil {
		return Report{}, err
	}
	fileDigest := sha256.Sum256(fileList)
	r := Report{Format: "launcher.gravit-compatibility.v1", SourceSHA256: snapshot.SourceSHA256, SourceBytes: snapshot.SourceBytes, SourceTotalBytes: snapshot.TotalBytes, FilesSHA256: hex.EncodeToString(fileDigest[:]), Categories: snapshot.Categories, ClaimedVersion: strings.TrimSpace(claimedVersion), VersionEvidence: "absent", VersionStatus: "unverified", Status: "manual", Components: []Component{}, Findings: []Finding{}, Summary: map[string]int{}}
	z, err := zip.NewReader(src, size)
	if err != nil {
		return Report{}, err
	}
	files := make([]*zip.File, 0, len(z.File))
	for _, f := range z.File {
		if !f.FileInfo().IsDir() {
			files = append(files, f)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	fileHashes := make(map[string]string, len(snapshot.Files))
	for _, f := range snapshot.Files {
		fileHashes[f.Path] = f.SHA256
	}
	r.SourceEntries = len(files)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	foundLaunch := false
	launchConfigs := 0
	runtimeConfigs := 0
	profileCount := 0
	foundRuntime := false
	var manifestVersions []string
	serverJars := 0
	for _, f := range files {
		n := strings.ReplaceAll(f.Name, "\\", "/")
		lower := strings.ToLower(n)
		base := strings.ToLower(path.Base(n))
		switch {
		case base == "launchserver.json":
			foundLaunch = true
			launchConfigs++
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("launchserver", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "launchserver", Path: n, Status: "recognized", Type: "json"})
			r.inspectLaunch(n, obj)
		case strings.HasSuffix(lower, "/profiles/") || (strings.Contains(lower, "/profiles/") && strings.HasSuffix(lower, ".json")) || strings.HasPrefix(lower, "profiles/") && strings.HasSuffix(lower, ".json"):
			profileCount++
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("client_profile", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "client_profile", Path: n, Status: "recognized", Type: "json"})
			r.inspectProfile(n, obj)
		case base == "launchserverruntime.json" || base == "launchserverruntimeconfig.json":
			foundRuntime = true
			runtimeConfigs++
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("runtime", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "runtime", Path: n, Status: "recognized", Type: "json"})
			r.inspectRuntime(n, obj)
		case (strings.Contains(lower, "/runtime/") || strings.HasPrefix(lower, "runtime/")) && strings.HasSuffix(lower, ".json"):
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("runtime_settings", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "runtime_settings", Path: n, Status: "manual", Type: "json"})
			r.inspectRuntime(n, obj)
		case strings.Contains(lower, "/modules/") && strings.HasSuffix(lower, ".jar") || strings.HasPrefix(lower, "modules/") && strings.HasSuffix(lower, ".jar"):
			r.Components = append(r.Components, Component{Kind: "module", Path: n, Status: "manual", Type: "jar"})
			r.finding("MODULE_REVIEW_REQUIRED", "manual", "module", n, "Пользовательский модуль требует анализа поведения; JAR при этом не запускается")
		case (base == ".env" || strings.HasSuffix(lower, "/serverwrapper.env")) && f.UncompressedSize64 <= maxConfigBytes:
			data, e := readBounded(f, maxConfigBytes)
			if e != nil {
				r.finding("WRAPPER_ENV_UNREADABLE", "blocked", "server_wrapper", n, "Не удалось прочитать окружение оболочки")
				continue
			}
			if bytes.Contains(data, []byte("SERVERWRAPPER_ADDRESS=")) || bytes.Contains(data, []byte("SERVERWRAPPER_CHECK_SERVER_TOKEN=")) {
				r.Components = append(r.Components, Component{Kind: "server_wrapper", Path: n, Status: "manual", Type: "environment"})
				r.finding("WRAPPER_REENROLL", "manual", "server_wrapper", n, "Окружение ServerWrapper содержит устаревшие настройки интеграции; секреты и ключи не импортируются")
			}
		case strings.Contains(lower, "serverwrapper/") && base == "config.json":
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("server_wrapper", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "server_wrapper", Path: n, Status: "manual", Type: "json"})
			r.inspectWrapper(n, obj)
		case base == "serverwrapper.json" || base == "serverwrapperconfig.json":
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("server_wrapper", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "server_wrapper", Path: n, Status: "manual", Type: "json"})
			r.inspectWrapper(n, obj)
		case base == "launchserver.jar":
			serverJars++
			r.ServerJarSHA256 = fileHashes[n]
			if f.UncompressedSize64 > maxJarBytes {
				r.finding("SERVER_JAR_TOO_LARGE", "blocked", "version", n, "server JAR exceeds 256 MiB bounded manifest inspection limit")
				continue
			}
			version, ok, e := jarManifestVersionFile(ctx, f)
			if e != nil {
				r.finding("SERVER_JAR_INVALID", "blocked", "version", n, "Не удалось проверить или изучить серверный JAR")
				continue
			}
			if ok {
				manifestVersions = append(manifestVersions, version)
			} else {
				r.finding("SERVER_VERSION_UNREADABLE", "manual", "version", n, "Нельзя определить релиз Gravit по манифесту серверного JAR")
			}
		case strings.HasSuffix(lower, ".json") && (strings.Contains(lower, "/modules/") || strings.HasPrefix(lower, "modules/")):
			if _, e := readObject(f); e != nil {
				r.addInvalid("module_config", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "module_config", Path: n, Status: "manual", Type: "json"})
			r.finding("MODULE_CONFIG_REVIEW", "manual", "module_config", n, "module-specific settings require manual compatibility review")
		}
	}
	if serverJars > 1 {
		r.finding("MULTIPLE_SERVER_JARS", "blocked", "version", "", "multiple LaunchServer.jar entries make binary provenance ambiguous")
	}
	if launchConfigs > 1 {
		r.finding("MULTIPLE_LAUNCHSERVERS", "blocked", "launchserver", "", "multiple LaunchServer.json configs make source identity ambiguous")
	}
	if runtimeConfigs > 1 {
		r.finding("MULTIPLE_RUNTIMES", "blocked", "runtime", "", "multiple runtime configs make source identity ambiguous")
	}
	if !foundLaunch {
		r.finding("LAUNCHSERVER_MISSING", "blocked", "launchserver", "", "Необходим файл LaunchServer.json")
	}
	if profileCount == 0 {
		r.finding("PROFILES_MISSING", "manual", "client_profile", "", "В каталоге profiles/ не найден JSON-файл ClientProfile")
	}
	if !foundRuntime {
		r.finding("RUNTIME_MISSING", "manual", "runtime", "", "Файл LaunchServerRuntime.json не найден; проверьте настройки среды выполнения отдельно")
	}
	// Для настоящей миграции отдельно обязательны содержимое и идентичность.
	// Отсутствие не считается успехом: внешняя авторизация и удалённые
	// Vanilla-ресурсы могут быть законными, но требуют явного решения оператора.
	if snapshot.Categories["client"] == 0 {
		r.finding("CLIENT_FILES_NOT_IN_SOURCE", "manual", "client", "", "В архиве нет файлов clients/updates; необходимо отдельно учесть внешнее содержимое клиента")
	}
	if snapshot.Categories["asset"] == 0 || snapshot.Categories["library"] == 0 {
		r.finding("SHARED_CONTENT_NOT_IN_SOURCE", "manual", "content", "", "Отсутствуют ресурсы или библиотеки; проверьте внешние зеркала и зависимости")
	}
	if snapshot.Categories["authentication"] == 0 {
		r.finding("AUTH_EXPORT_NOT_IN_SOURCE", "manual", "auth", "", "База учётных записей может быть внешней; экспорт и сопоставление UUID выполняются отдельно")
	}
	if snapshot.Categories["texture"] == 0 {
		r.finding("TEXTURE_FILES_NOT_IN_SOURCE", "manual", "texture", "", "Данные текстур отсутствуют; проверьте внешний TextureProvider или подтвердите намеренно пустой источник")
	}
	if len(manifestVersions) > 0 {
		v := manifestVersions[0]
		consistent := true
		for _, next := range manifestVersions {
			if next != v {
				consistent = false
			}
		}
		r.DetectedVersion = v
		r.VersionEvidence = "jar-manifest"
		r.finding("BINARY_PROVENANCE_NOT_ATTESTED", "manual", "version", "", "Манифест JAR не подтверждает подписанное происхождение; сравните serverJarSha256 с утверждённым артефактом релиза")
		if !consistent || (r.ClaimedVersion != "" && strings.TrimPrefix(r.ClaimedVersion, "v") != v) {
			r.VersionStatus = "conflict"
			r.finding("VERSION_CONFLICT", "blocked", "version", "", "Версия Gravit в источнике не совпадает с объявленной версией")
		} else if recognizedVersion(v) {
			r.VersionStatus = "recognized"
		} else {
			r.VersionStatus = "unsupported"
			r.finding("VERSION_UNSUPPORTED", "blocked", "version", "", "Обнаруженная версия сервера находится вне поддерживаемого диапазона 5.7.0–5.7.13")
		}
	} else if r.ClaimedVersion != "" {
		r.VersionEvidence = "operator-claim"
		r.finding("VERSION_NOT_VERIFIED", "manual", "version", "", "Указанная оператором версия не подтверждает идентичность исходного исполняемого файла")
		if !recognizedVersion(strings.TrimPrefix(r.ClaimedVersion, "v")) {
			r.VersionStatus = "unsupported"
			r.finding("VERSION_UNSUPPORTED", "blocked", "version", "", "Заявленная версия находится вне поддерживаемого диапазона 5.7.0–5.7.13")
		}
	} else {
		r.finding("VERSION_NOT_VERIFIED", "manual", "version", "", "Не удалось подтвердить версию сервера; укажите LaunchServer.jar из той же установки")
	}
	r.Summary = map[string]int{"recognized": 0, "manual": 0, "blocked": 0}
	for _, c := range r.Components {
		r.Summary[c.Status]++
	}
	for _, f := range r.Findings {
		r.Summary[f.Severity]++
		if f.Severity == "blocked" {
			r.Status = "blocked"
		}
	}
	// Этот сканер НИКОГДА не разрешает переключение: эквивалентность идентичностей,
	// мира и модулей сертифицируют отдельные этапы миграции в последующих выпусках.
	r.CutoverAllowed = false
	return r, nil
}
func (r *Report) addInvalid(kind, p string, e error) {
	r.Components = append(r.Components, Component{Kind: kind, Path: p, Status: "blocked"})
	r.finding("INVALID_JSON", "blocked", kind, p, e.Error())
}
func readBounded(f *zip.File, limit uint64) ([]byte, error) {
	if f.UncompressedSize64 > limit {
		return nil, errors.New("Размер файла превышает ограничение проверки")
	}
	rd, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer rd.Close()
	b, e := io.ReadAll(io.LimitReader(rd, int64(limit)+1))
	if e != nil {
		return nil, e
	}
	if uint64(len(b)) != f.UncompressedSize64 || uint64(len(b)) > limit {
		return nil, errors.New("Элемент ZIP обрезан или превышает допустимый размер")
	}
	return b, nil
}
func readObject(f *zip.File) (map[string]json.RawMessage, error) {
	b, e := readBounded(f, maxConfigBytes)
	if e == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		if err := rejectDuplicateJSON0332(dec); err != nil {
			return nil, err
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return nil, errors.New("Обнаружено несколько значений JSON")
		}
	}
	if e != nil {
		return nil, e
	}
	var v map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if e = dec.Decode(&v); e != nil {
		return nil, errors.New("Некорректное значение: объект JSON")
	}
	if v == nil {
		return nil, errors.New("JSON root: требуется объект")
	}
	var trailing any
	if e = dec.Decode(&trailing); e != io.EOF {
		return nil, errors.New("Обнаружено несколько значений JSON")
	}
	return v, nil
}
func rawObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var v map[string]json.RawMessage
	return v, json.Unmarshal(raw, &v) == nil && v != nil
}
func readType(obj map[string]json.RawMessage) string {
	var s string
	_ = json.Unmarshal(obj["type"], &s)
	return strings.ToLower(strings.TrimSpace(s))
}
func (r *Report) inspectLaunch(p string, obj map[string]json.RawMessage) {
	auth, ok := rawObject(obj["auth"])
	if !ok || len(auth) == 0 {
		r.finding("AUTH_INVALID", "blocked", "launchserver", p, "Провайдеры авторизации отсутствуют или заданы не в виде карты")
	} else {
		keys := make([]string, 0, len(auth))
		for k := range auth {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		defaults := 0
		for _, name := range keys {
			pair, valid := rawObject(auth[name])
			if !valid {
				r.finding("AUTH_ENTRY_INVALID", "blocked", "auth", p, "auth provider record must be an object")
				continue
			}
			var isDefault bool
			_ = json.Unmarshal(pair["isDefault"], &isDefault)
			if isDefault {
				defaults++
			}
			core, valid := rawObject(pair["core"])
			if !valid {
				r.finding("AUTH_CORE_MISSING", "blocked", "auth", p, "auth provider core is missing")
				continue
			}
			typ := readType(core)
			switch typ {
			case "sql", "mysql", "postgresql", "postgres", "file", "fileauthsystem", "memory", "reject", "null", "merge", "minecraft", "microsoft":
				r.finding("AUTH_REQUIRES_MAPPING", "manual", "auth", p, "auth core "+typ+" requires a dedicated credential and UUID migration review")
			case "":
				r.finding("AUTH_TYPE_MISSING", "blocked", "auth", p, "auth core type is required")
			default:
				r.finding("UNKNOWN_AUTH_PROVIDER", "blocked", "auth", p, "unknown auth core type (name and secret values are never recorded)")
			}
			if t, exists := pair["textureProvider"]; exists {
				provider, valid := rawObject(t)
				if !valid {
					r.finding("TEXTURE_INVALID", "blocked", "texture", p, "Провайдер текстур должен быть объектом")
				} else if kind := readType(provider); kind == "" {
					r.finding("TEXTURE_TYPE_MISSING", "blocked", "texture", p, "Не указан тип провайдера текстур")
				} else if kind != "void" && kind != "request" && kind != "json" && kind != "database" && kind != "local" && kind != "none" && kind != "mojang" {
					r.finding("TEXTURE_UNKNOWN", "manual", "texture", p, "Для провайдера текстур требуется адаптер совместимости")
				}
			}
		}
		if defaults != 1 {
			r.finding("AUTH_DEFAULT_AMBIGUOUS", "blocked", "auth", p, "exactly one default authentication provider is required")
		}
	}
	for _, key := range []string{"protectHandler", "permissionsHandler", "hwidHandler", "components", "netty"} {
		if raw, ok := obj[key]; ok {
			if m, valid := rawObject(raw); !valid {
				r.finding("LAUNCHSERVER_OBJECT_INVALID", "blocked", "launchserver", p, key+" must be an object")
			} else if key == "protectHandler" || key == "permissionsHandler" || key == "hwidHandler" {
				if typ := readType(m); typ != "" && typ != "none" && typ != "void" {
					r.finding("SECURITY_REVIEW", "manual", "launchserver", p, key+" handler requires manual security review")
				}
			}
		}
	}
	for _, key := range []string{"authProvider", "authHandler", "textureProvider"} {
		if _, ok := obj[key]; ok {
			r.finding("LEGACY_AUTH_SCHEMA", "blocked", "launchserver", p, "legacy auth schema detected: "+key)
		}
	}
}
func (r *Report) inspectProfile(p string, obj map[string]json.RawMessage) {
	for _, k := range []string{"title", "version", "mainClass"} {
		var s string
		if e := json.Unmarshal(obj[k], &s); e != nil || s == "" {
			r.finding("PROFILE_FIELD_INVALID", "blocked", "client_profile", p, "missing/invalid profile field: "+k)
		}
	}
	for _, k := range []string{"classPath", "jvmArgs", "clientArgs", "update", "updateVerify", "updateExclusions"} {
		if v, exists := obj[k]; exists {
			if uint64(len(v)) > maxConfigBytes {
				r.finding("PROFILE_FIELD_TOO_LARGE", "blocked", "client_profile", p, k+" exceeds inspection limit")
			}
		}
	}
	for _, key := range []string{"updateOptional", "optional", "optionals", "optionalFiles", "optionalActions"} {
		if raw, ok := obj[key]; ok && string(raw) != "null" {
			r.inspectOptional(p, key, raw)
		}
	}
	if _, ok := obj["servers"]; ok {
		r.finding("PROFILE_SERVERS_REVIEW", "manual", "client_profile", p, "server entries require target connectivity verification")
	}
}
func (r *Report) inspectRuntime(p string, obj map[string]json.RawMessage) {
	if len(obj) == 0 {
		r.finding("EMPTY_RUNTIME", "manual", "runtime", p, "Конфигурация среды выполнения пуста")
	}
	for _, k := range []string{"secretKey", "accessToken", "refreshToken", "privateKey"} {
		if _, found := obj[k]; found {
			r.finding("RUNTIME_CREDENTIALS", "manual", "runtime", p, "Материалы доверия среды выполнения не импортируются")
		}
	}
}
func (r *Report) inspectWrapper(p string, obj map[string]json.RawMessage) {
	if len(obj) == 0 {
		r.finding("WRAPPER_EMPTY", "manual", "server_wrapper", p, "empty wrapper config")
	}
	r.finding("WRAPPER_REENROLL", "manual", "server_wrapper", p, "Учётные данные и корневые ключи доверия ServerWrapper необходимо заменить средствами Never ServerBridge")
}

// jarManifestVersionFile сбрасывает ограниченный вложенный JAR в закрытый файл на
// диске. Исходный ZIP может содержать серверный JAR более 100 МиБ, и буферизация
// внутри HTTP-worker усилила бы расход памяти при параллельных загрузках.
func jarManifestVersionFile(ctx context.Context, entry *zip.File) (string, bool, error) {
	if entry.UncompressedSize64 > maxJarBytes {
		return "", false, errors.New("Превышен допустимый размер: JAR")
	}
	tmp, err := os.CreateTemp("", "gravit-jar-manifest-*.tmp")
	if err != nil {
		return "", false, err
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		return "", false, err
	}
	if runtime.GOOS != "windows" {
		if err := os.Remove(tmp.Name()); err != nil && !os.IsNotExist(err) {
			return "", false, err
		}
	}
	reader, err := entry.Open()
	if err != nil {
		return "", false, err
	}
	defer reader.Close()
	written, err := io.Copy(tmp, &contextReader{ctx: ctx, r: io.LimitReader(reader, maxJarBytes+1)})
	if err != nil {
		return "", false, err
	}
	if written != int64(entry.UncompressedSize64) {
		return "", false, errors.New("Несоответствие: JAR размер")
	}
	z, err := zip.NewReader(tmp, written)
	if err != nil {
		return "", false, err
	}
	if len(z.File) > 20000 {
		return "", false, errors.New("Число элементов JAR превышает ограничение")
	}
	for _, f := range z.File {
		if strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			if f.UncompressedSize64 > 64<<10 {
				return "", false, errors.New("Превышен допустимый размер: «JAR manifest»")
			}
			data, err := readBounded(f, 64<<10)
			if err != nil {
				return "", false, err
			}
			return parseJarManifest(data)
		}
	}
	return "", false, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func parseJarManifest(data []byte) (string, bool, error) {
	t := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(t, "\n")
	var product, version string
	for _, line := range lines {
		if i := strings.IndexByte(line, ':'); i > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:i]))
			value := strings.TrimSpace(line[i+1:])
			switch key {
			case "implementation-title", "bundle-name", "implementation-vendor":
				product += " " + strings.ToLower(value)
			case "implementation-version", "bundle-version":
				if version == "" {
					version = value
				}
			}
		}
	}
	if !strings.Contains(product, "gravit") && !strings.Contains(product, "launchserver") {
		return "", false, nil
	}
	m := versionPattern.FindStringSubmatch(version)
	if len(m) != 2 {
		return "", false, nil
	}
	return m[1], true, nil
}

// inspectOptional распознаёт известные действия, но не предполагает существование
// указанных ресурсов в Never. Неизвестные действия — жёсткие блокирующие условия, не
// предупреждения.
func (r *Report) inspectOptional(p, key string, raw json.RawMessage) {
	var options []json.RawMessage
	if err := json.Unmarshal(raw, &options); err != nil || options == nil {
		r.finding("OPTIONALS_INVALID", "blocked", "client_profile", p, "Дерево дополнительных элементов должно быть массивом")
		return
	}
	if len(options) > 4096 {
		r.finding("OPTIONALS_EXCESS", "blocked", "client_profile", p, "too many optional elements")
		return
	}
	for _, entry := range options {
		option, ok := rawObject(entry)
		if !ok {
			r.finding("OPTIONAL_INVALID", "blocked", "client_profile", p, "Дополнительный элемент должен быть объектом")
			continue
		}
		actions, ok := option["actions"]
		if !ok {
			continue
		}
		var list []json.RawMessage
		if err := json.Unmarshal(actions, &list); err != nil || list == nil || len(list) > 64 {
			r.finding("OPTIONAL_ACTIONS_INVALID", "blocked", "client_profile", p, "Дополнительные действия должны быть массивом не более чем из 64 элементов")
			continue
		}
		for _, entry := range list {
			act, ok := rawObject(entry)
			if !ok {
				r.finding("OPTIONAL_ACTION_INVALID", "blocked", "client_profile", p, "Некорректный объект дополнительного действия")
				continue
			}
			switch readType(act) {
			case "file", "classpath", "jvmargs", "clientargs":
				r.finding("OPTIONAL_ACTION_REVIEW", "manual", "client_profile", p, "Известное дополнительное действие требует преобразования в подписанный файл")
			default:
				r.finding("UNKNOWN_OPTIONAL_ACTION", "blocked", "client_profile", p, "Неизвестный или отсутствующий тип дополнительного действия")
			}
		}
	}
}

// rejectDuplicateJSON0332 обходит вложенные объекты до их декодирования в карты,
// так как encoding/json обычно допускает повторяющиеся ключи с правилом
// «последний побеждает».
func rejectDuplicateJSON0332(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return errors.New("Некорректное значение: «JSON syntax»")
	}
	open, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch open {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, e := d.Token()
			if e != nil {
				return errors.New("Некорректное значение: объект JSON")
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("Некорректное значение: ключ JSON")
			}
			if seen[key] {
				return errors.New("Повторяющийся ключ JSON")
			}
			seen[key] = true
			if len(seen) > 65536 {
				return errors.New("Слишком много ключей объекта JSON")
			}
			if e = rejectDuplicateJSON0332(d); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return errors.New("Объект JSON не закрыт")
		}
	case '[':
		i := 0
		for d.More() {
			if i > 100000 {
				return errors.New("Слишком много элементов массива")
			}
			if err := rejectDuplicateJSON0332(d); err != nil {
				return err
			}
			i++
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return errors.New("Массив JSON не закрыт")
		}
	default:
		return errors.New("Некорректное значение: разделитель JSON")
	}
	return nil
}
