// Package gravitmodules статически проверяет закреплённые исходником модули
// Gravit и настройки ServerWrapper. Он НИКОГДА не загружает, не связывает и не
// выполняет недоверенный код.
package gravitmodules

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
	"sort"
	"strings"
	"unicode/utf8"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

const Format = "launcher.gravit-modules.v1"
const maxJar int64 = 32 << 20
const maxJarEntries = 12000
const maxJarExpanded uint64 = 128 << 20
const maxWrapper int64 = 2 << 20

type Module struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Name           string `json:"name"`
	Implementation string `json:"implementation"` // built_in_equivalent | compatible_adapter | source_port | blocker
	Status         string `json:"status"`         // manual | blocked
	Reason         string `json:"reason"`
	LaunchHook     bool   `json:"launchHook"`
	AuthHook       bool   `json:"authHook"`
	SourcesPresent bool   `json:"sourcesPresent"`
}
type Wrapper struct {
	Path                 string `json:"path"`
	SHA256               string `json:"sha256"`
	Mode                 string `json:"mode"` // inline | config | environment
	ServerName           string `json:"serverName,omitempty"`
	LegacyAddressPresent bool   `json:"legacyAddressPresent"`
	LegacyTokenPresent   bool   `json:"legacyTokenPresent"`
	Replacement          string `json:"replacement"`
	Status               string `json:"status"` // manual | blocked
	Reason               string `json:"reason"`
}
type Report struct {
	Format          string    `json:"format"`
	SourceSHA256    string    `json:"sourceSha256"`
	InventorySHA256 string    `json:"inventorySha256"`
	Modules         []Module  `json:"modules"`
	Wrappers        []Wrapper `json:"wrappers"`
	Blockers        []string  `json:"blockers"`
	Ready           bool      `json:"ready"`
	CutoverAllowed  bool      `json:"cutoverAllowed"` // никогда не определяется только по статическому анализу
}

func safePath(p string) bool {
	return p != "" && len(p) <= 2048 && !strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\:\x00\r\n\t") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}
func readFile(ctx context.Context, f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("Файл превышает ограничение размера для статической проверки")
	}
	r, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	var b bytes.Buffer
	p := make([]byte, 64<<10)
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		n, err := r.Read(p)
		if n > 0 {
			if int64(b.Len()+n) > limit {
				return nil, errors.New("Превышен допустимый размер: «expanded file»")
			}
			b.Write(p[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if uint64(b.Len()) != f.UncompressedSize64 {
		return nil, errors.New("Запись ZIP обрезана")
	}
	return b.Bytes(), nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func jarEvidence(ctx context.Context, b []byte) (name string, auth, launch bool, err error) {
	z, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		return "", false, false, fmt.Errorf("Некорректное значение: модуль JAR: %w", e)
	}
	if len(z.File) == 0 || len(z.File) > maxJarEntries {
		return "", false, false, errors.New("Число записей JAR выходит за допустимые границы")
	}
	seen := map[string]bool{}
	var expanded uint64
	for _, f := range z.File {
		p := strings.TrimSuffix(f.Name, "/")
		if !safePath(p) || f.Mode()&os.ModeSymlink != 0 || f.Flags&1 != 0 || (f.Method != zip.Store && f.Method != zip.Deflate) {
			return "", false, false, errors.New("Небезопасное значение: запись JAR-архива")
		}
		k := strings.ToLower(p)
		if seen[k] {
			return "", false, false, errors.New("Обнаружен дубликат: запись JAR-архива")
		}
		seen[k] = true
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > maxJarExpanded-expanded {
			return "", false, false, errors.New("Распакованный JAR превышает ограничение размера")
		}
		expanded += f.UncompressedSize64
		if f.UncompressedSize64 > f.CompressedSize64*400+8192 {
			return "", false, false, errors.New("Коэффициент распаковки JAR превышает ограничение")
		}
		lower := strings.ToLower(p)
		if lower == "meta-inf/manifest.mf" {
			if f.UncompressedSize64 > 64<<10 {
				return "", false, false, errors.New("Превышен допустимый размер: манифест")
			}
			data, er := readFile(ctx, f, 64<<10)
			if er != nil {
				return "", false, false, er
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), "implementation-title:") {
					name = strings.TrimSpace(line[len("implementation-title:"):])
					if len(name) > 100 || !utf8.ValidString(name) {
						name = ""
					}
				}
			}
		}
		// Сканируйте настоящие пулы констант классов и дескрипторы служб, никогда не исполняя
		// их. Консервативный поиск подстрок может излишне блокировать, но не способен объявить
		// модуль безопасным.
		if strings.HasSuffix(lower, ".class") || strings.HasPrefix(lower, "meta-inf/services/") {
			if f.UncompressedSize64 > 4<<20 {
				return "", false, false, errors.New("Превышен допустимый размер: «class/service descriptor»")
			}
			data, er := readFile(ctx, f, 4<<20)
			if er != nil {
				return "", false, false, er
			}
			for _, s := range []string{"AuthProvider", "AuthCoreProvider", "AuthHandler", "AuthRequest", "auth.provider", "auth.core", "AuthProviderPair"} {
				if bytes.Contains(data, []byte(s)) {
					auth = true
				}
			}
			for _, s := range []string{"LaunchServer", "ClientProfile", "LaunchRequest", "LauncherEngine", "ClientLauncher", "LauncherModule", "launchserver"} {
				if bytes.Contains(data, []byte(s)) {
					launch = true
				}
			}
		}
	}
	return name, auth, launch, nil
}
func parseWrapper(raw []byte, p, sha string) Wrapper {
	w := Wrapper{Path: p, SHA256: sha, Replacement: "Never ServerBridge (new Ed25519 enrollment)", Status: "manual"}
	if strings.HasSuffix(strings.ToLower(p), ".env") || strings.EqualFold(path.Base(p), ".env") {
		w.Mode = "environment"
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "export ") {
				line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			}
			if strings.HasPrefix(line, "SERVERWRAPPER_ADDRESS=") {
				w.LegacyAddressPresent = true
			}
			if strings.HasPrefix(line, "SERVERWRAPPER_CHECK_SERVER_TOKEN=") {
				w.LegacyTokenPresent = true
			}
			if strings.Contains(line, "launcher.authlib.inlineClass=") {
				w.Mode = "inline"
			}
		}
		w.Reason = "Удалите устаревшие переменные окружения и параметры authlib; зарегистрируйте узел Never ServerBridge с новым ключом"
		return w
	}
	w.Mode = "config"
	var obj map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if e := decoder.Decode(&obj); e != nil || obj == nil {
		w.Status = "blocked"
		w.Reason = "Недопустимый JSON обёртки"
		return w
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		w.Status = "blocked"
		w.Reason = "Обнаружено несколько JSON-документов"
		return w
	}
	for _, key := range []string{"serverName", "name"} {
		if v, ok := obj[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && len(s) <= 128 && utf8.ValidString(s) {
				w.ServerName = s
				break
			}
		}
	}
	for key := range obj {
		k := strings.ToLower(key)
		if strings.Contains(k, "token") || strings.Contains(k, "secret") {
			w.LegacyTokenPresent = true
		}
		if strings.Contains(k, "address") || strings.Contains(k, "url") {
			w.LegacyAddressPresent = true
		}
	}
	w.Reason = "Устаревшую конфигурацию ServerWrapper/authlib нужно заменить новым зарегистрированным узлом ServerBridge; секреты не переносятся"
	return w
}
func legacyWrapperJar(p string) bool {
	base := strings.ToLower(path.Base(p))
	return base == "serverwrapper.jar" || base == "serverwrapperinline.jar" || strings.HasPrefix(base, "launcherauthlib") && strings.HasSuffix(base, ".jar")
}
func moduleJar(p string) bool {
	s := strings.ToLower(p)
	return strings.HasSuffix(s, ".jar") && (strings.HasPrefix(s, "modules/") || strings.Contains(s, "/modules/") || legacyWrapperJar(p))
}
func wrapperFile(p string) bool {
	s := strings.ToLower(p)
	base := path.Base(s)
	return base == "serverwrapper.json" || base == "serverwrapperconfig.json" || (strings.Contains(s, "serverwrapper/") && base == "config.json") || base == "serverwrapper.env" || base == ".env"
}

// Analyze сверяет идентичность архива и дайджесты каждого кандидата с MIG03. Байты и
// недоверенные строки вроде паролей/токенов не сохраняются.
func Analyze(ctx context.Context, file *os.File, size int64, inventory inv.Inventory) (Report, error) {
	result := Report{Format: Format, SourceSHA256: inventory.SourceSHA256, InventorySHA256: inventory.ManifestSHA256, Modules: []Module{}, Wrappers: []Wrapper{}, Blockers: []string{}}
	if _, e := inventory.Manifest(); e != nil {
		return Report{}, e
	}
	if size != inventory.SourceBytes {
		return Report{}, errors.New("Размер источника отличается от сохранённой инвентаризации")
	}
	if size < 1 || size > inv.MaxSourceBytes {
		return Report{}, errors.New("Размер источника выходит за ограничения MIG03")
	}
	// Внутренний вызывающий код тоже не может обойти закрепление целого архива.
	check := sha256.New()
	section := io.NewSectionReader(file, 0, size)
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		n, e := section.Read(buf)
		if n > 0 {
			_, _ = check.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return Report{}, e
		}
	}
	if hex.EncodeToString(check.Sum(nil)) != inventory.SourceSHA256 {
		return Report{}, errors.New("SHA-256 источника отличается от инвентаризации MIG03")
	}
	z, e := zip.NewReader(file, size)
	if e != nil {
		return Report{}, e
	}
	indexed := map[string]inv.File{}
	for _, f := range inventory.Files {
		indexed[f.Path] = f
	}
	sources := map[string]bool{}
	moduleArtifacts := map[string]bool{}
	for _, f := range z.File {
		if moduleJar(f.Name) && !legacyWrapperJar(f.Name) {
			// Наличие JAR доказывает лишь совпадение артефакта. Никогда не загружайте его
			// и не выводите функциональную совместимость из имени.
			moduleArtifacts[strings.ToLower(strings.TrimSuffix(path.Base(f.Name), path.Ext(f.Name)))] = true
		}

		if strings.HasSuffix(strings.ToLower(f.Name), ".java") {
			sources[strings.ToLower(f.Name)] = true
		}
	}
	sort.Slice(z.File, func(i, j int) bool { return z.File[i].Name < z.File[j].Name })
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		p := f.Name
		isConfig := indexed[p].Kind == "module_config"
		if !moduleJar(p) && !wrapperFile(p) && !isConfig {
			continue
		}
		entry, ok := indexed[p]
		if !ok || int64(f.UncompressedSize64) != entry.Size {
			return Report{}, fmt.Errorf("Запись отсутствует в MIG03: %s", p)
		}
		limit := maxJar
		if (wrapperFile(p) && !moduleJar(p)) || isConfig {
			limit = maxWrapper
		}
		if f.UncompressedSize64 > uint64(limit) {
			result.Blockers = append(result.Blockers, p+": источник превышает ограничение анализа")
			continue
		}
		b, err := readFile(ctx, f, limit)
		if err != nil {
			return Report{}, fmt.Errorf("Не удалось прочитать %s: %w", p, err)
		}
		sha := digest(b)
		if sha != entry.SHA256 {
			return Report{}, fmt.Errorf("Источник изменился после инвентаризации: %s", p)
		}
		if isConfig && !moduleJar(p) {
			// Конфигурация модуля влияет на исполняемое поведение, включая хуки входа и
			// запуска. Незаметный пропуск осиротевших конфигураций приводил к ложным
			// отчётам о чистой миграции. Проверяйте JSON и соотносите его с артефактом;
			// не сохраняйте в отчёте необработанную конфигурацию или секреты.
			base := strings.ToLower(p)
			i := strings.Index(base, "modules-config/")
			moduleName := ""
			if i >= 0 {
				tail := p[i+len("modules-config/"):]
				if j := strings.IndexByte(tail, '/'); j >= 0 {
					moduleName = tail[:j]
				}
			}
			m := Module{Path: p, SHA256: sha, Name: moduleName, Implementation: "source_port", Status: "blocked"}
			if !strings.HasSuffix(strings.ToLower(p), ".json") {
				m.Reason = "Неподдерживаемый формат конфигурации модуля; требуется перенос исходного кода"
			} else if !validModuleConfig0446(b) {
				m.Reason = "Недопустимый или неоднозначный JSON конфигурации модуля"
			} else if moduleName == "" || !moduleArtifacts[strings.ToLower(moduleName)] {
				m.Reason = "Для конфигурации модуля в архиве нет соответствующего JAR; устраните недостающую зависимость или явно перенесите код"
			} else {
				m.Status = "manual"
				m.Reason = "Конфигурация проверена; перенесите настройки отдельно и проверьте работу новых модулей. Старые секреты не принимаются"
			}
			result.Modules = append(result.Modules, m)
			if m.Status == "blocked" {
				result.Blockers = append(result.Blockers, p+": "+m.Reason)
			}
			continue
		}
		if moduleJar(p) {
			m := Module{Path: p, SHA256: sha, Name: path.Base(p), Implementation: "blocker", Status: "blocked"}
			n, auth, launch, er := jarEvidence(ctx, b)
			// Не сохраняйте предоставленный JAR текст манифеста: он недоверенный и может содержать
			// секреты.
			_ = n
			m.AuthHook = auth
			m.LaunchHook = launch
			prefix := strings.TrimSuffix(strings.ToLower(p), ".jar")
			for s := range sources {
				if strings.HasPrefix(s, prefix+"/") || strings.HasPrefix(s, "src/") && strings.Contains(s, strings.ToLower(strings.TrimSuffix(path.Base(p), ".jar"))) {
					m.SourcesPresent = true
					break
				}
			}
			if er != nil {
				m.Reason = "Небезопасный или недопустимый JAR: " + er.Error()
			} else if legacyWrapperJar(p) {
				// Эти старые бинарники никогда не импортируются. Имя указывает лишь роль
				// замены, а НЕ подлинность поставщика или доверие.
				m.Implementation = "built_in_equivalent"
				m.Status = "manual"
				m.Reason = "Устаревший бинарный файл wrapper/authlib необходимо удалить, а не запускать; замените его на Never ServerBridge и независимо проверьте вход и подключение"
			} else if auth || launch {
				m.Reason = "Модуль использует API аутентификации/лаунчера; требуется перенос исходного кода и поведенческие тесты"
			} else if m.SourcesPresent {
				m.Implementation = "source_port"
				m.Reason = "Исходный код доступен, но адаптер не проверен; требуется явный перенос и тестирование"
			} else {
				m.Reason = "Неизвестный исполняемый JAR: нет одобренного аналога или адаптера; требуется перенос исходного кода либо удаление"
			}
			result.Modules = append(result.Modules, m)
			if m.Status == "blocked" {
				result.Blockers = append(result.Blockers, p+": "+m.Reason)
			}
		} else {
			w := parseWrapper(b, p, sha)
			// Общий .env считается обёрткой только если его ключи действительно на неё
			// указывают.
			if (path.Base(strings.ToLower(p)) == ".env" || strings.HasSuffix(strings.ToLower(p), ".env")) && !w.LegacyAddressPresent && !w.LegacyTokenPresent && w.Mode != "inline" {
				continue
			}
			result.Wrappers = append(result.Wrappers, w)
			if w.Status == "blocked" {
				result.Blockers = append(result.Blockers, p+": "+w.Reason)
			}
		}
	}
	result.Ready = len(result.Blockers) == 0
	return result, nil
}

// Конфигурации модулей содержат секреты и не являются обычными JSON-документами.
// Проверяйте повторяющиеся ключи объектов вместо неявного принятия последнего.
func validModuleConfig0446(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var obj map[string]json.RawMessage
	if err := decoder.Decode(&obj); err != nil || obj == nil {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false
	}
	// Ключи верхнего уровня должны быть уникальны даже при Unicode case-folding.
	// Никогда не сохраняйте значения: они могут содержать пароли и токены
	// провайдера.
	seen := map[string]bool{}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false
		}
		k, ok := key.(string)
		if !ok || seen[strings.ToLower(k)] {
			return false
		}
		seen[strings.ToLower(k)] = true
		var v json.RawMessage
		if err = decoder.Decode(&v); err != nil {
			return false
		}
	}
	_, err = decoder.Token()
	return err == nil
}
