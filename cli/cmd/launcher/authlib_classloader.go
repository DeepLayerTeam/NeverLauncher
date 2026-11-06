package main

// Неизменяемые локально проверенные дополнения загрузчика классов. Этот пакет не загружает
// исполняемый код при старте и не переписывает библиотеки Mojang без уведомления.
import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

const compatSchema0279 = "launcher.authlib-classloader.v1"
const compatReceiptPath0279 = ".launcher/compatibility.json"

type compatArtifact0279 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type compatAgent0279 struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Options string `json:"options,omitempty"`
}
type compatLock0279 struct {
	SchemaVersion           string               `json:"schemaVersion"`
	AuthMode                string               `json:"authMode"`
	JavaMajor               int                  `json:"javaMajor"`
	ParentInstallPlanSHA256 string               `json:"parentInstallPlanSha256"`
	Classpath               []compatArtifact0279 `json:"classpath,omitempty"`
	Modulepath              []compatArtifact0279 `json:"modulepath,omitempty"`
	JavaAgents              []compatAgent0279    `json:"javaAgents,omitempty"`
	AddOpens                []string             `json:"addOpens,omitempty"`
}
type compatInputArtifact0279 struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	SourceFile string `json:"sourceFile"`
}
type compatInputAgent0279 struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	SourceFile string `json:"sourceFile"`
	Options    string `json:"options,omitempty"`
}
type compatRequest0279 struct {
	SchemaVersion string                    `json:"schemaVersion"`
	AuthMode      string                    `json:"authMode"`
	Classpath     []compatInputArtifact0279 `json:"classpath,omitempty"`
	Modulepath    []compatInputArtifact0279 `json:"modulepath,omitempty"`
	JavaAgents    []compatInputAgent0279    `json:"javaAgents,omitempty"`
	AddOpens      []string                  `json:"addOpens,omitempty"`
}

func compatReadRequest0279(path string) (compatRequest0279, error) {
	var input compatRequest0279
	file, err := os.Open(path)
	if err != nil {
		return input, err
	}
	defer file.Close()
	d := json.NewDecoder(io.LimitReader(file, 1<<20+1))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		return input, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return input, errors.New("Неожиданное значение: данные после запроса совместимости")
	}
	// Запретите приём слишком большого, хотя и синтаксически допустимого, документа JSON.
	if st, err := file.Stat(); err != nil || st.Size() > 1<<20 {
		return input, errors.New("Размер запроса совместимости превышает 1 МиБ")
	}
	base := filepath.Dir(path)
	for i := range input.Classpath {
		if !filepath.IsAbs(input.Classpath[i].SourceFile) {
			input.Classpath[i].SourceFile = filepath.Join(base, input.Classpath[i].SourceFile)
		}
	}
	for i := range input.Modulepath {
		if !filepath.IsAbs(input.Modulepath[i].SourceFile) {
			input.Modulepath[i].SourceFile = filepath.Join(base, input.Modulepath[i].SourceFile)
		}
	}
	for i := range input.JavaAgents {
		if !filepath.IsAbs(input.JavaAgents[i].SourceFile) {
			input.JavaAgents[i].SourceFile = filepath.Join(base, input.JavaAgents[i].SourceFile)
		}
	}
	return input, nil
}

func compatValidateJar0279(path, digest, prefix string) error {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(strings.ToLower(path), ".jar") {
		return fmt.Errorf("compatibility JAR: требуется «в каталоге %s:» %q", prefix, path)
	}
	if err := validateVanillaRelativePath(path); err != nil {
		return err
	}
	if !isSHA256Hex0271(digest) {
		return fmt.Errorf("Требуется SHA-256: %s", path)
	}
	return nil
}
func compatValidateLock0279(lock *compatLock0279) error {
	if lock == nil {
		return nil
	}
	if lock.SchemaVersion != compatSchema0279 || !isSHA256Hex0271(lock.ParentInstallPlanSHA256) {
		return errors.New("Некорректный идентификатор подтверждения совместимости")
	}
	switch lock.AuthMode {
	case "official", "offline", "yggdrasil":
	default:
		return errors.New("Режим аутентификации не поддерживается")
	}
	if lock.JavaMajor < 8 || lock.JavaMajor > 30 {
		return errors.New("Некорректное значение: основная версия Java для совместимости")
	}
	if len(lock.Classpath)+len(lock.Modulepath)+len(lock.JavaAgents) > 64 || len(lock.AddOpens) > 64 {
		return errors.New("Превышено допустимое число элементов загрузчика классов")
	}
	if lock.JavaMajor < 9 && (len(lock.Modulepath) > 0 || len(lock.AddOpens) > 0) {
		return errors.New("Java 8 не поддерживает module-path или --add-opens")
	}
	if lock.AuthMode == "yggdrasil" && len(lock.JavaAgents) == 0 {
		return errors.New("Для Yggdrasil требуется явно закреплённый Java Agent")
	}
	seen := map[string]bool{}
	register := func(path, sha, prefix string) error {
		if err := compatValidateJar0279(path, sha, prefix); err != nil {
			return err
		}
		if seen[path] {
			return fmt.Errorf("Повторяющийся JAR совместимости: %s", path)
		}
		seen[path] = true
		return nil
	}
	for _, entry := range lock.Classpath {
		if err := register(entry.Path, entry.SHA256, ".launcher/compat/classpath/"); err != nil {
			return err
		}
	}
	for _, entry := range lock.Modulepath {
		if err := register(entry.Path, entry.SHA256, ".launcher/compat/modules/"); err != nil {
			return err
		}
	}
	for _, entry := range lock.JavaAgents {
		if err := register(entry.Path, entry.SHA256, ".launcher/compat/agents/"); err != nil {
			return err
		}
		if strings.ContainsAny(entry.Options, "\r\n\x00") || len(entry.Options) > 2048 || strings.Contains(entry.Options, "${") {
			return fmt.Errorf("Некорректное значение: параметры Java-агента для %s", entry.Path)
		}
	}
	opened := map[string]bool{}
	for _, op := range lock.AddOpens {
		// Разрешайте только module/package=ALL-UNNAMED; произвольные параметры JVM запрещены.
		if !validAddOpens0279(op) || opened[op] {
			return fmt.Errorf("Не поддерживается: или повторяющийся параметр --add-opens %q", op)
		}
		opened[op] = true
	}
	return nil
}
func validAddOpens0279(op string) bool {
	if !strings.HasSuffix(op, "=ALL-UNNAMED") {
		return false
	}
	path := strings.TrimSuffix(op, "=ALL-UNNAMED")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || len(parts[0]) > 128 || len(parts[1]) > 128 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.Contains(part, "..") {
			return false
		}
		for _, ch := range part {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_') {
				return false
			}
		}
	}
	return true
}

// Отклоняйте входные данные не в формате JAR до превращения в исполняемый артефакт
// запуска. Java-агент обязан объявлять Premain-Class, иначе -javaagent не сработает.
func verifyCompatibilityJar0279(path string, agent bool) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("Файл совместимости не является JAR: %w", err)
	}
	defer reader.Close()
	if len(reader.File) == 0 || len(reader.File) > 65536 {
		return errors.New("Недопустимое число элементов JAR совместимости")
	}
	var total uint64
	names := map[string]bool{}
	foundPremain := false
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if err := validateVanillaRelativePath(entry.Name); err != nil {
			return err
		}
		if !entry.Mode().IsRegular() {
			return fmt.Errorf("Запись %s в JAR совместимости не является обычным файлом", entry.Name)
		}
		if names[entry.Name] {
			return fmt.Errorf("Повторяющийся элемент JAR совместимости: %s", entry.Name)
		}
		names[entry.Name] = true
		if entry.UncompressedSize64 > 512<<20 || total+entry.UncompressedSize64 > 512<<20 {
			return errors.New("Распакованные данные JAR совместимости превышают 512 МиБ")
		}
		total += entry.UncompressedSize64
		if strings.EqualFold(entry.Name, "META-INF/MANIFEST.MF") && agent {
			if entry.UncompressedSize64 > 64<<10 {
				return errors.New("Манифест Java Agent превышает допустимый размер")
			}
			f, e := entry.Open()
			if e != nil {
				return e
			}
			manifest, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
			closeErr := f.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
			if len(manifest) > 64<<10 {
				return errors.New("Манифест Java Agent превышает допустимый размер")
			}
			primary := string(manifest)
			if i := strings.Index(primary, "\n\n"); i >= 0 {
				primary = primary[:i]
			}
			if i := strings.Index(primary, "\r\n\r\n"); i >= 0 {
				primary = primary[:i]
			}
			foundPremain = regexp.MustCompile(`(?m)^Premain-Class:[ \t]*[A-Za-z_$][A-Za-z0-9_.$]*(?:\r)?$`).MatchString(primary)
		}
	}
	if agent && !foundPremain {
		return errors.New("В JAR агента Java отсутствует корректный атрибут Premain-Class манифеста")
	}
	return nil
}

func compatReceiptFile0279(root string) string {
	return filepath.Join(root, filepath.FromSlash(compatReceiptPath0279))
}
func readCompatReceipt0279(root string) (*compatLock0279, error) {
	path, err := secureClientDestination(root, compatReceiptPath0279)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, errors.New("compatibility receipt: требуется небольшой обычный файл")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock compatLock0279
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&lock); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("Лишние данные подтверждения")
	}
	if err := compatValidateLock0279(&lock); err != nil {
		return nil, err
	}
	return &lock, nil
}
func verifyCompat0279(root string, p factoryPlan0271) error {
	if p.Compatibility == nil {
		if _, err := os.Lstat(compatReceiptFile0279(root)); err == nil {
			return errors.New("Подтверждение совместимости не закреплено")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil // Старые InstallPlan не переносятся автоматически без уведомления.
	}
	if err := compatValidateLock0279(p.Compatibility); err != nil {
		return err
	}
	if p.Java.Major != p.Compatibility.JavaMajor {
		return errors.New("Версия Java в проверке совместимости отличается от InstallPlan")
	}
	actual, err := readCompatReceipt0279(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, p.Compatibility) {
		return errors.New("Подтверждение совместимости не совпадает с InstallPlan")
	}
	check := func(rel, sum string) error {
		full, err := secureClientDestination(root, rel)
		if err != nil {
			return err
		}
		if _, err := mirrorCheckedHash0274(full, sum); err != nil {
			return fmt.Errorf("Ошибка артефакта совместимости %s: %w", rel, err)
		}
		return verifyCompatibilityJar0279(full, strings.HasPrefix(rel, ".launcher/compat/agents/"))
	}
	for _, a := range actual.Classpath {
		if err := check(a.Path, a.SHA256); err != nil {
			return err
		}
	}
	for _, a := range actual.Modulepath {
		if err := check(a.Path, a.SHA256); err != nil {
			return err
		}
	}
	for _, a := range actual.JavaAgents {
		if err := check(a.Path, a.SHA256); err != nil {
			return err
		}
	}
	return nil
}

func compatApply0279(ctx context.Context, stage string, p factoryPlan0271, req compatRequest0279, allowAuthAgent bool) ([]mirrorAction0274, error) {
	if p.Compatibility != nil {
		return nil, errors.New("Совместимость уже настроена. Для изменения правил создайте новую сборку Client Factory")
	}
	if req.SchemaVersion != compatSchema0279 {
		return nil, errors.New("Не поддерживается: схема запроса совместимости")
	}
	lock := compatLock0279{SchemaVersion: compatSchema0279, AuthMode: req.AuthMode, JavaMajor: p.Java.Major, ParentInstallPlanSHA256: p.ReproducibilitySHA256, AddOpens: req.AddOpens}
	if req.AuthMode == "yggdrasil" && !allowAuthAgent {
		return nil, errors.New("custom Yggdrasil agent: требуется «--allow-auth-agent true»")
	}
	actions := []mirrorAction0274{}
	install := func(entry compatInputArtifact0279, prefix string) (compatArtifact0279, error) {
		result := compatArtifact0279{Path: entry.Path, SHA256: strings.ToLower(entry.SHA256)}
		if err := compatValidateJar0279(result.Path, result.SHA256, prefix); err != nil {
			return result, err
		}
		if entry.SourceFile == "" {
			return result, errors.New("Для закреплённого JAR совместимости необходим локальный sourceFile")
		}
		dst, err := secureClientDestination(stage, entry.Path)
		if err != nil {
			return result, err
		}
		_, err = mirrorCopyVerified0274(ctx, dst, mirrorArtifact0274{Path: entry.Path, File: entry.SourceFile, SHA256: result.SHA256})
		if err == nil {
			err = verifyCompatibilityJar0279(dst, prefix == ".launcher/compat/agents/")
		}
		if err == nil {
			actions = append(actions, mirrorAction0274{Kind: "compat-artifact", Path: entry.Path, After: result.SHA256})
		}
		return result, err
	}
	for _, entry := range req.Classpath {
		installed, err := install(entry, ".launcher/compat/classpath/")
		if err != nil {
			return nil, err
		}
		lock.Classpath = append(lock.Classpath, installed)
	}
	for _, entry := range req.Modulepath {
		installed, err := install(entry, ".launcher/compat/modules/")
		if err != nil {
			return nil, err
		}
		lock.Modulepath = append(lock.Modulepath, installed)
	}
	for _, entry := range req.JavaAgents {
		installed, err := install(compatInputArtifact0279{Path: entry.Path, SHA256: entry.SHA256, SourceFile: entry.SourceFile}, ".launcher/compat/agents/")
		if err != nil {
			return nil, err
		}
		lock.JavaAgents = append(lock.JavaAgents, compatAgent0279{Path: installed.Path, SHA256: installed.SHA256, Options: entry.Options})
	}
	if err := compatValidateLock0279(&lock); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomicBytes(compatReceiptFile0279(stage), append(raw, '\n'), 0600); err != nil {
		return nil, err
	}
	return append(actions, mirrorAction0274{Kind: "compat-receipt", Path: compatReceiptPath0279, Before: p.ReproducibilitySHA256, After: sha256HexBytes(append(raw, '\n'))}), nil
}

// Единственные допустимые изменения командной строки во время работы: закреплённые
// дополнения classpath, агенты и (Java 9+) явные открытия модулей/modulepath.
func compatJVMArgs0279(root string, p factoryPlan0271) ([]string, []string, error) {
	if err := verifyCompat0279(root, p); err != nil {
		return nil, nil, err
	}
	if p.Compatibility == nil {
		return nil, nil, nil
	}
	lock := p.Compatibility
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	extraCP := make([]string, 0, len(lock.Classpath))
	jvm := []string{}
	for _, lib := range lock.Classpath {
		extraCP = append(extraCP, filepath.Join(absRoot, filepath.FromSlash(lib.Path)))
	}
	for _, ag := range lock.JavaAgents {
		arg := "-javaagent:" + filepath.Join(absRoot, filepath.FromSlash(ag.Path))
		if ag.Options != "" {
			arg += "=" + ag.Options
		}
		jvm = append(jvm, arg)
	}
	if len(lock.Modulepath) > 0 {
		modules := make([]string, 0, len(lock.Modulepath))
		for _, m := range lock.Modulepath {
			modules = append(modules, filepath.Join(absRoot, filepath.FromSlash(m.Path)))
		}
		jvm = append(jvm, "--module-path", strings.Join(modules, string(os.PathListSeparator)))
	}
	for _, op := range lock.AddOpens {
		jvm = append(jvm, "--add-opens", op)
	}
	return jvm, extraCP, nil
}
func handleRuntimeCompat0279(args []string) error {
	if len(args) == 0 {
		return errors.New("Команды совместимости: compat-inspect|compat-verify|compat-apply")
	}
	flags := args[1:]
	dir := flagValue(flags, "--client-dir", "")
	if dir == "" {
		return errors.New("Требуется: --client-dir")
	}
	output := flagValue(flags, "--output", "")
	if err := rejectFactoryOutputPath0271(dir, output); err != nil {
		return err
	}
	switch args[0] {
	case "compat-inspect", "compat-verify":
		p, err := readFactoryPlan0271(dir)
		if err != nil {
			return err
		}
		if err = verifyFactoryPlan0271(dir, p); err != nil {
			return err
		}
		if args[0] == "compat-verify" {
			return writeOrPrintJSON(output, map[string]any{"status": "verified", "installPlanSha256": p.ReproducibilitySHA256, "compatibility": p.Compatibility})
		}
		return writeOrPrintJSON(output, p.Compatibility)
	case "compat-apply":
		inputFile := flagValue(flags, "--file", "")
		if inputFile == "" {
			return errors.New("compat-apply: требуется --file")
		}
		request, err := compatReadRequest0279(inputFile)
		if err != nil {
			return err
		}
		allow := flagValue(flags, "--allow-auth-agent", "false") == "true"
		plan, err := mirrorTransactional0274(context.Background(), dir, func(stage string) ([]mirrorAction0274, error) {
			p, err := readFactoryPlan0271(stage)
			if err != nil {
				return nil, err
			}
			return compatApply0279(context.Background(), stage, p, request, allow)
		})
		if err != nil {
			return err
		}
		return writeOrPrintJSON(output, plan)
	default:
		return fmt.Errorf("Неизвестная команда совместимости: %q", args[0])
	}
}

// Вызывается при создании метаданных совместимости транзакцией зеркала;
// дайджест транзакции после этого включает закреплённые дополнения Runtime.
func attachCompatToPlan0279(root string, p *factoryPlan0271) error {
	lock, err := readCompatReceipt0279(root)
	if errors.Is(err, os.ErrNotExist) {
		p.Compatibility = nil
		return nil
	}
	if err != nil {
		return err
	}
	p.Compatibility = lock
	return nil
}

// Проверенное происхождение изменения байтов архива authlib хранится отдельно
// от предоставленных автором байтов патча. Оно проверяется при каждом чтении и
// запуске, включая сборки без пользовательских Java-агентов.
const authlibProvenancePath0279 = ".launcher/authlib-provenance.json"
const authlibProvenanceSchema0279 = "launcher.authlib-provenance.v1"

type authlibChange0279 struct {
	Rule         string `json:"rule"`
	Path         string `json:"path"`
	BeforeSHA256 string `json:"beforeSha256"`
	PatchSHA256  string `json:"patchSha256"`
	AfterSHA256  string `json:"afterSha256"`
}
type authlibHistory0279 struct {
	SchemaVersion string              `json:"schemaVersion"`
	Changes       []authlibChange0279 `json:"changes"`
}

func addAuthlibProvenance0279(root string, change authlibChange0279) error {
	path := filepath.Join(root, filepath.FromSlash(authlibProvenancePath0279))
	history := authlibHistory0279{SchemaVersion: authlibProvenanceSchema0279}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &history); err != nil {
			return err
		}
		if history.SchemaVersion != authlibProvenanceSchema0279 {
			return errors.New("Неизвестная версия данных происхождения authlib")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(history.Changes) >= 32 {
		return errors.New("Превышено допустимое число преобразований authlib")
	}
	history.Changes = append(history.Changes, change)
	raw, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicBytes(path, append(raw, '\n'), 0600)
}
func verifyAuthlibProvenance0279(root string, p factoryPlan0271) error {
	full := filepath.Join(root, filepath.FromSlash(authlibProvenancePath0279))
	st, err := os.Lstat(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return errors.New("Некорректное значение: файл данных происхождения authlib")
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	var history authlibHistory0279
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&history); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("Лишние данные после записи происхождения authlib")
	}
	if history.SchemaVersion != authlibProvenanceSchema0279 || len(history.Changes) == 0 || len(history.Changes) > 32 {
		return errors.New("Некорректное значение: история происхождения authlib")
	}
	known := map[string]factorySource0271{}
	for _, src := range p.Sources {
		known[src.Path] = src
	}
	receipt, ok := known[authlibProvenancePath0279]
	if !ok || receipt.SHA256 != sha256HexBytes(raw) || receipt.Size != int64(len(raw)) {
		return errors.New("Источник authlib не закреплён в InstallPlan")
	}
	prior := map[string]string{}
	for i, item := range history.Changes {
		if last, has := prior[item.Path]; has && last != item.BeforeSHA256 {
			return fmt.Errorf("Нарушена цепочка преобразования authlib для %s", item.Path)
		}
		prior[item.Path] = item.AfterSHA256
		if item.Rule != "authlib-class-overlay.sha256.v1" || !strings.HasPrefix(item.Path, "libraries/com/mojang/authlib/") || !strings.HasSuffix(item.Path, ".jar") || !isSHA256Hex0271(item.BeforeSHA256) || !isSHA256Hex0271(item.AfterSHA256) || !isSHA256Hex0271(item.PatchSHA256) {
			return fmt.Errorf("Некорректное значение: запись происхождения authlib %d", i)
		}
		patchRel := ".launcher/compat/patches/" + item.PatchSHA256 + ".jar"
		if pinned, ok := known[patchRel]; !ok || pinned.SHA256 != item.PatchSHA256 {
			return fmt.Errorf("Данные патча authlib %s не закреплены", patchRel)
		}
		patchPath, err := secureClientDestination(root, patchRel)
		if err != nil {
			return err
		}
		if _, err := mirrorCheckedHash0274(patchPath, item.PatchSHA256); err != nil {
			return err
		}
		if i+1 == len(history.Changes) || !laterChange0279(history.Changes, i, item.Path) {
			dest, err := secureClientDestination(root, item.Path)
			if err != nil {
				return err
			}
			if _, err := mirrorCheckedHash0274(dest, item.AfterSHA256); err != nil {
				return fmt.Errorf("Ошибка целевого источника authlib: %w", err)
			}
		}
	}
	return nil
}
func laterChange0279(all []authlibChange0279, idx int, path string) bool {
	for _, item := range all[idx+1:] {
		if item.Path == path {
			return true
		}
	}
	return false
}
