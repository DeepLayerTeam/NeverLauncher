// Пакет gravitcontent преобразует инвентаризированную установку Gravit в исходные данные
// рабочей области сборки Never с закреплёнными хешами. Исходные JAR-файлы не запускаются.
package gravitcontent

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
	"path"
	"sort"
	"strings"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const MaxFileBytes int64 = 64 << 20 // существующий сборщик буферизует загрузку зашифрованной рабочей области
const MaxImportFiles = 25000

type File struct {
	SourcePath string `json:"sourcePath"`
	TargetPath string `json:"targetPath"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Ownership  string `json:"ownership"`
}

// SkippedFile — запись аудита о файле клиентского дерева, намеренно исключённом
// из подготовки. Защищённые и принадлежащие игроку пути не копируются в управляемое дерево Never.
type SkippedFile struct {
	SourcePath string `json:"sourcePath"`
	Reason     string `json:"reason"`
}

type Plan struct {
	SourceDirectory string                              `json:"sourceDirectory"`
	SkippedFiles    []SkippedFile                       `json:"skippedFiles"`
	Format          string                              `json:"format"`
	SourceSHA256    string                              `json:"sourceSha256"`
	InventorySHA256 string                              `json:"inventorySha256"`
	ProfilePath     string                              `json:"profilePath"`
	Profile         model.GravitImportResult02210       `json:"profile"`
	Optional        *model.GravitOptionalMigration02411 `json:"optional,omitempty"`
	Files           []File                              `json:"files"`
	FilesSHA256     string                              `json:"filesSha256"`
	Ready           bool                                `json:"ready"`
	Blockers        []string                            `json:"blockers"`
}

func safeTarget(p string) bool {
	for _, r := range p {
		if r < 32 || r == 127 {
			return false
		}
	}
	return p != "" && len(p) < 1024 && !strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\:\x00\r\n\t") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.HasPrefix(strings.ToLower(p), ".")
}

// safeSourceDirectory принимает каталог установки клиента относительно Gravit,
// а не произвольный путь в исходном ZIP. Инвентаризация уже проверена
// и запрещает обход каталогов, но относительный путь также проверяется отдельно.
func safeSourceDirectory(s string) bool {
	if !safeTarget(s) || len(s) > 512 {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// Правила обновления и исключений Gravit задают буквальные пути к файлам или поддеревьям,
// а не неограниченные регулярные выражения или маски. Используем результат конвертера
// модели, который уже проверил каждый путь и возможные конфликты.
func matchesFileRule(file string, patterns []string) bool {
	for _, rule := range patterns {
		if strings.HasSuffix(rule, "/**") {
			prefix := strings.TrimSuffix(rule, "**")
			if strings.HasPrefix(file, prefix) {
				return true
			}
		} else if file == rule {
			return true
		}
	}
	return false
}
func hiddenClientFile(file string) bool {
	for _, segment := range strings.Split(file, "/") {
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}
	return false
}
func protectedClientFile(file string) bool {
	// Пути с мирами игроков, настройками, снимками экрана и наборами ресурсов
	// нельзя развёртывать как управляемые лаунчером, даже если список обновлений
	// исходной системы настроен неправильно.
	first := strings.ToLower(strings.SplitN(file, "/", 2)[0])
	switch first {
	case "saves", "screenshots", "resourcepacks", "shaderpacks", "logs", "crash-reports":
		return true
	}
	switch strings.ToLower(file) {
	case "options.txt", "servers.dat", "usercache.json", "usernamecache.json":
		return true
	}
	return false
}

// Конвертер необязательного каталога проверяет семантику, но для определения владельца
// ему сначала нужны исходные файлы-кандидаты. Кандидатами могут быть только точные ключи
// файловых действий, но не перенаправления, JVM-команды или аргументы скриптов.
func optionalFilePaths(raw json.RawMessage) map[string]bool {
	paths := map[string]bool{}
	if len(raw) == 0 {
		return paths
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return paths
	}
	for _, item := range items {
		var actions []map[string]json.RawMessage
		if json.Unmarshal(item["actions"], &actions) != nil {
			continue
		}
		for _, action := range actions {
			var kind string
			if json.Unmarshal(action["type"], &kind) != nil || !strings.EqualFold(kind, "file") {
				continue
			}
			var entries map[string]string
			if json.Unmarshal(action["files"], &entries) != nil {
				continue
			}
			for source, target := range entries {
				if (target == "" || target == source) && safeTarget(source) {
					paths[source] = true
				}
			}
		}
	}
	return paths
}

func sourcePaths(obj map[string]json.RawMessage, key string) ([]string, error) {
	b, ok := obj[key]
	if !ok {
		return nil, nil
	}
	var paths []string
	if e := json.Unmarshal(b, &paths); e != nil || paths == nil {
		return nil, fmt.Errorf("Некорректное значение: %s пути", key)
	}
	if len(paths) > 4096 {
		return nil, fmt.Errorf("Превышено ограничение длины пути %s", key)
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !safeTarget(p) {
			return nil, fmt.Errorf("Небезопасный объект: %s путь: %q", key, p)
		}
		if !strings.HasSuffix(strings.ToLower(p), ".jar") && !strings.Contains(path.Base(p), ".") {
			p += "/**"
		}
		out = append(out, p)
	}
	return out, nil
}

func sourceFile(z *zip.Reader, name string, limit int64) ([]byte, error) {
	for _, f := range z.File {
		if f.Name != name {
			continue
		}
		if int64(f.UncompressedSize64) > limit {
			return nil, errors.New("Исходный элемент превышает ограничение размера")
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(r, limit+1))
		ce := r.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		if int64(len(b)) > limit {
			return nil, errors.New("Исходный элемент превышает допустимое ограничение")
		}
		return b, nil
	}
	return nil, errors.New("Отсутствует: исходный файл")
}

// Prepare сверяет все исходные данные с зафиксированной инвентаризацией MIG03,
// затем выбирает клиентское дерево ОДНОГО профиля и общие библиотеки/ресурсы.
// Файлы других профилей, launchserver, auth, обёртки, ключи и пользовательские модули
// никогда не копируются в клиентскую рабочую область.
func Prepare(ctx context.Context, src io.ReaderAt, size int64, saved inv.Inventory, profilePath, projectID, profileID, name, loader string, exactLoaderVersion ...string) (Plan, error) {
	out := Plan{Format: "launcher.gravit-content.v1", SourceSHA256: saved.SourceSHA256, InventorySHA256: saved.ManifestSHA256, ProfilePath: profilePath, Files: []File{}, SkippedFiles: []SkippedFile{}, Blockers: []string{}}
	actual, e := inv.Inspect(ctx, src, size, saved.SourceSHA256)
	if e != nil {
		return out, e
	}
	if actual.SourceBytes != saved.SourceBytes || actual.ManifestSHA256 != saved.ManifestSHA256 {
		return out, errors.New("Источник отличается от зафиксированной инвентаризации")
	}
	return PreparePinned(ctx, src, size, saved, profilePath, projectID, profileID, name, loader, exactLoaderVersion...)
}

// PreparePinned преобразует один профиль после полной проверки неизменяемых исходных
// байтов через gravitinventory.Inspect и сравнения манифеста с зафиксированным запуском.
// Применяется только для пробной миграции нескольких профилей из закрытого для записи,
// приватного изолированного хранилища. Реальный импорт выполняется через Prepare.
func PreparePinned(ctx context.Context, src io.ReaderAt, size int64, saved inv.Inventory, profilePath, projectID, profileID, name, loader string, exactLoaderVersion ...string) (Plan, error) {
	out := Plan{Format: "launcher.gravit-content.v1", SourceSHA256: saved.SourceSHA256, InventorySHA256: saved.ManifestSHA256, ProfilePath: profilePath, Files: []File{}, SkippedFiles: []SkippedFile{}, Blockers: []string{}}
	if size != saved.SourceBytes || saved.ManifestSHA256 == "" {
		return out, errors.New("Исходный снимок не проверен")
	}
	if _, e := saved.Manifest(); e != nil {
		return out, e
	}
	z, e := zip.NewReader(src, size)
	if e != nil {
		return out, e
	}
	if !safeTarget(profilePath) || !strings.HasPrefix(strings.ToLower(profilePath), "profiles/") || !strings.HasSuffix(strings.ToLower(profilePath), ".json") {
		return out, errors.New("Требуется: явный путь к исходному файлу profiles/*.json")
	}
	meta := map[string]inv.File{}
	for _, f := range saved.Files {
		meta[f.Path] = f
	}
	profileMeta, ok := meta[profilePath]
	if !ok || profileMeta.Kind != "client_profile" {
		return out, errors.New("Профиль отсутствует в проверенной инвентаризации")
	}
	raw, e := sourceFile(z, profilePath, 1<<20)
	if e != nil {
		return out, e
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != profileMeta.SHA256 {
		return out, errors.New("Содержимое профиля отличается от инвентаризации")
	}
	// Старый конвертер блокирует все непустые необязательные массивы. Извлеките их
	// и независимо проверьте промышленным конвертером OptionalFile; лишь после этого
	// удалите обработанное поле из изолированной копии для преобразования.
	var obj map[string]json.RawMessage
	if e = json.Unmarshal(raw, &obj); e != nil || obj == nil {
		return out, errors.New("Для профиль требуется: объект JSON")
	}
	optionRaw := obj["updateOptional"]
	if len(optionRaw) > 0 && !bytes.Equal(bytes.TrimSpace(optionRaw), []byte("null")) {
		var vals []json.RawMessage
		if e = json.Unmarshal(optionRaw, &vals); e != nil || vals == nil {
			return out, errors.New("Некорректное значение: необязательный массив")
		}
		if len(vals) > 0 {
			obj["updateOptional"] = json.RawMessage(`[]`)
		}
	} else if bytes.Equal(bytes.TrimSpace(optionRaw), []byte("null")) {
		// Gravit может представить отсутствующий необязательный список как null, тогда как
		// устаревший конвертер профилей принимает только массивы. Считаем null пустым списком.
		obj["updateOptional"] = json.RawMessage(`[]`)
	}
	clean, e := json.Marshal(obj)
	if e != nil {
		return out, e
	}
	converted, e := model.ConvertGravitProfile02210(clean, projectID, profileID, name, loader)
	if e != nil {
		return out, e
	}
	// Gravit ClientProfile не указывает сборку загрузчика. Оператор задаёт точную версию,
	// закрепляемую одновременно в неизменяемом Profile v2 и манифесте Minecraft релиза.
	// Нельзя определять сборку Forge/Fabric по клиентскому JAR или считать
	// универсальный загрузчик заведомо пригодным к запуску.
	loaderVersion := ""
	if len(exactLoaderVersion) > 1 {
		return out, errors.New("Разрешена только одна точно указанная версия загрузчика")
	}
	if len(exactLoaderVersion) == 1 {
		loaderVersion = exactLoaderVersion[0]
	}
	converted.Profile.MinecraftVersion = converted.Settings.Minecraft.Version
	converted.Profile.JavaMajor = converted.Settings.Runtime.Java.MajorVersion
	converted.Profile.LoaderVersion = loaderVersion
	converted.Settings.Minecraft.LoaderVersion = loaderVersion
	if loader != "vanilla" && loaderVersion == "" {
		out.Blockers = append(out.Blockers, "Требуется точная версия загрузчика для "+loader)
	}
	if loader == "vanilla" && loaderVersion != "" {
		out.Blockers = append(out.Blockers, "Профиль Vanilla не может указывать версию загрузчика")
	}
	if normalized, normalizeErr := model.NormalizeProfileV2(converted.Profile); normalizeErr != nil {
		out.Blockers = append(out.Blockers, "Некорректный профиль запуска: "+normalizeErr.Error())
	} else {
		converted.Profile = normalized
	}
	out.Profile = converted
	// Исходный профиль может содержать поддерживаемые ссылки на серверы после ручной проверки;
	// поле 'manual' НИКОГДА не означает разрешения на настройку сервера.
	for _, fld := range converted.Fields {
		if fld.Status == "blocked" {
			out.Blockers = append(out.Blockers, "profile."+fld.Field+": "+fld.Reason)
		}
	}
	stem := strings.TrimSuffix(path.Base(profilePath), path.Ext(profilePath))
	if stem == "" || stem == "." {
		return out, errors.New("Некорректное значение: имя файла профиля")
	}
	// Поле `dir` профиля Gravit определяет клиентское дерево и не обязательно
	// совпадает с именем JSON-файла (переименования распространены). Если `dir` указан
	// явно, нельзя подставлять вместо него базовое имя файла: это может незаметно
	// для оператора импортировать файлы другого профиля.
	sourceDirectory := stem
	if dirRaw, exists := obj["dir"]; exists {
		if e = json.Unmarshal(dirRaw, &sourceDirectory); e != nil || !safeSourceDirectory(sourceDirectory) {
			return out, errors.New("Некорректное значение: каталог клиента Gravit")
		}
	}
	if !safeSourceDirectory(sourceDirectory) {
		return out, errors.New("Некорректное значение: каталог клиента Gravit")
	}
	out.SourceDirectory = sourceDirectory
	prefixes := []string{"updates/" + sourceDirectory + "/", "clients/" + sourceDirectory + "/"}
	used := map[string]string{}
	clientFiles := 0
	optionalCandidates := []model.ManifestFile{}
	// Поле `update` определяет файлы под управлением Gravit; всё остальное
	// в клиентском дереве потенциально принадлежит игроку. Исходный JAR из
	// classpath также обязателен, даже если он отсутствует в `update`.
	updateRules, e := sourcePaths(obj, "update")
	if e != nil {
		out.Blockers = append(out.Blockers, e.Error())
		// Заблокированный источник не должен получать более разрешительную трактовку.
		updateRules = []string{".migration/no-match"}
	}
	optionalFiles := optionalFilePaths(optionRaw)
	classpath := make(map[string]bool, len(converted.Settings.Runtime.Launch.ClasspathEntries))
	for _, cp := range converted.Settings.Runtime.Launch.ClasspathEntries {
		classpath[cp] = true
	}
	ownerExcluded := make([]string, 0)
	for _, rule := range converted.Settings.FileRules {
		if rule.Action == "exclude" {
			ownerExcluded = append(ownerExcluded, rule.Pattern)
		}
	}
	for _, f := range saved.Files {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		var target string
		switch {
		case f.Sensitive || f.Kind == "module" || f.Kind == "runtime" || f.Kind == "authentication" || f.Kind == "server_wrapper" || f.Kind == "launchserver" || f.Kind == "key" || f.Kind == "texture":
			continue
		case strings.HasPrefix(f.Path, prefixes[0]):
			target = strings.TrimPrefix(f.Path, prefixes[0])
		case strings.HasPrefix(f.Path, prefixes[1]):
			target = strings.TrimPrefix(f.Path, prefixes[1])
		case strings.HasPrefix(f.Path, "libraries/") || strings.HasPrefix(f.Path, "assets/"):
			target = f.Path
		default:
			continue
		}
		if !safeTarget(target) || f.Size > MaxFileBytes {
			out.Blockers = append(out.Blockers, "Небезопасный или слишком большой файл клиента: "+f.Path)
			continue
		}
		clientTree := strings.HasPrefix(f.Path, prefixes[0]) || strings.HasPrefix(f.Path, prefixes[1])
		if clientTree && (matchesFileRule(target, ownerExcluded) || protectedClientFile(target) || hiddenClientFile(target)) {
			out.SkippedFiles = append(out.SkippedFiles, SkippedFile{f.Path, "Путь клиента принадлежит игроку или защищён"})
			if classpath[target] {
				out.Blockers = append(out.Blockers, "Путь к классам ссылается на защищённые данные пользователя: "+target)
			}
			continue
		}
		if clientTree && !matchesFileRule(target, updateRules) && !classpath[target] && !optionalFiles[target] {
			out.SkippedFiles = append(out.SkippedFiles, SkippedFile{f.Path, "Отсутствует в обновлении Gravit и списке классов"})
			continue
		}
		fold := strings.ToLower(target)
		if prior, duplicate := used[fold]; duplicate {
			out.Blockers = append(out.Blockers, "Конфликт целевого пути между "+prior+" and "+f.Path)
			continue
		}
		used[fold] = f.Path
		if strings.HasSuffix(f.Path, "/") || len(f.SHA256) != 64 {
			out.Blockers = append(out.Blockers, "Некорректный элемент: "+f.Path)
			continue
		}
		out.Files = append(out.Files, File{SourcePath: f.Path, TargetPath: target, Size: f.Size, SHA256: f.SHA256, Ownership: "required"})
		if clientTree {
			clientFiles++
		}
		if optionalFiles[target] {
			if classpath[target] {
				out.Blockers = append(out.Blockers, "Базовый путь к классам требует необязательный файл: "+target)
			}
			optionalCandidates = append(optionalCandidates, model.ManifestFile{Path: target, SHA256: f.SHA256, Size: f.Size, Ownership: "optional", Required: false})
		}
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].TargetPath < out.Files[j].TargetPath })
	sort.Slice(out.SkippedFiles, func(i, j int) bool { return out.SkippedFiles[i].SourcePath < out.SkippedFiles[j].SourcePath })
	if clientFiles == 0 {
		out.Blockers = append(out.Blockers, "В выбранном каталоге клиента Gravit нет управляемых файлов: "+sourceDirectory)
	}
	if len(out.Files) > MaxImportFiles {
		out.Blockers = append(out.Blockers, "Превышено допустимое количество файлов клиента")
	}
	if len(optionRaw) > 0 && !bytes.Equal(bytes.TrimSpace(optionRaw), []byte("[]")) && !bytes.Equal(bytes.TrimSpace(optionRaw), []byte("null")) {
		migrated, e := model.ConvertGravitOptionalView02411(raw, model.NewComponentCatalog0241(nil, 1), optionalCandidates)
		if e != nil {
			return out, e
		}
		out.Optional = &migrated
		if !migrated.Ready {
			out.Blockers = append(out.Blockers, "Дополнительные действия не поддерживаются или не разрешены")
		}
		optional := map[string]bool{}
		for _, c := range migrated.Catalog.Components {
			for _, p := range c.Files {
				optional[p] = true
			}
		}
		for i := range out.Files {
			if optional[out.Files[i].TargetPath] {
				out.Files[i].Ownership = "optional"
			}
		}
	}
	// Проверяем присутствие JAR в classpath до подготовки и подписания.
	// Служба миграции не должна незаметно загружать или создавать отсутствующие JAR.
	selected := map[string]bool{}
	for _, f := range out.Files {
		selected[f.TargetPath] = true
	}
	for _, p := range converted.Settings.Runtime.Launch.ClasspathEntries {
		if !selected[p] {
			out.Blockers = append(out.Blockers, "Отсутствует библиотека из пути к классам: "+p)
		}
	}
	fdata, e := json.Marshal(out.Files)
	if e != nil {
		return out, e
	}
	d := sha256.Sum256(fdata)
	out.FilesSHA256 = hex.EncodeToString(d[:])
	out.Ready = len(out.Blockers) == 0
	return out, nil
}

// Reader один раз индексирует проверенный исходный ZIP: импорт 25 000 файлов
// не должен вызывать квадратичное число линейных поисков по центральному каталогу.
type Reader struct{ entries map[string]*zip.File }

func NewReader(src io.ReaderAt, size int64) (*Reader, error) {
	z, e := zip.NewReader(src, size)
	if e != nil {
		return nil, e
	}
	entries := make(map[string]*zip.File, len(z.File))
	for _, f := range z.File {
		if _, duplicate := entries[f.Name]; duplicate {
			return nil, errors.New("Обнаружен дубликат: элемент ZIP-архива")
		}
		entries[f.Name] = f
	}
	return &Reader{entries: entries}, nil
}
func (r *Reader) ReadVerified(ctx context.Context, item File) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if item.Size > MaxFileBytes || !safeTarget(item.TargetPath) {
		return nil, errors.New("Файл превышает ограничения подготовленной области")
	}
	f, ok := r.entries[item.SourcePath]
	if !ok {
		return nil, errors.New("Файл отсутствует в исходном ZIP-архиве")
	}
	if int64(f.UncompressedSize64) != item.Size {
		return nil, errors.New("Обнаружено изменение: размер исходного файла")
	}
	stream, e := f.Open()
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(stream, MaxFileBytes+1))
	ce := stream.Close()
	if e != nil {
		return nil, e
	}
	if ce != nil {
		return nil, ce
	}
	h := sha256.Sum256(b)
	if int64(len(b)) != item.Size || hex.EncodeToString(h[:]) != item.SHA256 {
		return nil, fmt.Errorf("Несовпадение: контрольная сумма содержимого: %q", item.SourcePath)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return b, nil
}
func ReadVerifiedFile(ctx context.Context, src io.ReaderAt, size int64, item File) ([]byte, error) {
	r, e := NewReader(src, size)
	if e != nil {
		return nil, e
	}
	return r.ReadVerified(ctx, item)
}
func WorkspaceID(run, profilePath string) string {
	h := sha256.Sum256([]byte(run + "\x00" + profilePath))
	return "ws-gravit-" + hex.EncodeToString(h[:16])
}
