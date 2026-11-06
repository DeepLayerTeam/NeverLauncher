package gravitcontent

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

const profileFixture = `{"title":"Demo","info":"Server","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"minJavaVersion":17,"maxJavaVersion":999,"classLoaderConfig":"SYSTEM_ARGS","classPath":["minecraft.jar"],"update":["minecraft.jar"],"updateVerify":["minecraft.jar"],"updateExclusions":["saves","screenshots","resourcepacks","options.txt"],"settings":{"ram":4096,"autoEnter":false,"fullScreen":false},"limited":false}`

func testZip(t *testing.T, contents map[string]string) ([]byte, inv.Inventory) {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for name, value := range contents {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(value)); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	raw := buf.Bytes()
	d := sha256.Sum256(raw)
	inventory, e := inv.Inspect(context.Background(), bytes.NewReader(raw), int64(len(raw)), hex.EncodeToString(d[:]))
	if e != nil {
		t.Fatal(e)
	}
	return raw, inventory
}
func TestContentRealFileSelection0337(t *testing.T) {
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json": profileFixture, "updates/demo/minecraft.jar": "jar-bytes", "updates/other/evil.jar": "other", "assets/indexes/index.json": "{}", "libraries/com/example/lib.jar": "lib", "LaunchServer.json": "{}", "modules/unsafe.jar": "must-not-execute", "skins/example.png": "private-image",
	})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if !p.Ready {
		t.Fatalf("Неожиданные блокирующие ошибки: %+v", p.Blockers)
	}
	if len(p.Files) != 3 {
		t.Fatalf("Неожиданные подготовленные файлы: %+v", p.Files)
	}
	if p.FilesSHA256 == "" || len(p.FilesSHA256) != 64 {
		t.Fatal("Отсутствует хеш плана файлов")
	}
	for _, f := range p.Files {
		if strings.Contains(f.SourcePath, "unsafe") || strings.Contains(f.SourcePath, "other") || strings.Contains(f.SourcePath, "skins") || strings.HasSuffix(f.SourcePath, "LaunchServer.json") {
			t.Fatalf("Включён исполняемый или посторонний файл исходной сборки: %+v", f)
		}
		content, e := ReadVerifiedFile(context.Background(), bytes.NewReader(raw), int64(len(raw)), f)
		if e != nil || int64(len(content)) != f.Size {
			t.Fatalf("Проверка подготовленного состояния завершилась ошибкой: %v", e)
		}
	}
	p2, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil || p2.FilesSHA256 != p.FilesSHA256 {
		t.Fatalf("Недетерминированный план: %v", e)
	}
}
func TestContentRejectsCollisionAndArchiveMutation0337(t *testing.T) {
	raw, invSnapshot := testZip(t, map[string]string{"profiles/demo.json": profileFixture, "updates/demo/minecraft.jar": "one", "clients/demo/minecraft.jar": "two"})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), invSnapshot, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if p.Ready || len(p.Blockers) == 0 {
		t.Fatal("Конфликт регистра символов или путей не был заблокирован")
	}
	other := append([]byte(nil), raw...)
	other[len(other)-1] ^= 1
	if _, e = Prepare(context.Background(), bytes.NewReader(other), int64(len(other)), invSnapshot, "profiles/demo.json", "project", "demo", "", "vanilla"); e == nil {
		t.Fatal("Изменённый ZIP ошибочно совпал с инвентаризацией")
	}
}
func TestContentRejectsCustomBehavior0337(t *testing.T) {
	hostile := strings.Replace(profileFixture, `"limited":false`, `"limited":true`, 1)
	raw, manifest := testZip(t, map[string]string{"profiles/demo.json": hostile, "updates/demo/minecraft.jar": "jar"})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), manifest, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if p.Ready {
		t.Fatal("Несовместимый флаг разрешений Gravit должен запрещать импорт")
	}
}
func TestContentOptionalUnknownAction0337(t *testing.T) {
	hostile := strings.Replace(profileFixture, `"limited":false`, `"limited":false,"updateOptional":[{"name":"bad","actions":[{"type":"execute","command":"rm -rf /"}]}]`, 1)
	raw, manifest := testZip(t, map[string]string{"profiles/demo.json": hostile, "updates/demo/minecraft.jar": "jar"})
	p, e := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), manifest, "profiles/demo.json", "project", "demo", "", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	if p.Ready || p.Optional == nil || p.Optional.Ready {
		t.Fatalf("Неподдерживаемое необязательное действие ошибочно принято: %+v", p.Optional)
	}
}
func TestContentSafeTargets0337(t *testing.T) {
	for _, p := range []string{"../world", "C:/foo", "/root", "mods\\foo", "a/../b", ".migration/evil"} {
		if safeTarget(p) {
			t.Fatalf("Принят небезопасный путь %q", p)
		}
	}
}

// 0.44.3: исходный каталог установки — явное поле `dir` профиля, а не имя
// JSON-файла. Каждый импортированный байт аутентифицируется дайджестом MIG03.
func TestContentExplicitClientDirectory0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"limited":false`, `"dir":"production-pack","limited":false`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/public.json":                  profile,
		"updates/production-pack/minecraft.jar": "correct-jar",
		"updates/public/minecraft.jar":          "WRONG-JAR",
		"clients/public/launcher.jar":           "foreign",
		"libraries/dependency.jar":              "shared-library",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/public.json", "project", "public", "", "vanilla")
	if err != nil || !p.Ready {
		t.Fatalf("Не удалось импортировать явно указанный каталог: %v, %+v", err, p.Blockers)
	}
	if p.SourceDirectory != "production-pack" || len(p.Files) != 2 {
		t.Fatalf("Импортировано неправильное дерево исходных файлов: %+v", p)
	}
	for _, file := range p.Files {
		if strings.Contains(file.SourcePath, "/public/") {
			t.Fatalf("Скопировано неправильное дерево клиентских файлов: %s", file.SourcePath)
		}
		b, err := ReadVerifiedFile(context.Background(), bytes.NewReader(raw), int64(len(raw)), file)
		if err != nil || len(b) == 0 {
			t.Fatalf("Не удалось прочитать проверенный файл: %v", err)
		}
	}
}

func TestContentNeverCopiesPlayerFiles0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"update":["minecraft.jar"]`, `"update":["minecraft.jar","mods"]`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json":                 profile,
		"updates/demo/minecraft.jar":         "jar",
		"updates/demo/mods/expected.jar":     "mod",
		"updates/demo/mods/.unused":          "dot-file",
		"updates/demo/options.txt":           "player's options",
		"updates/demo/saves/world/level.dat": "player world",
		"updates/demo/screenshots/foo.png":   "user screenshot",
		"updates/demo/unmanaged.jar":         "not in update",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Ready {
		t.Fatalf("Корректное дерево файлов клиента было заблокировано: %+v", p.Blockers)
	}
	if len(p.Files) != 2 {
		t.Fatalf("Неожиданные управляемые файлы: %+v", p.Files)
	}
	if len(p.SkippedFiles) != 5 {
		t.Fatalf("Пропущенные файлы отсутствуют в журнале аудита: %+v", p.SkippedFiles)
	}
	for _, f := range p.Files {
		if strings.Contains(f.TargetPath, "saves") || strings.Contains(f.TargetPath, "options") || strings.Contains(f.TargetPath, "unmanaged") || strings.Contains(f.TargetPath, "screenshots") {
			t.Fatalf("Скопированы данные игрока: %q", f.TargetPath)
		}
	}
}

func TestContentRejectsMissingExplicitDirectory0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"limited":false`, `"dir":"renamed","limited":false`, 1)
	raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/minecraft.jar": "wrong"})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready || !strings.Contains(strings.Join(p.Blockers, " "), "renamed") {
		t.Fatalf("При отсутствии явно заданного каталога выполнен незаметный переход на запасной вариант: %+v", p)
	}
}

func TestContentRejectsProtectedClasspath0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"classPath":["minecraft.jar"]`, `"classPath":["saves/evil.jar"]`, 1)
	raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/saves/evil.jar": "untrusted", "updates/demo/minecraft.jar": "good"})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready || !strings.Contains(strings.Join(p.Blockers, " "), "unsafe classpath") {
		t.Fatalf("Принят защищённый путь классов: %+v", p)
	}
}

func TestContentSourceDirectoryUnsafe0443(t *testing.T) {
	for _, directory := range []string{"../other", "/tmp", ".migration", "a\\b", "C:/local"} {
		profile := strings.Replace(profileFixture, `"limited":false`, `"dir":`+strconv.Quote(directory)+`,"limited":false`, 1)
		raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/minecraft.jar": "test"})
		if _, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla"); err == nil {
			t.Fatalf("Принят небезопасный каталог клиента %q", directory)
		}
	}
}

func TestContentStagesOptionalDeclaredFiles0443(t *testing.T) {
	optional := `"updateOptional":[{"name":"Maps","actions":[{"type":"file","files":{"mods/maps.jar":""}}]}],`
	profile := strings.Replace(profileFixture, `"limited":false`, optional+`"limited":false`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json":            profile,
		"updates/demo/minecraft.jar":    "main",
		"updates/demo/mods/maps.jar":    "optional-content",
		"updates/demo/mods/unknown.jar": "unapproved-content",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil || !p.Ready || p.Optional == nil || !p.Optional.Ready {
		t.Fatalf("Необязательный файл не подготовлен: %v, %+v %+v %+v %+v", err, p.Blockers, p.Optional, p.Files, p.SkippedFiles)
	}
	if len(p.Files) != 2 || len(p.SkippedFiles) != 1 {
		t.Fatalf("Неожиданная подготовка необязательных файлов: %+v", p)
	}
	for _, f := range p.Files {
		if f.TargetPath == "mods/maps.jar" && f.Ownership != "optional" {
			t.Fatal("У необязательного файла потеряны сведения о принадлежности")
		}
		if f.TargetPath == "mods/unknown.jar" {
			t.Fatal("Включён неописанный файл")
		}
	}
}

func TestContentEmptyUpdateDoesNotStageUnmanaged0443(t *testing.T) {
	profile := strings.Replace(profileFixture, `"update":["minecraft.jar"]`, `"update":[]`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json":          profile,
		"updates/demo/minecraft.jar":  "required by classpath",
		"updates/demo/bin/client.exe": "not explicitly managed",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil || !p.Ready {
		t.Fatalf("Некорректный путь классов: %v %+v", err, p.Blockers)
	}
	if len(p.Files) != 1 || p.Files[0].TargetPath != "minecraft.jar" || len(p.SkippedFiles) != 1 {
		t.Fatalf("Неожиданно перенесён компонент, отсутствующий в списке: %+v", p)
	}
}

// 0.44.5: файловое действие Gravit допускает пустое назначение или назначение
// идентичности. Оба варианта должны импортировать одни и те же аутентифицированные
// необязательные байты.
func TestContentOptionalIdentityDestination0445(t *testing.T) {
	profile := strings.Replace(profileFixture, `"limited":false`, `"limited":false,"updateOptional":[{"name":"NEI","mark":true,"actions":[{"type":"file","files":{"mods/nei.jar":"mods/nei.jar"}}]}]`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/demo.json":         profile,
		"updates/demo/minecraft.jar": "minecraft",
		"updates/demo/mods/nei.jar":  "optional-content",
	})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil || !p.Ready || p.Optional == nil || !p.Optional.Ready {
		t.Fatalf("В результате преобразования необязательных файлов отсутствует целевой путь идентификации: %v %+v", err, p.Blockers)
	}
	if len(p.Files) != 2 || len(p.Optional.Catalog.Components) != 1 {
		t.Fatalf("Неправильный набор файлов или каталог необязательных компонентов: %+v", p)
	}
	for _, f := range p.Files {
		if f.TargetPath == "mods/nei.jar" {
			if f.Ownership != "optional" {
				t.Fatalf("Необязательный файл ошибочно стал обязательным: %+v", f)
			}
			b, err := ReadVerifiedFile(context.Background(), bytes.NewReader(raw), int64(len(raw)), f)
			if err != nil || string(b) != "optional-content" {
				t.Fatalf("Необязательное содержимое не проверено: %v", err)
			}
			return
		}
	}
	t.Fatal("Необязательный JAR-файл не подготовлен")
}

func TestContentNullableOptionalCollection0445(t *testing.T) {
	profile := strings.Replace(profileFixture, `"limited":false`, `"limited":false,"updateOptional":null`, 1)
	raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/minecraft.jar": "jar"})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil || !p.Ready || p.Optional != nil {
		t.Fatalf("Допускающая null коллекция необязательных файлов нарушила импорт: %v %+v", err, p)
	}
}

// Отклоняйте перемещение вместо подготовки файла под неверным подписанным
// именем.
func TestContentOptionalRelocationRequiresManualResolution0445(t *testing.T) {
	profile := strings.Replace(profileFixture, `"limited":false`, `"limited":false,"updateOptional":[{"name":"bad","actions":[{"type":"file","files":{"mods/nei.jar":"mods/renamed.jar"}}]}]`, 1)
	raw, saved := testZip(t, map[string]string{"profiles/demo.json": profile, "updates/demo/minecraft.jar": "jar", "updates/demo/mods/nei.jar": "mod"})
	p, err := Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), saved, "profiles/demo.json", "project", "demo", "", "vanilla")
	if err != nil || p.Ready || p.Optional == nil || p.Optional.Ready {
		t.Fatalf("Разрешено небезопасное перемещение необязательного файла: %v %+v", err, p)
	}
}

// Импорт модифицированного клиента должен закрепить точную сборку загрузчика и в
// версионированном снимке Profile v2, и в метаданных запуска Minecraft рабочего
// пространства. Исходному ZIP запрещено угадывать сборку загрузчика по произвольным
// именам JAR.
func TestContentModdedLaunchAndOptionalMaterialization0493(t *testing.T) {
	profile := strings.Replace(profileFixture, `"update":["minecraft.jar"]`, `"update":["minecraft.jar","mods"]`, 1)
	profile = strings.Replace(profile, `"classPath":["minecraft.jar"]`, `"classPath":["minecraft.jar","libraries/forge-loader.jar"]`, 1)
	profile = strings.Replace(profile, `"limited":false`, `"limited":false,"updateOptional":[{"name":"Map Overlay","mark":true,"actions":[{"type":"file","files":{"mods/map-overlay.jar":""}}]}]`, 1)
	raw, saved := testZip(t, map[string]string{
		"profiles/forge.json":                profile,
		"updates/forge/minecraft.jar":        "game-library-v1",
		"updates/forge/mods/worldgen.jar":    "worldgen-v1",
		"updates/forge/mods/map-overlay.jar": "optional-v1",
		"libraries/forge-loader.jar":         "forge-loader-v1",
		"updates/other/mods/private.jar":     "foreign-profile",
	})
	ctx := context.Background()
	blocked, err := Prepare(ctx, bytes.NewReader(raw), int64(len(raw)), saved, "profiles/forge.json", "project", "forge", "Forge", "forge")
	if err != nil || blocked.Ready || !strings.Contains(strings.Join(blocked.Blockers, ";"), "exact loader version") {
		t.Fatalf("Принята конфигурация без версии загрузчика: %v %+v", err, blocked.Blockers)
	}
	plan, err := Prepare(ctx, bytes.NewReader(raw), int64(len(raw)), saved, "profiles/forge.json", "project", "forge", "Forge", "forge", "49.0.38")
	if err != nil || !plan.Ready || plan.Optional == nil || !plan.Optional.Ready {
		t.Fatalf("Отклонён импорт клиента с модификациями: %v %+v", err, plan.Blockers)
	}
	if plan.Profile.Profile.LoaderVersion != "49.0.38" || plan.Profile.Profile.MinecraftVersion != "1.20.4" || plan.Profile.Profile.JavaMajor != 17 || plan.Profile.Settings.Minecraft.LoaderVersion != "49.0.38" {
		t.Fatalf("Метаданные запуска не были зафиксированы: %+v", plan.Profile)
	}
	if len(plan.Files) != 4 || plan.FilesSHA256 == "" {
		t.Fatalf("Потеряны модификации, библиотеки и необязательные компоненты: %+v", plan.Files)
	}
	reader, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range plan.Files {
		actual, err := reader.ReadVerified(ctx, file)
		if err != nil || len(actual) == 0 {
			t.Fatalf("Не удалось создать файл %s: %v", file.TargetPath, err)
		}
		if file.TargetPath == "mods/map-overlay.jar" && file.Ownership != "optional" {
			t.Fatal("Потеряна принадлежность необязательного файла")
		}
		if strings.Contains(file.SourcePath, "other") {
			t.Fatal("В импорт попали данные другого профиля")
		}
	}
	bad, err := Prepare(ctx, bytes.NewReader(raw), int64(len(raw)), saved, "profiles/forge.json", "project", "forge", "Forge", "forge", "../malicious")
	if err != nil || bad.Ready {
		t.Fatalf("Принята небезопасная версия: %v %+v", err, bad.Blockers)
	}
}
