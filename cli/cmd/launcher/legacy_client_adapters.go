package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Рецепты старого запуска выводятся из ПОДГОТОВЛЕННЫХ профилей Minecraft и
// загрузчика, а не угадываются по строке версии Forge. Рецепт неизменяем в
// lock Client Factory и проверяется при каждом запуске.
type legacyClasspath0278 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type legacyTarget0278 struct {
	OS        string                `json:"os"`
	Arch      string                `json:"arch"`
	Classpath []legacyClasspath0278 `json:"classpath"`
	Natives   string                `json:"natives"`
}
type legacyLaunch0278 struct {
	Schema        string             `json:"schema"`
	Family        string             `json:"family"`
	ParentProfile string             `json:"parentProfile"`
	ParentSHA256  string             `json:"parentSha256"`
	ChildProfile  string             `json:"childProfile,omitempty"`
	ChildSHA256   string             `json:"childSha256,omitempty"`
	JavaMajor     int                `json:"javaMajor"`
	MainClass     string             `json:"mainClass"`
	GameArguments []string           `json:"gameArguments"`
	Tweaker       string             `json:"tweaker,omitempty"`
	Targets       []legacyTarget0278 `json:"targets"`
}

func legacyFamily0278(loader, mc string) bool {
	if loader == "forge" {
		return mc == "1.7.10" || mc == "1.12.2"
	}
	if loader != "vanilla" {
		return false
	}
	major, minor, _, ok := parseMinecraftReleaseVersion(mc)
	return ok && major == 1 && minor <= 12
}
func legacyLaunchFile0278(root string) string {
	return filepath.Join(root, ".launcher", "legacy-launch.json")
}

// Старые версии Mojang не используют современное arguments.game.
// Разделение сохраняет аргументы в кавычках и отклоняет незакрытые
// кавычки, а не формирует неоднозначные вызовы лаунчера.
func splitLegacyArguments0278(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	quote := rune(0)
	started := false
	escaped := false
	for _, c := range s {
		if escaped {
			b.WriteRune(c)
			escaped = false
			continue
		}
		if c == '\\' && quote == '"' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
			started = true
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			started = true
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if started {
				out = append(out, b.String())
				b.Reset()
				started = false
			}
			continue
		}
		b.WriteRune(c)
		started = true
	}
	if quote != 0 || escaped {
		return nil, errors.New("Незакрытая кавычка или экранирование в устаревшем параметре minecraftArguments")
	}
	if started {
		out = append(out, b.String())
	}
	return out, nil
}

// Объединяйте унаследованные старые параметры по границам argv, а не конкатенацией
// строк. Некоторые профили установки Forge содержат лишь --tweakClass, другие
// повторяют --username/--version, не указывая все базовые параметры Mojang. Явное
// значение дочернего процесса перекрывает родительское для этого параметра; не
// упомянутые дочерним параметры родителя должны сохраняться.
func mergeLegacyArgumentTokens0278(parent, child []string) []string {
	if len(parent) == 0 {
		return append([]string(nil), child...)
	}
	if len(child) == 0 {
		return append([]string(nil), parent...)
	}
	childOptions := make(map[string]bool)
	for _, token := range child {
		if strings.HasPrefix(token, "--") && len(token) > 2 {
			childOptions[strings.SplitN(token, "=", 2)[0]] = true
		}
	}
	out := make([]string, 0, len(parent)+len(child))
	for i := 0; i < len(parent); {
		option := parent[i]
		if strings.HasPrefix(option, "--") && len(option) > 2 {
			start := i
			i++
			for i < len(parent) && !strings.HasPrefix(parent[i], "--") {
				i++
			}
			if !childOptions[strings.SplitN(option, "=", 2)[0]] {
				out = append(out, parent[start:i]...)
			}
			continue
		}
		out = append(out, option)
		i++
	}
	return append(out, child...)
}

func readLegacyProfile0278(root, rel string) (MojangVersionFile, string, error) {
	var profile MojangVersionFile
	if err := validateVanillaRelativePath(rel); err != nil {
		return profile, "", err
	}
	full, err := secureClientDestination(root, rel)
	if err != nil {
		return profile, "", err
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return profile, "", err
	}
	if err = json.Unmarshal(raw, &profile); err != nil {
		return profile, "", fmt.Errorf("Некорректное значение: профиль версии %s: %w", rel, err)
	}
	if strings.TrimSpace(profile.ID) == "" || strings.TrimSpace(profile.MainClass) == "" {
		return profile, "", fmt.Errorf("Неполные данные: устаревший профиль %s", rel)
	}
	return profile, sha256HexBytes(raw), nil
}
func legacyGroupArtifact0278(name string) string {
	p := strings.Split(name, ":")
	if len(p) < 3 {
		return name
	}
	// Классификаторы — отдельные артефакты, однако при изменении версии заменяется
	// соответствующая группа group:artifact:classifier без изменения порядка classpath.
	if len(p) >= 4 {
		return p[0] + ":" + p[1] + ":" + p[3]
	}
	return p[0] + ":" + p[1]
}
func legacyLibraryList0278(child, parent []MojangLibrary) []MojangLibrary {
	seen := map[string]bool{}
	result := make([]MojangLibrary, 0, len(child)+len(parent))
	for _, lib := range append(append([]MojangLibrary{}, child...), parent...) {
		key := legacyGroupArtifact0278(lib.Name)
		if !seen[key] {
			result = append(result, lib)
			seen[key] = true
		}
	}
	return result
}
func resolveLegacyLaunch0278(root, loader, minecraft, profilePath string, javaMajor int, targets []vanillaTarget) (*legacyLaunch0278, error) {
	if !legacyFamily0278(loader, minecraft) {
		return nil, nil
	}
	if javaMajor != 8 {
		return nil, fmt.Errorf("Для устаревший %s %s требуется: Java 8", loader, minecraft)
	}
	parentRel := filepath.ToSlash(filepath.Join("versions", minecraft, minecraft+".json"))
	parent, parentHash, err := readLegacyProfile0278(root, parentRel)
	if err != nil {
		return nil, err
	}
	if parent.ID != minecraft {
		return nil, errors.New("идентификатор исходного профиля прежней системы не совпадает с Minecraft")
	}
	if strings.TrimSpace(parent.MinecraftArgs) == "" && len(parent.Arguments.Game) == 0 {
		return nil, errors.New("В родительском профиле старого формата отсутствуют параметры игры")
	}
	selected := parent
	parentArgs, err := splitLegacyArguments0278(parent.MinecraftArgs)
	if err != nil {
		return nil, fmt.Errorf("Параметры родительского профиля старого формата: %w", err)
	}
	gameArgs := parentArgs
	childHash := ""
	childRel := ""
	if loader == "forge" {
		childRel = profilePath
		if childRel == "" || childRel == parentRel {
			return nil, errors.New("Отсутствует: дочерний профиль прежней версии Forge")
		}
		var child loaderVersionProfile
		full, e := secureClientDestination(root, childRel)
		if e != nil {
			return nil, e
		}
		raw, e := os.ReadFile(full)
		if e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &child); e != nil {
			return nil, e
		}
		if child.InheritsFrom != minecraft {
			return nil, fmt.Errorf("Профиль Forge старого формата должен наследовать %s", minecraft)
		}
		if child.MainClass != "net.minecraft.launchwrapper.Launch" {
			return nil, fmt.Errorf("Старый Forge должен использовать LaunchWrapper, получено %s", child.MainClass)
		}
		expected := "net.minecraftforge.fml.common.launcher.FMLTweaker"
		if minecraft == "1.7.10" {
			expected = "cpw.mods.fml.common.launcher.FMLTweaker"
		}
		if !legacyMinecraftArgumentsContainTweaker(child.MinecraftArgs, expected) {
			return nil, fmt.Errorf("Отсутствует: проверенный модификатор запуска Forge %s", expected)
		}
		childHash = sha256HexBytes(raw)
		selected.MainClass = child.MainClass
		selected.Libraries = legacyLibraryList0278(child.Libraries, parent.Libraries)
		childArgs, parseErr := splitLegacyArguments0278(child.MinecraftArgs)
		if parseErr != nil {
			return nil, fmt.Errorf("Дочерние параметры Forge старого формата: %w", parseErr)
		}
		gameArgs = mergeLegacyArgumentTokens0278(parentArgs, childArgs)
	}
	args := gameArgs
	if len(args) == 0 {
		return nil, errors.New("Отсутствуют параметры запуска старого формата")
	}
	recipe := &legacyLaunch0278{Schema: "launcher.legacy-launch.v1", Family: loader + "/" + minecraft, ParentProfile: parentRel, ParentSHA256: parentHash, ChildProfile: childRel, ChildSHA256: childHash, JavaMajor: 8, MainClass: selected.MainClass, GameArguments: args}
	if loader == "forge" {
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "--tweakClass" {
				recipe.Tweaker = args[i+1]
				break
			}
		}
	}
	for _, t := range targets {
		target, e := normalizeVanillaTarget(t)
		if e != nil {
			return nil, e
		}
		item := legacyTarget0278{OS: target.OS, Arch: target.Arch, Natives: filepath.ToSlash(filepath.Join("natives", target.OS, target.Arch))}
		for _, lib := range selected.Libraries {
			if lib.ClientReq != nil && !*lib.ClientReq {
				continue
			}
			if !rulesAllowTarget(lib.Rules, target) || !libraryArtifactAppliesToTarget(lib.Name, target) || isClassifiedNativeLibrary(lib.Name) {
				continue
			}
			// Нативные библиотеки, заданные только классификатором, не имеют артефакта classpath.
			artifact := lib.Downloads.Artifact
			if !hasMojangDownloadDescriptor(artifact) && len(lib.Downloads.Classifiers) > 0 {
				continue
			}
			rel := strings.TrimSpace(artifact.Path)
			if rel == "" {
				rel = localMavenPath(lib.Name)
			}
			rel = "libraries/" + strings.TrimPrefix(filepath.ToSlash(rel), "libraries/")
			e = addLegacyClasspath0278(root, &item, rel)
			if e != nil {
				return nil, fmt.Errorf("%s: %w", lib.Name, e)
			}
		}
		// Унаследованный клиент Minecraft всегда остаётся последним элементом classpath.
		jarRel := filepath.ToSlash(filepath.Join("versions", minecraft, minecraft+".jar"))
		if err = addLegacyClasspath0278(root, &item, jarRel); err != nil {
			return nil, err
		}
		recipe.Targets = append(recipe.Targets, item)
	}
	sort.Slice(recipe.Targets, func(i, j int) bool {
		return recipe.Targets[i].OS+"/"+recipe.Targets[i].Arch < recipe.Targets[j].OS+"/"+recipe.Targets[j].Arch
	})
	return recipe, nil
}
func addLegacyClasspath0278(root string, target *legacyTarget0278, rel string) error {
	if err := validateVanillaRelativePath(rel); err != nil {
		return err
	}
	full, err := secureClientDestination(root, rel)
	if err != nil {
		return err
	}
	st, err := os.Lstat(full)
	if err != nil {
		return fmt.Errorf("Отсутствует: артефакт пути классов %s: %w", rel, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("Артефакт classpath не является обычным файлом: %s", rel)
	}
	hash, size, err := hashFile(full)
	if err != nil {
		return err
	}
	for _, old := range target.Classpath {
		if old.Path == rel {
			if old.SHA256 != hash {
				return fmt.Errorf("Конфликтующий артефакт classpath %s", rel)
			}
			return nil
		}
	}
	target.Classpath = append(target.Classpath, legacyClasspath0278{Path: rel, SHA256: hash, Size: size})
	return nil
}
func writeLegacyLaunch0278(root string, recipe *legacyLaunch0278) error {
	if recipe == nil {
		return nil
	}
	b, err := json.MarshalIndent(recipe, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicBytes(legacyLaunchFile0278(root), append(b, '\n'), 0o600)
}
func verifyLegacyLaunch0278(root string, p factoryPlan0271) error {
	if p.Legacy == nil {
		// Ранее опубликованные lock-файлы 0.27.7 не содержат старого рецепта.
		// Их исходный дайджест плана и результаты сохраняют силу.
		return nil
	}
	actual, err := resolveLegacyLaunch0278(root, p.Loader, p.MinecraftVersion, p.Launch.ProfilePath, p.Java.Major, p.Targets)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(p.Legacy)
	resolved, _ := json.Marshal(actual)
	if string(expected) != string(resolved) {
		return errors.New("Обнаружено изменение: инструкция запуска прежней версии")
	}
	raw, err := os.ReadFile(legacyLaunchFile0278(root))
	if err != nil {
		return err
	}
	var fromDisk legacyLaunch0278
	if err = json.Unmarshal(raw, &fromDisk); err != nil {
		return err
	}
	disk, _ := json.Marshal(fromDisk)
	if string(expected) != string(disk) {
		return errors.New("файл запуска прежней версии не совпадает с «планом установки»")
	}
	return nil
}

var legacyPlaceholder0278 = regexp.MustCompile(`\$\{([^{}]+)\}`)

func expandLegacyArgs0278(args []string, variables map[string]string) ([]string, error) {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		unknown := ""
		value := legacyPlaceholder0278.ReplaceAllStringFunc(arg, func(token string) string {
			key := strings.TrimSuffix(strings.TrimPrefix(token, "${"), "}")
			result, ok := variables[key]
			if !ok {
				unknown = key
				return token
			}
			return result
		})
		if unknown != "" || strings.Contains(value, "${") {
			return nil, fmt.Errorf("Не поддерживается: заглушка запуска прежней версии %s", unknown)
		}
		out = append(out, value)
	}
	return out, nil
}
func currentLegacyTarget0278(recipe *legacyLaunch0278) (*legacyTarget0278, error) {
	t := currentVanillaTarget()
	for i := range recipe.Targets {
		v := &recipe.Targets[i]
		if v.OS == t.OS && v.Arch == t.Arch {
			return v, nil
		}
	}
	return nil, fmt.Errorf("В сборке старого формата нет цели Runtime %s/%s", t.OS, t.Arch)
}
func runLegacyClient0278(ctx context.Context, root, javaExecutable, username, uuid string) error {
	p, err := readFactoryPlan0271(root)
	if err != nil {
		return err
	}
	if err = verifyFactoryPlan0271(root, p); err != nil {
		return err
	}
	if p.Legacy == nil {
		return errors.New("В InstallPlan отсутствует адаптер устаревшей версии")
	}
	t, err := currentLegacyTarget0278(p.Legacy)
	if err != nil {
		return err
	}
	if username == "" {
		return errors.New("Требуется: --username")
	}
	if javaExecutable == "" {
		javaExecutable = "java"
	}
	// Используйте обязательную проверку основной версии в существующем селекторе Java.
	if err = verifyLegacyJava0278(ctx, javaExecutable); err != nil {
		return err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	classpath := make([]string, 0, len(t.Classpath))
	for _, entry := range t.Classpath {
		classpath = append(classpath, filepath.Join(absRoot, filepath.FromSlash(entry.Path)))
	}
	natives := filepath.Join(absRoot, filepath.FromSlash(t.Natives))
	if st, e := os.Stat(natives); e != nil || !st.IsDir() {
		return fmt.Errorf("Нативные библиотеки старого формата недоступны для %s/%s", t.OS, t.Arch)
	}
	token := os.Getenv("LAUNCHER_MINECRAFT_ACCESS_TOKEN")
	if token != "" && uuid == "" {
		return errors.New("Для авторизованного запуска старого формата требуется --uuid")
	}
	gameAssets := filepath.Join(absRoot, "assets")
	virtualAssets := filepath.Join(absRoot, "assets", "virtual", p.Launch.AssetIndex)
	if st, e := os.Stat(virtualAssets); e == nil && st.IsDir() {
		gameAssets = virtualAssets
	}
	authSession := "-"
	if token != "" {
		authSession = "token:" + token + ":" + uuid
	}
	variables := map[string]string{
		"auth_player_name": username, "auth_uuid": uuid, "auth_access_token": token, "auth_session": authSession,
		"user_properties": "{}", "user_type": "legacy", "version_name": p.MinecraftVersion, "version_type": "release",
		"game_directory": absRoot, "game_assets": gameAssets,
		"assets_root": filepath.Join(absRoot, "assets"), "assets_index_name": p.Launch.AssetIndex,
		"launcher_name": "Launcher", "launcher_version": version, "classpath": strings.Join(classpath, string(os.PathListSeparator)),
		"natives_directory": natives,
	}
	if p.Compatibility != nil {
		switch p.Compatibility.AuthMode {
		case "official", "yggdrasil":
			if token == "" || uuid == "" {
				return errors.New("Для выбранного режима аутентификации необходимы токен и UUID")
			}
			variables["user_type"] = "msa"
		case "offline":
			variables["auth_access_token"] = ""
			variables["auth_session"] = "-"
			variables["user_type"] = "legacy"
		}
	}
	gameArgs, err := expandLegacyArgs0278(p.Legacy.GameArguments, variables)
	if err != nil {
		return err
	}
	compatJVM, compatClasspath, err := compatJVMArgs0279(root, p)
	if err != nil {
		return err
	}
	classpath = append(classpath, compatClasspath...)
	variables["classpath"] = strings.Join(classpath, string(os.PathListSeparator))
	args := []string{"-Djava.library.path=" + natives, "-Dorg.lwjgl.librarypath=" + natives}
	args = append(args, compatJVM...)
	trustedJVM, trustedMain, trustedCleanup, err := trustedPrepare0306(root, p.Legacy.MainClass)
	if err != nil {
		return err
	}
	defer trustedCleanup()
	// Совместимость Guard — обязательная проверка, а не просто опубликованный список
	// разрешений. Все обычные JVM-агенты, включая агенты совместимости, и доверенные плагины
	// должны соответствовать независимо подписанной политике до создания процесса.
	var guardedAgents, guardedPlugins []string
	for _, arg := range append(append([]string{}, compatJVM...), trustedJVM...) {
		if strings.HasPrefix(strings.ToLower(arg), "-javaagent:") {
			path := strings.TrimPrefix(arg, "-javaagent:")
			if index := strings.IndexByte(path, '='); index >= 0 {
				path = path[:index]
			}
			guardedAgents = append(guardedAgents, path)
		}
	}
	if active, release, e := trustedLoad0306(root, strings.TrimSpace(os.Getenv(trustedPublicKeyEnv0306))); e != nil {
		return e
	} else if active != nil {
		for _, plugin := range active.Plugins {
			path, e := trustedPath0306(root, release+"/plugins/"+plugin.Name)
			if e != nil {
				return e
			}
			guardedPlugins = append(guardedPlugins, path)
		}
	}
	if err := guardCompatValidateLaunch0502(root, p.ReproducibilitySHA256, p.MinecraftVersion, p.Loader, guardedAgents, guardedPlugins); err != nil {
		return fmt.Errorf("Guard отклонил запуск Java из-за несовместимости: %w", err)
	}
	args = append(args, trustedJVM...)
	args = append(args, "-cp", strings.Join(classpath, string(os.PathListSeparator)), trustedMain)
	args = append(args, gameArgs...)
	cmd := exec.CommandContext(ctx, javaExecutable, args...)
	cmd.Dir = absRoot
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("Процесс Java старого формата завершился: %w", err)
	}
	return nil
}
func verifyLegacyJava0278(ctx context.Context, executable string) error {
	check, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(check, executable, "-version")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Проверка версии Java: %w", err)
	}
	// Разрешайте форматы версии Java 8: 1.8.0_*** и 8.0.*.
	if !regexp.MustCompile(`(?m)(?:version|openjdk)\s+"(?:1\.8\.|8(?:[.+-]|"))`).Match(raw) {
		return fmt.Errorf("Для адаптера прежней системы необходима Java 8; обнаружено: %q", strings.TrimSpace(string(raw)))
	}
	return nil
}
func handleRuntimeLegacy0278(args []string) error {
	if len(args) < 1 {
		return errors.New("Для команды прежней системы необходимо указать inspect или run")
	}
	dir := flagValue(args[1:], "--client-dir", "")
	if dir == "" {
		return errors.New("Требуется: --client-dir")
	}
	switch args[0] {
	case "legacy-inspect":
		plan, err := readFactoryPlan0271(dir)
		if err != nil {
			return err
		}
		if err = verifyFactoryPlan0271(dir, plan); err != nil {
			return err
		}
		if plan.Legacy == nil {
			return errors.New("Клиент не относится к целям старого формата")
		}
		return writeOrPrintJSON(flagValue(args[1:], "--output", ""), plan.Legacy)
	case "legacy-run":
		timeout, err := time.ParseDuration(flagValue(args[1:], "--timeout", "0s"))
		if err != nil {
			return err
		}
		ctx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		return runLegacyClient0278(ctx, dir, flagValue(args[1:], "--java", "java"), flagValue(args[1:], "--username", ""), flagValue(args[1:], "--uuid", ""))
	default:
		return fmt.Errorf("Неизвестное значение: устаревшая команда %s", args[0])
	}
}
