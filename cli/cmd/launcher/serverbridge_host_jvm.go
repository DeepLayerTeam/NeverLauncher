package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Профили запуска JVM намеренно ограничены точками входа Java. Это не универсальный
// запускатель процессов: каждый артефакт, включая символьные ссылки, разрешается относительно
// настроенного корня сервера и при конфигурации, и при запуске.
var (
	hostJavaClass0283   = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)
	hostJavaModule0283  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	hostJvmHeap0283     = regexp.MustCompile(`^-X(?:ms|mx|ss)[1-9][0-9]*[kKmMgG]$`)
	hostJvmNumber0283   = regexp.MustCompile(`^-XX:(?:MaxGCPauseMillis|InitiatingHeapOccupancyPercent|G1HeapRegionSize|ParallelGCThreads|ConcGCThreads)=[1-9][0-9]*[mMgG]?$`)
	hostJvmBoolean0283  = regexp.MustCompile(`^-XX:\+(?:UseG1GC|UseZGC|UseParallelGC|UseSerialGC|AlwaysPreTouch|DisableExplicitGC|UseStringDeduplication|UnlockExperimentalVMOptions|ParallelRefProcEnabled|PerfDisableSharedMem)$`)
	hostJvmProperty0283 = regexp.MustCompile(`^-D(?:file\.encoding|user\.language|user\.country|user\.timezone|terminal\.ansi|log4j2\.formatMsgNoLookups|using\.aikars\.flags|aikars\.new\.flags)=[A-Za-z0-9_./:+-]{1,128}$`)
)

func hostValidateJavaExecutable0283(path string, allowCustom bool) error {
	base := filepath.Base(path)
	if runtime.GOOS == "windows" {
		if strings.EqualFold(base, "java.exe") {
			return nil
		}
	} else if base == "java" {
		return nil
	}
	if allowCustom {
		return nil
	}
	return fmt.Errorf("Для «non-Java executable» %q требуется «explicit host-level --allow-custom-java-executable»", base)
}

func hostJavaListFlag0283(args []string, single, repeated string) []string {
	out := make([]string, 0)
	if value := flagValue(args, single, ""); value != "" {
		out = append(out, filepath.SplitList(value)...)
	}
	return append(out, multiFlagValues01910(args, repeated)...)
}

func hostResolveJavaEntries0283(root string, raw []string, allowWildcard bool) ([]string, error) {
	if len(raw) > 128 {
		return nil, errors.New("Превышено число элементов пути JVM (максимум 128)")
	}
	result := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		if item == "" || len(item) > 4096 || strings.ContainsAny(item, "\x00\r\n") {
			return nil, errors.New("Пустое значение: «or invalid JVM path entry»")
		}
		if strings.ContainsAny(item, "*?") {
			if !allowWildcard || !strings.HasSuffix(item, string(filepath.Separator)+"*") || strings.Count(item, "*") != 1 || strings.Contains(item, "?") {
				return nil, fmt.Errorf("В пути классов поддерживаются только завершающие шаблоны directory/*: %q", item)
			}
			dir, err := hostResolveDirectory0282(root, strings.TrimSuffix(item, string(filepath.Separator)+"*"))
			if err != nil {
				return nil, fmt.Errorf("Шаблон пути классов JVM %q: %w", item, err)
			}
			item = dir + string(filepath.Separator) + "*"
		} else {
			path := item
			if !filepath.IsAbs(path) {
				path = filepath.Join(root, path)
			}
			info, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("Путь JVM %q: %w", item, err)
			}
			if info.IsDir() {
				item, err = hostResolveDirectory0282(root, path)
			} else if info.Mode().IsRegular() && strings.EqualFold(filepath.Ext(path), ".jar") {
				item, err = hostResolveInsideRoot01910(root, path, true)
			} else {
				return nil, fmt.Errorf("Путь JVM %q: требуется «a directory or .jar file»", item)
			}
			if err != nil {
				return nil, fmt.Errorf("Путь JVM %q: %w", path, err)
			}
		}
		if strings.ContainsRune(item, os.PathListSeparator) {
			return nil, fmt.Errorf("Путь JVM содержит разделитель списка путей: %q", item)
		}
		if !seen[item] {
			result = append(result, item)
			seen[item] = true
		}
	}
	return result, nil
}

func hostNormalizeJavaProfile0283(config *serverBridgeHostConfig01910) error {
	root := config.ServerRoot
	var err error
	if len(config.Classpath) > 0 {
		config.Classpath, err = hostResolveJavaEntries0283(root, config.Classpath, true)
		if err != nil {
			return err
		}
	}
	if len(config.Modulepath) > 0 {
		config.Modulepath, err = hostResolveJavaEntries0283(root, config.Modulepath, false)
		if err != nil {
			return err
		}
	}
	return nil
}

func hostValidateJavaProfile0283(config serverBridgeHostConfig01910) error {
	if err := hostValidateJavaExecutable0283(config.JavaPath, config.AllowCustomJavaExecutable); err != nil {
		return err
	}
	if config.MainClass != "" && len(config.MainClass) > 512 || len(config.Module) > 256 {
		return errors.New("Слишком длинная точка входа JVM")
	}
	if err := hostValidateJvmArguments0283(config.JVMArgs, config.ServerArgs); err != nil {
		return err
	}
	// Проверяйте сохранённые канонические пути повторно: символьные ссылки могли измениться после настройки.
	normalized := config
	if err := hostNormalizeJavaProfile0283(&normalized); err != nil {
		return err
	}
	if len(normalized.Classpath) != len(config.Classpath) || len(normalized.Modulepath) != len(config.Modulepath) {
		return errors.New("Сохранённые пути JVM имеют неканонический формат")
	}
	for i := range config.Classpath {
		if normalized.Classpath[i] != config.Classpath[i] {
			return errors.New("Сохранённый путь классов JVM имеет неканонический формат")
		}
	}
	for i := range config.Modulepath {
		if normalized.Modulepath[i] != config.Modulepath[i] {
			return errors.New("Сохранённый путь модулей JVM имеет неканонический формат")
		}
	}
	switch config.LaunchMode {
	case "java-jar", "java-args-file":
		if config.MainClass != "" || config.Module != "" || len(config.Classpath) != 0 || len(config.Modulepath) != 0 {
			return errors.New("«java-jar/java-args-file modes»: запрещено «mix main class, module or classpath settings»")
		}
	case "java-main-class":
		if config.ServerJar != "" || config.JavaArgsFile != "" {
			return errors.New("«main-class mode»: запрещено одновременное использование параметров запуска jar и argfile")
		}
		if !hostJavaClass0283.MatchString(config.MainClass) || len(config.Classpath) == 0 || config.Module != "" || len(config.Modulepath) != 0 {
			return errors.New("java-main-class: требуется «--main-class and --classpath-entry; modulepath is not supported in this mode»")
		}
	case "java-module":
		if config.ServerJar != "" || config.JavaArgsFile != "" {
			return errors.New("«module mode»: запрещено одновременное использование параметров запуска jar и argfile")
		}
		if config.JavaMajor > 0 && config.JavaMajor < 9 {
			return errors.New("Для модулей Java необходима Java 9 или новее")
		}
		if !hostJavaModule0283.MatchString(config.Module) || len(config.Modulepath) == 0 || len(config.Classpath) != 0 {
			return errors.New("java-module: требуется «--module and --modulepath-entry; classpath is not supported in this mode»")
		}
		if config.MainClass != "" && !hostJavaClass0283.MatchString(config.MainClass) {
			return errors.New("Некорректное значение: «module main class»")
		}
	default:
		return fmt.Errorf("Не поддерживается: режим запуска хоста %q", config.LaunchMode)
	}
	return nil
}

func hostValidateJvmArguments0283(jvm, server []string) error {
	if len(jvm) > 96 || len(server) > 128 {
		return errors.New("Слишком много аргументов JVM или игры")
	}
	for _, arg := range jvm {
		if len(arg) > 256 || !hostJvmHeap0283.MatchString(arg) && !hostJvmNumber0283.MatchString(arg) && !hostJvmBoolean0283.MatchString(arg) && !hostJvmProperty0283.MatchString(arg) {
			return fmt.Errorf("Аргумент JVM %q не одобрен; агенты, произвольные -D и файлы аргументов JVM требуют отдельно проверенной конфигурации запуска", arg)
		}
		// Флаги кучи должны задавать размер; отклоняйте неправдоподобно большие целые значения, вызывающие переполнение.
		if hostJvmHeap0283.MatchString(arg) {
			digits := strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(arg, "-Xms"), "-Xmx"), "-Xss"), "kKmMgG")
			n, err := strconv.ParseUint(digits, 10, 48)
			if err != nil {
				return errors.New("Некорректное значение: «JVM memory value»")
			}
			suffix := strings.ToUpper(arg[len(arg)-1:])
			switch suffix {
			case "K":
				n /= 1024
			case "G":
				n *= 1024
			}
			if n > 1024*1024 {
				return errors.New("Лимит памяти JVM превышает 1 ТиБ")
			}
			if strings.HasPrefix(arg, "-Xss") && n > 64 {
				return errors.New("Размер стека потока JVM превышает 64 МиБ")
			}
		}
	}
	for _, arg := range server {
		if arg == "" || len(arg) > 1024 || strings.HasPrefix(arg, "@") || strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("Некорректное значение: «game argument %q (empty/response-file/control characters are forbidden)»", arg)
		}
	}
	return nil
}

func hostJavaProfileCommand0283(config serverBridgeHostConfig01910) ([]string, error) {
	if err := hostValidateJavaProfile0283(config); err != nil {
		return nil, err
	}
	switch config.LaunchMode {
	case "java-main-class":
		return []string{"-cp", strings.Join(config.Classpath, string(os.PathListSeparator)), config.MainClass}, nil
	case "java-module":
		args := []string{"--module-path", strings.Join(config.Modulepath, string(os.PathListSeparator)), "--module", config.Module}
		if config.MainClass != "" {
			args[len(args)-1] += "/" + config.MainClass
		}
		return args, nil
	}
	return nil, fmt.Errorf("Неизвестный режим профиля JVM: %s", config.LaunchMode)
}

// Minecraft Forge использует отдельный установленный и одобренный оператором файл аргументов
// поставщика. Необязательному user_jvm_args.txt нельзя доверять как второму запускателю: каждый
// токен, кроме комментариев, должен быть одобренным однотокенным флагом JVM.
func hostReadUserJVMArgs0283(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 256*1024 {
		return nil, errors.New("Превышен допустимый размер: «user JVM argument file»")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	args := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Не допускаются неоднозначности токенизации оболочки или Java argfile.
		if strings.ContainsAny(line, "\"'\\") {
			return nil, errors.New("Пользовательские аргументы JVM в кавычках или с экранированием не разрешены")
		}
		for _, token := range strings.Fields(line) {
			if strings.HasPrefix(token, "#") {
				break
			}
			args = append(args, token)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := hostValidateJvmArguments0283(args, nil); err != nil {
		return nil, err
	}
	return args, nil
}
