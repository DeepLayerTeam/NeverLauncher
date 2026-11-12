package model

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var runtimeEnvironmentName0223 = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var javaModuleName0223 = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*(/[A-Za-z_$][A-Za-z0-9_.$]*)?$`)
var heapSize0223 = regexp.MustCompile(`(?i)^-Xm([sx])([1-9][0-9]*)([kmg]?)$`)

// ValidateRuntimeConstraints0223 проверяет исполняемое поведение, а не только форму полей.
// Устаревшие манифесты v1 намеренно освобождены от проверки: их подписи и поведение
// Runtime нельзя менять обновлением.
func ValidateRuntimeConstraints0223(m Manifest) error {
	java := m.Runtime.Java
	if java.MajorVersion == 0 && java.Distribution == "" && len(m.Runtime.JVMArgs) == 0 && m.Runtime.Memory == (MemoryInfo{}) && len(m.Runtime.Launch.ClasspathEntries) == 0 && len(m.Runtime.Launch.ModulepathEntries) == 0 && m.Runtime.Launch.MainClass == "" && m.Runtime.Launch.ClasspathStrategy == "" && len(m.Runtime.Launch.EnvironmentAllowlist) == 0 && m.Runtime.Launch.MainModule == "" {
		// У неполного черновика нет запускаемого Runtime; публикация проверяет его отдельно.
		return nil
	}
	if java.MajorVersion < 1 || java.MajorVersion > 255 {
		return fmt.Errorf("runtime.java.majorVersion должно быть от 1 до 255")
	}
	min, rec, max := java.MinimumMajorVersion, java.RecommendedMajorVersion, java.MaximumMajorVersion
	if min < 0 || rec < 0 || max < 0 || min > 255 || rec > 255 || max > 255 ||
		(min > 0 && max > 0 && min > max) ||
		(rec > 0 && min > 0 && rec < min) || (rec > 0 && max > 0 && rec > max) ||
		(min > 0 && java.MajorVersion < min) || (max > 0 && java.MajorVersion > max) {
		return fmt.Errorf("Диапазон основных версий runtime.java противоречив")
	}
	mem := m.Runtime.Memory
	if mem.MinimumMb < 0 || mem.RecommendedMb < 0 || mem.MaximumMb < 0 ||
		(mem.MaximumMb > 0 && mem.MinimumMb > mem.MaximumMb) ||
		(mem.RecommendedMb > 0 && mem.MinimumMb > 0 && mem.RecommendedMb < mem.MinimumMb) ||
		(mem.MaximumMb > 0 && mem.RecommendedMb > mem.MaximumMb) {
		return fmt.Errorf("Неверный порядок минимальной, рекомендуемой и максимальной памяти runtime.memory (МБ)")
	}
	seenHeap := map[byte]bool{}
	heapValues := map[byte]int64{}
	for _, arg := range m.Runtime.JVMArgs {
		if strings.TrimSpace(arg) == "" || strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("Недопустимый элемент runtime.jvmArgs")
		}
		lower := strings.ToLower(arg)
		switch lower {
		case "-cp", "-classpath", "--class-path", "--module-path", "--patch-module", "--upgrade-module-path", "-p", "-m", "--module", "-jar":
			return fmt.Errorf("Флаг пути или точки входа JVM %q должен задаваться типизированными полями", arg)
		}
		if strings.HasPrefix(lower, "-xbootclasspath") || strings.HasPrefix(lower, "--class-path=") || strings.HasPrefix(lower, "--module-path=") || strings.HasPrefix(lower, "--patch-module=") || strings.HasPrefix(lower, "--upgrade-module-path=") || strings.HasPrefix(lower, "-xx:onerror=") || strings.HasPrefix(lower, "-xx:onoutofmemoryerror=") || strings.HasPrefix(lower, "-javaagent:") || strings.HasPrefix(lower, "-agentpath:") || strings.HasPrefix(lower, "-agentlib:") {
			return fmt.Errorf("Неподдерживаемое переопределение начальной загрузки, пути или агента JVM: %q", arg)
		}
		if strings.HasPrefix(lower, "-xmx") || strings.HasPrefix(lower, "-xms") {
			match := heapSize0223.FindStringSubmatch(arg)
			if match == nil {
				return fmt.Errorf("Недопустимый аргумент памяти кучи JVM: %q", arg)
			}
			kind := match[1][0]
			if seenHeap[kind] {
				return fmt.Errorf("Повторяющийся аргумент памяти кучи JVM -Xm%c", kind)
			}
			seenHeap[kind] = true
			num, err := strconv.ParseInt(match[2], 10, 64)
			if err != nil {
				return fmt.Errorf("Недопустимый аргумент памяти кучи: %w", err)
			}
			switch strings.ToLower(match[3]) {
			case "k":
				num = num/1024 + boolToInt0223(num%1024 > 0)
			case "g":
				if num > (1 << 50) {
					return fmt.Errorf("Слишком большой аргумент памяти кучи")
				}
				num *= 1024
			case "":
				num = num/1048576 + boolToInt0223(num%1048576 > 0)
			}
			heapValues[kind] = num
			if (mem.MinimumMb > 0 && num < int64(mem.MinimumMb)) || (mem.MaximumMb > 0 && num > int64(mem.MaximumMb)) {
				return fmt.Errorf("Аргумент памяти кучи %q выходит за пределы runtime.memory", arg)
			}
		}
	}
	if seenHeap['s'] && seenHeap['x'] && heapValues['s'] > heapValues['x'] {
		return fmt.Errorf("Значение JVM -Xms превышает -Xmx")
	}
	launch := m.Runtime.Launch
	switch strings.ToLower(strings.TrimSpace(launch.ClasspathStrategy)) {
	case "", "manifest", "libraries", "compatibility", "mojang":
	default:
		return fmt.Errorf("Неподдерживаемая стратегия runtime.launch.classpathStrategy: %q", launch.ClasspathStrategy)
	}
	declared := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		if f.Required {
			declared[f.Path] = true
		}
	}
	used := map[string]bool{}
	for _, group := range [][]string{launch.ClasspathEntries, launch.ModulepathEntries} {
		for _, entry := range group {
			if entry == "" || strings.ContainsAny(entry, "\\:\x00\r\n") || strings.HasPrefix(entry, "/") || path.Clean(entry) != entry || entry == "." || strings.HasPrefix(entry, "../") || !strings.HasSuffix(strings.ToLower(entry), ".jar") {
				return fmt.Errorf("Недопустимая подписанная запись classpath/modulepath: %q", entry)
			}
			if !declared[entry] {
				return fmt.Errorf("Путь запуска Runtime %q не является обязательным файлом манифеста", entry)
			}
			if used[entry] {
				return fmt.Errorf("Повторяющийся путь запуска Runtime: %q", entry)
			}
			used[entry] = true
		}
	}
	if launch.MainModule != "" {
		if !javaModuleName0223.MatchString(launch.MainModule) || len(launch.ModulepathEntries) == 0 {
			return fmt.Errorf("Для runtime.launch.mainModule требуются корректное имя модуля и modulepathEntries")
		}
	} else if len(launch.ModulepathEntries) > 0 {
		return fmt.Errorf("Для modulepathEntries требуется runtime.launch.mainModule")
	}
	env := map[string]bool{}
	for _, name := range launch.EnvironmentAllowlist {
		upper := strings.ToUpper(name)
		if !runtimeEnvironmentName0223.MatchString(name) || env[upper] || upper == "JAVA_TOOL_OPTIONS" || upper == "_JAVA_OPTIONS" || upper == "JDK_JAVA_OPTIONS" || upper == "CLASSPATH" {
			return fmt.Errorf("Недопустимое, небезопасное или повторяющееся имя environmentAllowlist: %q", name)
		}
		env[upper] = true
	}
	for _, arg := range m.Minecraft.GameArgs {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("Недопустимый элемент minecraft.gameArgs")
		}
	}
	return nil
}

func boolToInt0223(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
