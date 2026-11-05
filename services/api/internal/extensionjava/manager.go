package extensionjava

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const HostMain = "ru.launcher.sdk.host.JavaExtensionHost"

var className = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.]{1,200}$`)
var javaVersionPattern = regexp.MustCompile(`(?:java|openjdk) version "(?:1\.)?(\d+)(?:[.\-+"_]|$)`)

type JarInfo struct {
	EntrypointClass   string            `json:"entrypointClass"`
	GravitModuleClass string            `json:"gravitModuleClass,omitempty"`
	ClassFiles        int               `json:"classFiles"`
	Libraries         []LibraryInfo0482 `json:"libraries,omitempty"`
	MaxClassMajor     int               `json:"maxClassMajor"`
	MinimumJava       int               `json:"minimumJava"`
}

type RuntimeInfo struct {
	Executable string `json:"executable"`
	Feature    int    `json:"feature"`
}

// Inspect проверяет распакованный JAR Java-хоста, не исполняя его код. Это не
// проверка подписи и не антивирусный сканер.
func Inspect(file string) (JarInfo, error) {
	st, err := os.Lstat(file)
	if err != nil {
		return JarInfo{}, err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() < 64 || st.Size() > 128<<20 {
		return JarInfo{}, errors.New("JAR должен быть обычным файлом, а не символической ссылкой, размером не более 128 МиБ")
	}
	zr, err := zip.OpenReader(file)
	if err != nil {
		return JarInfo{}, fmt.Errorf("Ошибка открытия JAR: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > 4096 {
		return JarInfo{}, errors.New("Слишком много элементов в JAR")
	}
	seen := map[string]bool{}
	classes := map[string]bool{}
	var descriptor *zip.File
	var total uint64
	result := JarInfo{MinimumJava: 17}
	for _, f := range zr.File {
		name := f.Name
		if name == "" || name == "." || strings.HasPrefix(name, "./") || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") || strings.HasPrefix(name, "../") || name == ".." || strings.Contains(name, "//") {
			return JarInfo{}, fmt.Errorf("Небезопасный элемент JAR %q", name)
		}
		if seen[name] {
			return JarInfo{}, fmt.Errorf("Повторяющийся элемент JAR %q", name)
		}
		seen[name] = true
		if f.Mode()&os.ModeSymlink != 0 {
			return JarInfo{}, errors.New("JAR содержит символическую ссылку")
		}
		if f.UncompressedSize64 > 32<<20 {
			return JarInfo{}, fmt.Errorf("Элемент JAR %q превышает допустимый размер", name)
		}
		total += f.UncompressedSize64
		if total > 384<<20 {
			return JarInfo{}, errors.New("Размер распакованного JAR превышает лимит")
		}
		if name == "META-INF/MANIFEST.MF" {
			descriptor = f
		}
		if !strings.HasSuffix(name, ".class") {
			continue
		}
		classes[name] = true
		result.ClassFiles++
		if f.UncompressedSize64 < 8 {
			return JarInfo{}, fmt.Errorf("Обрезанный класс %q", name)
		}
		r, e := f.Open()
		if e != nil {
			return JarInfo{}, e
		}
		header := make([]byte, 8)
		_, e = io.ReadFull(r, header)
		if e == nil {
			// Дочитайте поток до конца, чтобы действительно проверить CRC ZIP, а не только
			// заголовок.
			_, e = io.Copy(io.Discard, r)
		}
		closeErr := r.Close()
		if e != nil {
			return JarInfo{}, fmt.Errorf("Ошибка чтения класса %s: %w", name, e)
		}
		if closeErr != nil {
			return JarInfo{}, closeErr
		}
		if binary.BigEndian.Uint16(header[4:6]) == 65535 {
			return JarInfo{}, fmt.Errorf("Предварительная версия байт-кода %s не поддерживается без --enable-preview", name)
		}
		if binary.BigEndian.Uint32(header[:4]) != 0xCAFEBABE {
			return JarInfo{}, fmt.Errorf("Недопустимая сигнатура класса %q", name)
		}
		major := int(binary.BigEndian.Uint16(header[6:8]))
		if major < 45 || major > 100 {
			return JarInfo{}, fmt.Errorf("Неподдерживаемая версия класса %d в %q", major, name)
		}
		if major > result.MaxClassMajor {
			result.MaxClassMajor = major
		}
	}
	if descriptor == nil || descriptor.UncompressedSize64 > 65536 {
		return JarInfo{}, errors.New("Манифест JAR отсутствует или превышает допустимый размер")
	}
	r, err := descriptor.Open()
	if err != nil {
		return JarInfo{}, err
	}
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	_ = r.Close()
	if err != nil {
		return JarInfo{}, err
	}
	if len(data) > 65536 {
		return JarInfo{}, errors.New("Манифест JAR превышает лимит")
	}
	attrs := map[string]string{}
	current := ""
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for _, line := range lines {
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") {
			if current == "" {
				return JarInfo{}, errors.New("Продолжение строки манифеста JAR без начальной строки")
			}
			attrs[current] += line[1:]
			continue
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return JarInfo{}, errors.New("Некорректный манифест JAR")
		}
		current = strings.ToLower(parts[0])
		if _, exists := attrs[current]; exists {
			return JarInfo{}, errors.New("Повторяющийся атрибут манифеста JAR")
		}
		attrs[current] = parts[1]
	}
	if attrs["main-class"] != HostMain {
		return JarInfo{}, fmt.Errorf("Значение JAR Main-Class должно быть %s", HostMain)
	}
	class := attrs["launcher-extension-class"]
	if !className.MatchString(class) || strings.Contains(class, "..") || strings.HasPrefix(class, ".") || strings.HasSuffix(class, ".") {
		return JarInfo{}, errors.New("Недопустимое значение Launcher-Extension-Class")
	}
	if _, ok := attrs["class-path"]; ok {
		return JarInfo{}, errors.New("Внешний JAR Class-Path запрещён")
	}
	if !classes[strings.ReplaceAll(class, ".", "/")+".class"] {
		return JarInfo{}, errors.New("Объявленный класс расширения отсутствует в JAR")
	}
	// Адаптер Gravit включается явно, имеет фиксированную точку входа и явно
	// перенесённый модуль. Не считайте произвольные JAR Gravit совместимыми.
	const gravitAdapter = "ru.launcher.sdk.gravit.GravitCompatExtension"
	portedModule := attrs["launcher-gravit-module-class"]
	if class == gravitAdapter {
		if !className.MatchString(portedModule) || strings.Contains(portedModule, "..") || strings.HasPrefix(portedModule, ".") || strings.HasSuffix(portedModule, ".") || strings.HasPrefix(portedModule, "pro.gravit.launcher.") || strings.HasPrefix(portedModule, "ru.launcher.sdk.") {
			return JarInfo{}, errors.New("Для пакета совместимости Gravit требуется корректный Launcher-Gravit-Module-Class")
		}
		if !classes[strings.ReplaceAll(portedModule, ".", "/")+".class"] {
			return JarInfo{}, errors.New("Перенесённый класс модуля Gravit отсутствует в JAR")
		}
		if !classes["ru/launcher/sdk/gravit/GravitCompatExtension.class"] {
			return JarInfo{}, errors.New("Класс среды совместимости Gravit отсутствует в JAR")
		}
		result.GravitModuleClass = portedModule
	} else if portedModule != "" {
		return JarInfo{}, errors.New("Для класса модуля Gravit требуется явная точка входа адаптера совместимости")
	}
	if !classes["ru/launcher/sdk/host/JavaExtensionHost.class"] {
		return JarInfo{}, errors.New("Класс Java Extension Host отсутствует в JAR")
	}
	libraries, extraClasses, libraryMaxMajor, err := inspectLibraries0482(zr, classes)
	if err != nil {
		return JarInfo{}, fmt.Errorf("Ошибка проверки встроенных зависимостей: %w", err)
	}
	result.Libraries = libraries
	result.ClassFiles += extraClasses
	if libraryMaxMajor > result.MaxClassMajor {
		result.MaxClassMajor = libraryMaxMajor
	}
	result.EntrypointClass = class
	if result.MaxClassMajor > 61 {
		result.MinimumJava = result.MaxClassMajor - 44
	}
	return result, nil
}

// ProbeRuntime проверяет настоящий исполняемый файл JVM с ограниченным сроком
// выполнения.
func ProbeRuntime(ctx context.Context, javaBinary string, requiredFeature int) (RuntimeInfo, error) {
	javaBinary = strings.TrimSpace(javaBinary)
	if javaBinary == "" {
		var err error
		javaBinary, err = exec.LookPath("java")
		if err != nil {
			return RuntimeInfo{}, fmt.Errorf("Среда выполнения Java не найдена: %w", err)
		}
	} else {
		if !filepath.IsAbs(javaBinary) {
			return RuntimeInfo{}, errors.New("Для «configured Java executable» требуется: «absolute»")
		}
		st, err := os.Lstat(javaBinary)
		if err != nil {
			return RuntimeInfo{}, err
		}
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			return RuntimeInfo{}, errors.New("Для «configured Java executable» требуется: «regular, not symlink»")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, javaBinary, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return RuntimeInfo{}, fmt.Errorf("Проверка среды выполнения Java не пройдена: %w", err)
	}
	output = bytes.TrimSpace(output)
	if len(output) > 4096 {
		return RuntimeInfo{}, errors.New("Слишком длинный вывод среды выполнения Java")
	}
	match := javaVersionPattern.FindSubmatch(output)
	if len(match) != 2 {
		return RuntimeInfo{}, errors.New("Неизвестная версия среды выполнения Java")
	}
	feature, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return RuntimeInfo{}, err
	}
	if feature < 17 || feature < requiredFeature {
		return RuntimeInfo{}, fmt.Errorf("Java %d не может загрузить требуемый байт-код Java %d", feature, requiredFeature)
	}
	return RuntimeInfo{Executable: javaBinary, Feature: feature}, nil
}
