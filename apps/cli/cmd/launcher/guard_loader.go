package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// guardCompatClassName0504 проверяет бинарные имена классов JVM по подписанной политике.
func guardCompatClassName0504(class string) bool {
	if len(class) == 0 || len(class) > 256 || !strings.Contains(class, ".") {
		return false
	}
	for _, part := range strings.Split(class, ".") {
		if part == "" {
			return false
		}
		for i, r := range part {
			if r > 127 || (i == 0 && !(unicode.IsLetter(r) || r == '_' || r == '$')) ||
				(i > 0 && !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$')) {
				return false
			}
		}
	}
	return true
}

// guardLoaderConfig0504 помещает в защищённый Java premain только записи артефактов,
// ранее проверенные по Ed25519. Это не новый корень доверия. SHA-256 источника
// классов загрузчика повторно проверяется внутри JVM при определении класса.
func guardLoaderConfig0504(root string, p guardCompatPolicy0502) (string, error) {
	loader := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(p.Loader, "-", ""), "_", ""))
	switch loader {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		return "", fmt.Errorf("Guard: неизвестный доверенный загрузчик JVM %q", p.Loader)
	}
	var library []guardCompatArtifact0502
	for _, a := range p.Artifacts {
		if a.Kind != "loader-library" {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(a.Path), ".jar") || !guardCompatRel0502(a.Path) {
			return "", fmt.Errorf("Guard: недопустимый путь к библиотеке загрузчика %q", a.Path)
		}
		for _, revoked := range p.RevokedDigests {
			if revoked == a.SHA256 {
				return "", errors.New("Guard: библиотека загрузчика отозвана")
			}
		}
		hash, err := guardCompatHashFile0502(root, a.Path)
		if err != nil {
			return "", err
		}
		if hash != a.SHA256 {
			return "", fmt.Errorf("Обнаружено изменение: хеш библиотеки загрузчика Guard: %s", a.Path)
		}
		library = append(library, a)
	}
	if (loader == "vanilla" && len(library) != 0) || (loader != "vanilla" && len(library) == 0) || len(library) > 128 {
		return "", errors.New("Guard: список библиотек загрузчика не соответствует подписанному идентификатору")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "loader.id=%s\nloader.count=%d\n", loader, len(library))
	for i, a := range library {
		// Проверка путей Go выполняется относительно проверенного клиентского корня.
		path, err := guardCompatPath0502(root, a.Path)
		if err != nil {
			return "", err
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "loader.%d.path=%s\nloader.%d.sha256=%s\n", i,
			base64.StdEncoding.EncodeToString([]byte(absolute)), i, a.SHA256)
	}
	if len(p.LoaderClassBytes) > 4096 {
		return "", errors.New("Guard: превышено допустимое число привязок байткода классов загрузчика")
	}
	fmt.Fprintf(&out, "loader.class.count=%d\n", len(p.LoaderClassBytes))
	for i, cls := range p.LoaderClassBytes {
		if !guardCompatClassName0504(cls.Class) || !guardCompatHex0502(cls.SHA256) {
			return "", errors.New("Guard: недопустимая привязка байткода класса загрузчика")
		}
		fmt.Fprintf(&out, "loader.class.%d.name=%s\nloader.class.%d.sha256=%s\n", i,
			base64.StdEncoding.EncodeToString([]byte(cls.Class)), i, cls.SHA256)
	}
	return out.String(), nil
}
