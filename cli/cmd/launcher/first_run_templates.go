package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// productionTemplates содержит точные канонические файлы производственного
// развёртывания, чтобы установленный бинарный файл nl мог создать
// самостоятельный каталог первого запуска без исходного репозитория.
//
//go:embed templates/production.zip
var productionTemplates []byte

func readCanonicalProductionTemplate(name string) ([]byte, string, error) {
	if override := strings.TrimSpace(os.Getenv("LAUNCHER_PRODUCTION_TEMPLATE_DIR")); override != "" {
		path := filepath.Join(filepath.Clean(override), name)
		data, err := os.ReadFile(path)
		return data, path, err
	}
	if name != "docker-compose.yml" && name != "nginx.conf" && name != "env.production.example" {
		return nil, "", fmt.Errorf("unknown production template: %q", name)
	}
	path := "production/" + name
	archive, err := zip.NewReader(bytes.NewReader(productionTemplates), int64(len(productionTemplates)))
	if err != nil {
		return nil, path, fmt.Errorf("invalid embedded production templates: %w", err)
	}
	for _, entry := range archive.File {
		if entry.Name != path {
			continue
		}
		if entry.UncompressedSize64 > 4<<20 {
			return nil, path, fmt.Errorf("embedded production template too large: %s", name)
		}
		rc, err := entry.Open()
		if err != nil {
			return nil, path, fmt.Errorf("open embedded template %s: %w", name, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, 4<<20+1))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, path, readErr
		}
		if closeErr != nil {
			return nil, path, closeErr
		}
		if len(data) > 4<<20 {
			return nil, path, fmt.Errorf("embedded production template too large: %s", name)
		}
		return data, "embedded:" + path, nil
	}
	return nil, path, fmt.Errorf("embedded production template %s missing", name)
}
