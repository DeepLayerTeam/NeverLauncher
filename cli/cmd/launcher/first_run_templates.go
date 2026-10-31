package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// productionTemplates содержит точные канонические файлы производственного
// развёртывания, чтобы установленный бинарный файл nl мог создать
// самостоятельный каталог первого запуска без исходного репозитория.
//
//go:embed templates/production/*
var productionTemplates embed.FS

func readCanonicalProductionTemplate(name string) ([]byte, string, error) {
	if override := strings.TrimSpace(os.Getenv("LAUNCHER_PRODUCTION_TEMPLATE_DIR")); override != "" {
		path := filepath.Join(filepath.Clean(override), name)
		data, err := os.ReadFile(path)
		return data, path, err
	}
	path := "templates/production/" + name
	data, err := productionTemplates.ReadFile(path)
	if err != nil {
		return nil, path, fmt.Errorf("embedded production template %s: %w", name, err)
	}
	return data, "embedded:" + path, nil
}
