package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// productionTemplates содержит точный канонический рабочее развёртывание файлы
// так установленный nl бинарный файл может создавать автономный первый запуск каталог без
// depending на исходник checkout.
//
//Go:embed templates/production/*
var productionTemplates embed.FS

func readCanonicalProductionTemplate(name string) ([]byte, string, error) {
	if override := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_PRODUCTION_TEMPLATE_DIR")); override != "" {
		path := filepath.Join(filepath.Clean(override), name)
		data, err := os.ReadFile(path)
		return data, path, err
	}
	path := "templates/production/" + name
	data, err := productionTemplates.ReadFile(path)
	if err != nil {
		return nil, path, fmt.Errorf("встроенный рабочий template %s: %w", name, err)
	}
	return data, "embedded:" + path, nil
}
