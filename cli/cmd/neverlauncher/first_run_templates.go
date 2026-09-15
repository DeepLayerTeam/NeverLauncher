package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// productionTemplates contains the exact canonical production deployment files
// so an installed nl binary can create a standalone first-run directory without
// depending on a source checkout.
//
//go:embed templates/production/*
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
		return nil, path, fmt.Errorf("embedded production template %s: %w", name, err)
	}
	return data, "embedded:" + path, nil
}
