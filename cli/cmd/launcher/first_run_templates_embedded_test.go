package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedProductionTemplatesFromCanonicalSource(t *testing.T) {
	t.Setenv("LAUNCHER_PRODUCTION_TEMPLATE_DIR", "")
	for _, name := range []string{"docker-compose.yml", "nginx.conf", "env.production.example"} {
		got, source, err := readCanonicalProductionTemplate(name)
		if err != nil {
			t.Fatalf("встроенный ресурс %s: %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "production", name))
		if err != nil {
			t.Fatalf("эталонный ресурс %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Встроенный %s отличается от эталона", name)
		}
		if !strings.HasPrefix(source, "embedded:") {
			t.Errorf("Неожиданный источник: %s", source)
		}
	}
	if _, _, err := readCanonicalProductionTemplate("../VERSION"); err == nil {
		t.Fatal("Произвольный относительный путь принят как производственный шаблон")
	}
}
