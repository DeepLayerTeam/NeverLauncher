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
			t.Fatalf("embedded %s: %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "production", name))
		if err != nil {
			t.Fatalf("canonical %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("embedded %s differs from canonical", name)
		}
		if !strings.HasPrefix(source, "embedded:") {
			t.Errorf("unexpected source %s", source)
		}
	}
	if _, _, err := readCanonicalProductionTemplate("../VERSION"); err == nil {
		t.Fatal("arbitrary relative path accepted as production template")
	}
}
