package dbmigrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedMigrationCatalogMatchesBackendBytes(t *testing.T) {
	migrations, err := List()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join("..", "..", "..", "services", "api", "internal", "dbmigrate", "sql")
	files, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := os.ReadFile(filepath.Join(source, "..", "migration_names.json"))
	if err != nil {
		t.Fatal(err)
	}
	var names map[string]string
	if err := json.Unmarshal(mapping, &names); err != nil {
		t.Fatal(err)
	}
	expected := make(map[string][]byte)
	for _, entry := range files {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		name := entry.Name()
		if historical, ok := names[name]; ok {
			name = historical
		}
		expected[name] = b
	}
	if len(migrations) != len(expected) || len(migrations) < 100 {
		t.Fatalf("Количество миграций CLI %d не совпадает с Backend %d", len(migrations), len(expected))
	}
	for _, migration := range migrations {
		b, ok := expected[migration.Version+".sql"]
		if !ok {
			t.Errorf("Миграция присутствует только в CLI: %s", migration.Version)
			continue
		}
		sum := sha256.Sum256(b)
		if migration.Checksum != hex.EncodeToString(sum[:]) || migration.SQL != string(b) {
			t.Errorf("Несоответствие контрольной суммы или байтов: %s", migration.Version)
		}
	}
}
