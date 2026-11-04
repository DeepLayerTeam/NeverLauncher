package dbmigrate

import (
	"crypto/sha256"
	"encoding/hex"
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
	expected := make(map[string][]byte)
	for _, entry := range files {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		expected[entry.Name()] = b
	}
	if len(migrations) != len(expected) || len(migrations) < 100 {
		t.Fatalf("CLI migration count %d != backend %d", len(migrations), len(expected))
	}
	for _, migration := range migrations {
		b, ok := expected[migration.Version+".sql"]
		if !ok {
			t.Errorf("CLI-only migration: %s", migration.Version)
			continue
		}
		sum := sha256.Sum256(b)
		if migration.Checksum != hex.EncodeToString(sum[:]) || migration.SQL != string(b) {
			t.Errorf("checksum/bytes mismatch: %s", migration.Version)
		}
	}
}
