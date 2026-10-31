package httpapi

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"path/filepath"
	"strings"
	"testing"
)

// A SQLite HTTP repository must not silently start with an ephemeral limiter,
// an unmanaged Redis lease, or a second writer to the same SQLite file.
func TestSQLiteCoordinatorFailClosed0374(t *testing.T) {
	state := NewRuntimeState()
	cfg := config.Config{RepositoryDriver: "sqlite", DatabaseDSN: filepath.Join(t.TempDir(), "http.db")}
	if err := state.ConfigureProductRuntime(cfg); err == nil || !strings.Contains(err.Error(), "coordinator") {
		t.Fatalf("missing coordinator must fail closed: %v", err)
	}
	cfg.SQLiteCoordinatorPath = cfg.DatabaseDSN
	if err := state.ConfigureProductRuntime(cfg); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("overlapping writer locks must fail: %v", err)
	}
}
