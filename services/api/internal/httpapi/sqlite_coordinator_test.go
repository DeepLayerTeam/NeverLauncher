package httpapi

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"path/filepath"
	"strings"
	"testing"
)

// HTTP-репозиторий SQLite не должен незаметно запускаться с эфемерным
// ограничителем, неконтролируемой арендой Redis или вторым писателем в тот же
// SQLite-файл.
func TestSQLiteCoordinatorFailClosed0374(t *testing.T) {
	state := NewRuntimeState()
	cfg := config.Config{RepositoryDriver: "sqlite", DatabaseDSN: filepath.Join(t.TempDir(), "http.db")}
	if err := state.ConfigureProductRuntime(cfg); err == nil || !strings.Contains(err.Error(), "coordinator") {
		t.Fatalf("При отсутствии координатора операция должна блокироваться: %v", err)
	}
	cfg.SQLiteCoordinatorPath = cfg.DatabaseDSN
	if err := state.ConfigureProductRuntime(cfg); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("Пересекающиеся блокировки записи должны приводить к отказу: %v", err)
	}
}
