package deployment

import (
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
)

func TestMinimalDeployment0375(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{Environment: "production", DeploymentMode: "single-node", RepositoryDriver: "sqlite", DatabaseDSN: filepath.Join(root, "db", "http.sqlite"), SQLiteCoordinatorPath: filepath.Join(root, "db", "coordinator.sqlite"), StorageDriver: "local", StorageLocalPath: filepath.Join(root, "storage"), RateLimitEnabled: true, RateLimitFailClosed: true, RateLimitGlobalPerMinute: 1200, RateLimitAuthPerMinute: 20, RateLimitServerBridgePerMinute: 6000}
	plan, err := Detect(cfg)
	if err != nil || plan.Mode != SingleNode || !plan.SingleInstance || !strings.HasSuffix(plan.LockPath, ".launcher-api.owner.lock") {
		t.Fatalf("План=%+v, ошибка=%v", plan, err)
	}
	owner, err := Acquire(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Acquire(plan); err == nil {
		t.Fatal("Два процесса API получили одну блокировку владельца")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := Acquire(plan)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	cfg.ServerBridgeHARequired = true
	if _, err = Detect(cfg); err == nil {
		t.Fatal("Ошибочно принята распределённая высокая доступность")
	}
	cfg.ServerBridgeHARequired = false
	cfg.RedisURL = "redis://localhost:6379"
	if _, err = Detect(cfg); err == nil {
		t.Fatal("Redis принят в минимальном режиме")
	}
	cfg.RedisURL = ""
	cfg.DatabaseDSN = cfg.SQLiteCoordinatorPath
	if _, err = Detect(cfg); err == nil {
		t.Fatal("Одна БД SQLite используется для репозитория и координатора")
	}
}
