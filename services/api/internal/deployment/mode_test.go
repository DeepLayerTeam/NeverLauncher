package deployment

import (
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
)

func standardConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		Environment: "production", DeploymentMode: "auto", RepositoryDriver: "postgres", SQLDriver: "pgx",
		DatabaseDSN: "postgres://test.invalid/db", StorageDriver: "local", StorageLocalPath: filepath.Join(t.TempDir(), "storage"),
		SQLiteCoordinatorPath: "/var/lib/launcher/coordinator.db", ServerBridgeHARequired: false,
		RateLimitEnabled: true, RateLimitFailClosed: true,
		RateLimitGlobalPerMinute: 1200, RateLimitAuthPerMinute: 20, RateLimitServerBridgePerMinute: 6000,
	}
}

func TestAutoDetectStandardAndNetworkHA(t *testing.T) {
	cfg := standardConfig(t)
	p, err := Detect(cfg)
	if err != nil || p.Mode != Standard || p.Coordinator != "sqlite" || !p.SingleInstance || !strings.HasSuffix(p.LockPath, ".launcher-api.owner.lock") {
		t.Fatalf("Стандартный план=%+v, ошибка=%v", p, err)
	}
	cfg.SQLiteCoordinatorPath = ""
	cfg.StorageDriver = "s3"
	cfg.ServerBridgeHARequired = true
	cfg.RedisURL = "redis://redis.internal:6379"
	cfg.ServerBridgeReplicaID = "api-a"
	p, err = Detect(cfg)
	if err != nil || p.Mode != NetworkHA || p.Coordinator != "redis" || p.SingleInstance || p.LockPath != "" {
		t.Fatalf("План высокой доступности=%+v, ошибка=%v", p, err)
	}
}

func TestExplicitModeRejectsUnsafeCombinations(t *testing.T) {
	cfg := standardConfig(t)
	tests := []struct {
		name     string
		mutate   func(*config.Config)
		fragment string
	}{
		{"unsupported", func(c *config.Config) { c.DeploymentMode = "bogus" }, "unsupported"},
		{"not-standalone", func(c *config.Config) { c.DeploymentMode = "single-node" }, "SQLite HTTP repository"},
		{"sqlite-requires-persistent-path", func(c *config.Config) { c.RepositoryDriver = "sqlite" }, "absolute clean persistent path"},
		{"mixed-HA", func(c *config.Config) { c.ServerBridgeHARequired = true }, "distributed HA"},
		{"network-requires-s3", func(c *config.Config) { c.DeploymentMode = "network-ha" }, "shared S3"},
		{"network-requires-stable-replica-id", func(c *config.Config) {
			c.DeploymentMode = "network-ha"
			c.SQLiteCoordinatorPath = ""
			c.StorageDriver = "s3"
			c.ServerBridgeHARequired = true
			c.RedisURL = "redis://redis.internal:6379"
		}, "LAUNCHER_REPLICA_ID"},
		{"network-rejects-unsafe-replica-id", func(c *config.Config) {
			c.DeploymentMode = "network-ha"
			c.SQLiteCoordinatorPath = ""
			c.StorageDriver = "s3"
			c.ServerBridgeHARequired = true
			c.RedisURL = "redis://redis.internal:6379"
			c.ServerBridgeReplicaID = "api/a"
		}, "stable non-whitespace"},
		{"network-requires-redis", func(c *config.Config) {
			c.DeploymentMode = "network-ha"
			c.StorageDriver = "s3"
			c.SQLiteCoordinatorPath = ""
			c.ServerBridgeHARequired = true
			c.RedisURL = ""
		}, "requires Redis"},
		{"fail-open", func(c *config.Config) { c.RateLimitFailClosed = false }, "fail-closed"},
		{"disabled-limit", func(c *config.Config) { c.RateLimitEnabled = false }, "fail-closed"},
		{"override-local", func(c *config.Config) { c.DeploymentLockPath = "/tmp/alternate.lock" }, "cannot be overridden"},
		{"unsupported-repo", func(c *config.Config) { c.RepositoryDriver = "magic" }, "unsupported"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			tc.mutate(&c)
			_, err := Detect(c)
			if err == nil || !strings.Contains(err.Error(), tc.fragment) {
				t.Fatalf("Получено %v, ожидалось %q", err, tc.fragment)
			}
		})
	}
}

func TestStandardS3RequiresSharedExplicitLock(t *testing.T) {
	cfg := standardConfig(t)
	cfg.StorageDriver = "s3"
	cfg.SQLiteCoordinatorPath = ""
	cfg.RedisURL = "redis://redis:6379"
	_, err := Detect(cfg)
	if err == nil || !strings.Contains(err.Error(), "LOCK_PATH") {
		t.Fatalf("Без блокировки операция должна завершиться ошибкой: %v", err)
	}
	cfg.DeploymentLockPath = "/var/lib/launcher/instance.lock"
	p, err := Detect(cfg)
	if err != nil || p.Mode != Standard || p.LockPath != cfg.DeploymentLockPath {
		t.Fatalf("План=%+v, ошибка=%v", p, err)
	}
}

func TestDevelopmentMemoryHasNoProductionEscape(t *testing.T) {
	p, err := Detect(config.Config{Environment: "dev", RepositoryDriver: "memory"})
	if err != nil || p.Mode != Development {
		t.Fatalf("Результат разработки=%+v, ошибка=%v", p, err)
	}
	_, err = Detect(config.Config{Environment: "production", RepositoryDriver: "memory"})
	if err == nil {
		t.Fatal("Режим в памяти должен быть запрещён в производственной среде")
	}
}

func TestDeveloperRelativeStorageStillHasExclusiveAbsoluteLock(t *testing.T) {
	cfg := standardConfig(t)
	cfg.Environment = "dev"
	cfg.StorageLocalPath = "./data/storage"
	p, err := Detect(cfg)
	if err != nil || !filepath.IsAbs(p.LockPath) || !p.SingleInstance {
		t.Fatalf("План=%+v, ошибка=%v", p, err)
	}
}
