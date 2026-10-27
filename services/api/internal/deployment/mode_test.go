package deployment

import (
	"path/filepath"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
)

func standardConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		Environment: "production", DeploymentMode: "auto", RepositoryDriver: "postgres", SQLDriver: "pgx",
		DatabaseDSN: "postgres://test.invalid/db", StorageDriver: "local", StorageLocalPath: filepath.Join(t.TempDir(), "storage"),
		SQLiteCoordinatorPath: "/var/lib/neverlauncher/coordinator.db", ServerBridgeHARequired: false,
		RateLimitEnabled: true, RateLimitFailClosed: true,
		RateLimitGlobalPerMinute: 1200, RateLimitAuthPerMinute: 20, RateLimitServerBridgePerMinute: 6000,
	}
}

func TestAutoDetectStandardAndNetworkHA(t *testing.T) {
	cfg := standardConfig(t)
	p, err := Detect(cfg)
	if err != nil || p.Mode != Standard || p.Coordinator != "sqlite" || !p.SingleInstance || !strings.HasSuffix(p.LockPath, ".neverlauncher-api.owner.lock") {
		t.Fatalf("standard plan=%+v error=%v", p, err)
	}
	cfg.SQLiteCoordinatorPath = ""
	cfg.StorageDriver = "s3"
	cfg.ServerBridgeHARequired = true
	cfg.RedisURL = "redis://redis.internal:6379"
	p, err = Detect(cfg)
	if err != nil || p.Mode != NetworkHA || p.Coordinator != "redis" || p.SingleInstance || p.LockPath != "" {
		t.Fatalf("HA plan=%+v error=%v", p, err)
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
		{"sqlite-only-not-wired", func(c *config.Config) { c.RepositoryDriver = "sqlite" }, "not implemented"},
		{"mixed-HA", func(c *config.Config) { c.ServerBridgeHARequired = true }, "distributed HA"},
		{"network-requires-s3", func(c *config.Config) { c.DeploymentMode = "network-ha" }, "shared S3"},
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
				t.Fatalf("got %v, expected %q", err, tc.fragment)
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
		t.Fatalf("must fail without lock: %v", err)
	}
	cfg.DeploymentLockPath = "/var/lib/neverlauncher/instance.lock"
	p, err := Detect(cfg)
	if err != nil || p.Mode != Standard || p.LockPath != cfg.DeploymentLockPath {
		t.Fatalf("plan=%+v error=%v", p, err)
	}
}

func TestDevelopmentMemoryHasNoProductionEscape(t *testing.T) {
	p, err := Detect(config.Config{Environment: "dev", RepositoryDriver: "memory"})
	if err != nil || p.Mode != Development {
		t.Fatalf("dev result=%+v err=%v", p, err)
	}
	_, err = Detect(config.Config{Environment: "production", RepositoryDriver: "memory"})
	if err == nil {
		t.Fatal("memory must fail in production")
	}
}

func TestDeveloperRelativeStorageStillHasExclusiveAbsoluteLock(t *testing.T) {
	cfg := standardConfig(t)
	cfg.Environment = "dev"
	cfg.StorageLocalPath = "./data/storage"
	p, err := Detect(cfg)
	if err != nil || !filepath.IsAbs(p.LockPath) || !p.SingleInstance {
		t.Fatalf("plan=%+v err=%v", p, err)
	}
}
