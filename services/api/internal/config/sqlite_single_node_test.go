package config

import (
	"strings"
	"testing"
)

func TestSingleNodeSQLiteProductionPolicy0327(t *testing.T) {
	cfg := Config{
		Environment: "production", RepositoryDriver: "postgres", SQLDriver: "pgx", DatabaseDSN: "postgres://user:pass@db:5432/launcher?sslmode=require",
		PublicURL: "https://api.example.com", AuthTokenSecret: "0123456789abcdef0123456789abcdef", StorageDriver: "local",
		StorageLocalPath: "/var/lib/launcher/storage", BackupRoot: "/var/lib/launcher/backups", ExtensionRoot: "/var/lib/launcher/extensions",
		ExtensionBackupRetention: 10, CORSAllowedOrigins: []string{"https://launcher.example.com"}, WebAuthnRPID: "example.com", WebAuthnRPName: "Launcher",
		WebAuthnOrigins: []string{"https://launcher.example.com"}, GuardReleaseAllowlistJSON: testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: testBridgeAllowlist0135,
		SQLiteCoordinatorPath:      "/var/lib/launcher/coord/state.db", RateLimitEnabled: true, RateLimitFailClosed: true,
		RateLimitGlobalPerMinute: 1200, RateLimitAuthPerMinute: 20, RateLimitServerBridgePerMinute: 6000,
	}
	// Explicit SQLite coordination does not require Redis when HA is disabled.
	if e := ValidateProduction(cfg); e != nil {
		t.Fatalf("single-node validation: %v", e)
	}
	cfg.ServerBridgeHARequired = true
	if e := ValidateProduction(cfg); e == nil || !strings.Contains(e.Error(), "SQLite single-node") {
		t.Fatalf("HA not rejected: %v", e)
	}
	cfg.ServerBridgeHARequired = false
	cfg.RateLimitFailClosed = false
	if e := ValidateProduction(cfg); e == nil {
		t.Fatal("fail-open must be rejected")
	}
	cfg.RateLimitFailClosed = true
	cfg.SQLiteCoordinatorPath = "./state.db"
	if e := ValidateProduction(cfg); e == nil {
		t.Fatal("relative SQLite path must be rejected")
	}
}

func TestProductionMinimalSQLiteAccepted0375(t *testing.T) {
	cfg := Config{
		Environment: "production", DeploymentMode: "single-node", RepositoryDriver: "sqlite",
		DatabaseDSN: "/var/lib/launcher/db/http.sqlite", SQLiteCoordinatorPath: "/var/lib/launcher/db/coord.sqlite",
		PublicURL: "https://api.example.com", AuthTokenSecret: "0123456789abcdef0123456789abcdef",
		StorageDriver: "local", StorageLocalPath: "/var/lib/launcher/storage", BackupRoot: "/var/lib/launcher/backups", ExtensionRoot: "/var/lib/launcher/extensions", ExtensionBackupRetention: 10,
		CORSAllowedOrigins: []string{"https://launcher.example.com"}, WebAuthnRPID: "example.com", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON: testGuardAllowlist0134, BridgeReleaseAllowlistJSON: testBridgeAllowlist0135,
		RateLimitEnabled: true, RateLimitFailClosed: true, RateLimitGlobalPerMinute: 1200, RateLimitAuthPerMinute: 20, RateLimitServerBridgePerMinute: 6000,
	}
	if err := ValidateProduction(cfg); err != nil {
		t.Fatalf("production minimal must accept verified SQLite-only topology: %v", err)
	}
	cfg.RedisURL = "redis://127.0.0.1:6379"
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("minimal must reject Redis")
	}
	cfg.RedisURL = ""
	cfg.DeploymentMode = "auto"
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("implicit SQLite production selection must fail")
	}
}
