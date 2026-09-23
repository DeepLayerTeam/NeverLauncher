package config

import "testing"

const testGuardAllowlist0134 = `{"0.13.4":{"guardSha256":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"launcherSha256":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"requireAuthenticode":false}}`
const testBridgeAllowlist0135 = `{"0.13.5":{"velocitySha256":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"paperSha256":["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"purpurSha256":["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]}}`

func TestValidateProductionRejectsUnsafeDefaults(t *testing.T) {
	cfg := Config{
		Environment:        "production",
		RepositoryDriver:   "postgres",
		SQLDriver:          "pgx",
		DatabaseDSN:        "postgres://user:pass@db:5432/neverlauncher?sslmode=require",
		PublicURL:          "https://launcher.example.com",
		AuthTokenSecret:    "dev-only-change-me",
		StorageDriver:      "local",
		StorageLocalPath:   "/var/lib/neverlauncher/storage",
		BackupRoot:         "/var/lib/neverlauncher/storage/backups",
		CORSAllowedOrigins: []string{"*"},
	}
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("unsafe production configuration must be rejected")
	}
}

func TestValidateProductionAcceptsSeparatedRootsAndExplicitOrigins(t *testing.T) {
	cfg := Config{
		Environment:                "production",
		RepositoryDriver:           "postgres",
		SQLDriver:                  "pgx",
		DatabaseDSN:                "postgres://user:pass@db:5432/neverlauncher?sslmode=require",
		PublicURL:                  "https://api.example.com",
		AuthTokenSecret:            "0123456789abcdef0123456789abcdef",
		StorageDriver:              "local",
		StorageLocalPath:           "/var/lib/neverlauncher/storage",
		BackupRoot:                 "/var/lib/neverlauncher/backups",
		CORSAllowedOrigins:         []string{"https://launcher.example.com"},
		WebAuthnRPID:               "example.com",
		WebAuthnRPName:             "NeverLauncher",
		WebAuthnOrigins:            []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: testBridgeAllowlist0135,
	}
	if err := ValidateProduction(cfg); err != nil {
		t.Fatalf("valid production configuration rejected: %v", err)
	}
}

func TestValidateE2EProductionAllowsOnlyLoopbackHTTP(t *testing.T) {
	cfg := Config{
		Environment:                "e2e-production",
		RepositoryDriver:           "postgres",
		SQLDriver:                  "pgx",
		DatabaseDSN:                "postgres://user:pass@db:5432/neverlauncher?sslmode=disable",
		PublicURL:                  "http://127.0.0.1:18080",
		AuthTokenSecret:            "0123456789abcdef0123456789abcdef",
		StorageDriver:              "local",
		StorageLocalPath:           "/var/lib/neverlauncher/storage",
		BackupRoot:                 "/var/lib/neverlauncher/backups",
		CORSAllowedOrigins:         []string{"https://e2e.invalid"},
		WebAuthnRPID:               "127.0.0.1",
		WebAuthnRPName:             "NeverLauncher E2E",
		WebAuthnOrigins:            []string{"http://127.0.0.1:18080"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: testBridgeAllowlist0135,
	}
	if err := ValidateProduction(cfg); err != nil {
		t.Fatalf("loopback HTTP must be accepted only for e2e-production: %v", err)
	}
	cfg.PublicURL = "http://example.test:18080"
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("non-loopback HTTP must be rejected for e2e-production")
	}
	cfg.Environment = "production"
	cfg.PublicURL = "http://127.0.0.1:18080"
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("loopback HTTP must still be rejected for regular production")
	}
}
