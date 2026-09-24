package config

import "testing"

const testGuardAllowlist0134 = `{"schemaVersion":"2.0","releases":{"0.14.0":{"protocolVersion":4,"platforms":{"windows":{"signingMode":"authenticode","artifacts":[{"guardSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","requireAuthenticode":true}]},"linux":{"signingMode":"integrity-only","artifacts":[{"guardSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"macos":{"signingMode":"developer-id-notarized","artifacts":[{"guardSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}}}}`
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

func TestValidateProductionRequiresCompleteBukkitFamilyAllowlist0144(t *testing.T) {
	base := Config{
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
		BridgeReleaseAllowlistJSON: `{"0.14.4":{"velocitySha256":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"paperSha256":["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"purpurSha256":["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]}}`,
	}
	if err := ValidateProduction(base); err == nil {
		t.Fatal("0.14.4 production policy without Bukkit/Spigot/Folia hashes must be rejected")
	}
	base.BridgeReleaseAllowlistJSON = `{"0.14.4":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`
	if err := ValidateProduction(base); err != nil {
		t.Fatalf("complete 0.14.4 Bukkit-family release policy rejected: %v", err)
	}
}

func TestValidateProductionRequiresCompleteProxyFamilyAllowlist0145(t *testing.T) {
	base := Config{
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
		BridgeReleaseAllowlistJSON: `{"0.14.5":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`,
	}
	if err := ValidateProduction(base); err == nil {
		t.Fatal("0.14.5 production policy without BungeeCord/Waterfall hashes must be rejected")
	}
	base.BridgeReleaseAllowlistJSON = `{"0.14.5":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`
	if err := ValidateProduction(base); err != nil {
		t.Fatalf("complete 0.14.5 proxy-family release policy rejected: %v", err)
	}
}

func TestValidateProductionRequiresFabricHash0146(t *testing.T) {
	base := Config{
		Environment: "production", RepositoryDriver: "postgres", SQLDriver: "pgx",
		DatabaseDSN: "postgres://user:pass@db/neverlauncher", PublicURL: "https://launcher.example.com",
		AuthTokenSecret: "0123456789abcdef0123456789abcdef", StorageDriver: "local",
		StorageLocalPath: "/var/lib/neverlauncher/storage", BackupRoot: "/var/lib/neverlauncher/backups",
		CORSAllowedOrigins: []string{"https://launcher.example.com"}, WebAuthnRPID: "example.com",
		WebAuthnRPName: "NeverLauncher", WebAuthnOrigins: []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: `{"0.14.6":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`,
	}
	if err := ValidateProduction(base); err == nil {
		t.Fatal("0.14.6 production policy without Fabric hash must be rejected")
	}
	base.BridgeReleaseAllowlistJSON = `{"0.14.6":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"],"fabricSha256":["9999999999999999999999999999999999999999999999999999999999999999"]}}`
	if err := ValidateProduction(base); err != nil {
		t.Fatalf("complete 0.14.6 Fabric release policy rejected: %v", err)
	}
}
