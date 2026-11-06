package config

import "testing"

const testGuardAllowlist0134 = `{"schemaVersion":"2.0","releases":{"0.14.0":{"protocolVersion":4,"platforms":{"windows":{"signingMode":"authenticode","artifacts":[{"guardSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","requireAuthenticode":true}]},"linux":{"signingMode":"integrity-only","artifacts":[{"guardSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"macos":{"signingMode":"developer-id-notarized","artifacts":[{"guardSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}}}}`
const testBridgeAllowlist0135 = `{"0.13.5":{"velocitySha256":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"paperSha256":["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"purpurSha256":["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]}}`

func TestValidateProductionRejectsUnsafeDefaults(t *testing.T) {
	cfg := Config{
		Environment:              "production",
		RepositoryDriver:         "postgres",
		SQLDriver:                "pgx",
		DatabaseDSN:              "postgres://user:pass@db:5432/launcher?sslmode=require",
		PublicURL:                "https://launcher.example.com",
		AuthTokenSecret:          "dev-only-change-me",
		StorageDriver:            "local",
		StorageLocalPath:         "/var/lib/launcher/storage",
		BackupRoot:               "/var/lib/launcher/storage/backups",
		ExtensionRoot:            "/var/lib/launcher/extensions",
		ExtensionBackupRetention: 10,
		CORSAllowedOrigins:       []string{"*"},
	}
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("небезопасная промышленная конфигурация должна быть отклонена")
	}
}

func TestValidateProductionAcceptsSeparatedRootsAndExplicitOrigins(t *testing.T) {
	cfg := Config{
		Environment:                "production",
		RepositoryDriver:           "postgres",
		SQLDriver:                  "pgx",
		DatabaseDSN:                "postgres://user:pass@db:5432/launcher?sslmode=require",
		PublicURL:                  "https://api.example.com",
		AuthTokenSecret:            "0123456789abcdef0123456789abcdef",
		StorageDriver:              "local",
		StorageLocalPath:           "/var/lib/launcher/storage",
		BackupRoot:                 "/var/lib/launcher/backups",
		ExtensionRoot:              "/var/lib/launcher/extensions",
		ExtensionBackupRetention:   10,
		CORSAllowedOrigins:         []string{"https://launcher.example.com"},
		WebAuthnRPID:               "example.com",
		WebAuthnRPName:             "Launcher",
		WebAuthnOrigins:            []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: testBridgeAllowlist0135,
	}
	if err := ValidateProduction(cfg); err != nil {
		t.Fatalf("Корректная промышленная конфигурация ошибочно отклонена: %v", err)
	}
}

func TestValidateE2EProductionAllowsOnlyLoopbackHTTP(t *testing.T) {
	cfg := Config{
		Environment:                "e2e-production",
		RepositoryDriver:           "postgres",
		SQLDriver:                  "pgx",
		DatabaseDSN:                "postgres://user:pass@db:5432/launcher?sslmode=disable",
		PublicURL:                  "http://127.0.0.1:18080",
		AuthTokenSecret:            "0123456789abcdef0123456789abcdef",
		StorageDriver:              "local",
		StorageLocalPath:           "/var/lib/launcher/storage",
		BackupRoot:                 "/var/lib/launcher/backups",
		ExtensionRoot:              "/var/lib/launcher/extensions",
		ExtensionBackupRetention:   10,
		CORSAllowedOrigins:         []string{"https://e2e.invalid"},
		WebAuthnRPID:               "127.0.0.1",
		WebAuthnRPName:             "Launcher E2E",
		WebAuthnOrigins:            []string{"http://127.0.0.1:18080"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: testBridgeAllowlist0135,
	}
	if err := ValidateProduction(cfg); err != nil {
		t.Fatalf("локальный HTTP должен разрешаться только для e2e-production: %v", err)
	}
	cfg.PublicURL = "http://example.test:18080"
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("HTTP не на локальном интерфейсе должен отклоняться для e2e-production")
	}
	cfg.Environment = "production"
	cfg.PublicURL = "http://127.0.0.1:18080"
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("локальный HTTP также должен отклоняться для обычной промышленной конфигурации")
	}
}

func TestValidateProductionRequiresCompleteBukkitFamilyAllowlist0144(t *testing.T) {
	base := Config{
		Environment:                "production",
		RepositoryDriver:           "postgres",
		SQLDriver:                  "pgx",
		DatabaseDSN:                "postgres://user:pass@db:5432/launcher?sslmode=require",
		PublicURL:                  "https://api.example.com",
		AuthTokenSecret:            "0123456789abcdef0123456789abcdef",
		StorageDriver:              "local",
		StorageLocalPath:           "/var/lib/launcher/storage",
		BackupRoot:                 "/var/lib/launcher/backups",
		ExtensionRoot:              "/var/lib/launcher/extensions",
		ExtensionBackupRetention:   10,
		CORSAllowedOrigins:         []string{"https://launcher.example.com"},
		WebAuthnRPID:               "example.com",
		WebAuthnRPName:             "Launcher",
		WebAuthnOrigins:            []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: `{"0.14.4":{"velocitySha256":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"paperSha256":["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"purpurSha256":["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]}}`,
	}
	if err := ValidateProduction(base); err == nil {
		t.Fatal("промышленная политика 0.14.4 без хешей Bukkit/Spigot/Folia должна быть отклонена")
	}
	base.BridgeReleaseAllowlistJSON = `{"0.14.4":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`
	if err := ValidateProduction(base); err != nil {
		t.Fatalf("полная политика релиза 0.14.4 семейства Bukkit отклонена: %v", err)
	}
}

func TestValidateProductionRequiresCompleteProxyFamilyAllowlist0145(t *testing.T) {
	base := Config{
		Environment:                "production",
		RepositoryDriver:           "postgres",
		SQLDriver:                  "pgx",
		DatabaseDSN:                "postgres://user:pass@db:5432/launcher?sslmode=require",
		PublicURL:                  "https://api.example.com",
		AuthTokenSecret:            "0123456789abcdef0123456789abcdef",
		StorageDriver:              "local",
		StorageLocalPath:           "/var/lib/launcher/storage",
		BackupRoot:                 "/var/lib/launcher/backups",
		ExtensionRoot:              "/var/lib/launcher/extensions",
		ExtensionBackupRetention:   10,
		CORSAllowedOrigins:         []string{"https://launcher.example.com"},
		WebAuthnRPID:               "example.com",
		WebAuthnRPName:             "Launcher",
		WebAuthnOrigins:            []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: `{"0.14.5":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`,
	}
	if err := ValidateProduction(base); err == nil {
		t.Fatal("промышленная политика 0.14.5 без хешей BungeeCord/Waterfall должна быть отклонена")
	}
	base.BridgeReleaseAllowlistJSON = `{"0.14.5":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`
	if err := ValidateProduction(base); err != nil {
		t.Fatalf("полная политика релиза 0.14.5 семейства прокси отклонена: %v", err)
	}
}

func TestValidateProductionRequiresFabricHash0146(t *testing.T) {
	base := Config{
		Environment: "production", RepositoryDriver: "postgres", SQLDriver: "pgx",
		DatabaseDSN: "postgres://user:pass@db/launcher", PublicURL: "https://launcher.example.com",
		AuthTokenSecret: "0123456789abcdef0123456789abcdef", StorageDriver: "local",
		StorageLocalPath: "/var/lib/launcher/storage", BackupRoot: "/var/lib/launcher/backups",
		ExtensionRoot:            "/var/lib/launcher/extensions",
		ExtensionBackupRetention: 10,
		CORSAllowedOrigins:       []string{"https://launcher.example.com"}, WebAuthnRPID: "example.com",
		WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: `{"0.14.6":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"]}}`,
	}
	if err := ValidateProduction(base); err == nil {
		t.Fatal("промышленная политика 0.14.6 без хеша Fabric должна быть отклонена")
	}
	base.BridgeReleaseAllowlistJSON = `{"0.14.6":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"],"fabricSha256":["9999999999999999999999999999999999999999999999999999999999999999"]}}`
	if err := ValidateProduction(base); err != nil {
		t.Fatalf("полная политика релиза 0.14.6 Fabric отклонена: %v", err)
	}
}

func TestValidateProductionRequiresForgeNeoForgeHashes0147(t *testing.T) {
	base := Config{
		Environment: "production", RepositoryDriver: "postgres", SQLDriver: "pgx",
		DatabaseDSN: "postgres://user:pass@db/launcher", PublicURL: "https://launcher.example.com",
		AuthTokenSecret: "0123456789abcdef0123456789abcdef", StorageDriver: "local",
		StorageLocalPath: "/var/lib/launcher/storage", BackupRoot: "/var/lib/launcher/backups",
		ExtensionRoot:            "/var/lib/launcher/extensions",
		ExtensionBackupRetention: 10,
		CORSAllowedOrigins:       []string{"https://launcher.example.com"}, WebAuthnRPID: "example.com",
		WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON:  testGuardAllowlist0134,
		BridgeReleaseAllowlistJSON: `{"0.14.7":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"],"fabricSha256":["9999999999999999999999999999999999999999999999999999999999999999"]}}`,
	}
	if err := ValidateProduction(base); err == nil {
		t.Fatal("промышленная политика 0.14.7 без хешей Forge/NeoForge должна быть отклонена")
	}
	base.BridgeReleaseAllowlistJSON = `{"0.14.7":{"velocitySha256":["1111111111111111111111111111111111111111111111111111111111111111"],"bungeeCordSha256":["7777777777777777777777777777777777777777777777777777777777777777"],"waterfallSha256":["8888888888888888888888888888888888888888888888888888888888888888"],"bukkitSha256":["2222222222222222222222222222222222222222222222222222222222222222"],"spigotSha256":["3333333333333333333333333333333333333333333333333333333333333333"],"paperSha256":["4444444444444444444444444444444444444444444444444444444444444444"],"purpurSha256":["5555555555555555555555555555555555555555555555555555555555555555"],"foliaSha256":["6666666666666666666666666666666666666666666666666666666666666666"],"fabricSha256":["9999999999999999999999999999999999999999999999999999999999999999"],"forgeSha256":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"neoforgeSha256":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}}`
	if err := ValidateProduction(base); err != nil {
		t.Fatalf("полная политика релиза 0.14.7 Forge/NeoForge отклонена: %v", err)
	}
}

func TestValidateProductionServerBridgeHA01911RequiresRedisAndFailClosedPolicy(t *testing.T) {
	cfg := Config{
		Environment: "production", RepositoryDriver: "postgres", SQLDriver: "pgx",
		DatabaseDSN: "postgres://user:pass@db:5432/launcher?sslmode=require", PublicURL: "https://api.example.com",
		AuthTokenSecret: "0123456789abcdef0123456789abcdef", StorageDriver: "local", StorageLocalPath: "/var/lib/launcher/storage", BackupRoot: "/var/lib/launcher/backups",
		ExtensionRoot:            "/var/lib/launcher/extensions",
		ExtensionBackupRetention: 10,
		CORSAllowedOrigins:       []string{"https://launcher.example.com"}, WebAuthnRPID: "example.com", WebAuthnRPName: "Launcher", WebAuthnOrigins: []string{"https://launcher.example.com"},
		GuardReleaseAllowlistJSON: testGuardAllowlist0134, BridgeReleaseAllowlistJSON: testBridgeAllowlist0135,
		ServerBridgeHARequired: true, ServerBridgeReplicaID: "api-a", RedisURL: "redis://redis:6379/0",
		RateLimitEnabled: true, RateLimitFailClosed: true, RateLimitGlobalPerMinute: 1200, RateLimitAuthPerMinute: 20, RateLimitServerBridgePerMinute: 6000,
	}
	if err := ValidateProduction(cfg); err != nil {
		t.Fatalf("Корректная промышленная политика HA ошибочно отклонена: %v", err)
	}
	cfg.RedisURL = ""
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("промышленная конфигурация высокой доступности без Redis должна быть отклонена")
	}
	cfg.RedisURL = "redis://redis:6379/0"
	cfg.ServerBridgeHARequired = false
	if err := ValidateProduction(cfg); err == nil {
		t.Fatal("идентичность реплики без обязательной политики высокой доступности должна быть отклонена")
	}
}
