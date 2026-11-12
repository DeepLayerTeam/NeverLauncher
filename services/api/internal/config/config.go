package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config содержит настройки Backend API.
type Config struct {
	HTTPAddr                                     string
	PublicURL                                    string
	MinecraftMicrosoftClientID                   string
	YggdrasilSigningKeyFile                      string
	YggdrasilTextureDomains                      []string
	DatabaseDSN                                  string
	RepositoryDriver                             string
	SQLDriver                                    string
	RedisAddr                                    string
	RedisURL                                     string
	SQLiteCoordinatorPath                        string
	DeploymentMode                               string
	DeploymentLockPath                           string
	ServerBridgeHARequired                       bool
	ServerBridgeReplicaID                        string
	TrustedProxyCIDRs                            []string
	RateLimitEnabled                             bool
	RateLimitGlobalPerMinute                     int
	RateLimitAuthPerMinute                       int
	RateLimitServerBridgePerMinute               int
	RateLimitFailClosed                          bool
	StorageDriver                                string
	StorageLocalPath                             string
	StorageS3Endpoint                            string
	StorageS3Bucket                              string
	StorageS3Region                              string
	StorageS3AccessKey                           string
	StorageS3SecretKey                           string
	StorageS3PublicURL                           string
	StorageS3PathStyle                           bool
	StorageDeliveryMode                          string
	StorageCDNOrigin                             string
	StorageMaxUploadBytes                        int64
	BackupRoot                                   string
	ExtensionRoot                                string
	ExtensionBackupRetention                     int
	ExtensionHostEnabled                         bool
	ExtensionHostListen                          string
	ExtensionHostStartupTimeoutSeconds           int
	ExtensionHostHeartbeatTimeoutSeconds         int
	ExtensionHostStopTimeoutSeconds              int
	ExtensionHostCapabilityTimeoutSeconds        int
	ExtensionHostMaxMemoryMB                     int64
	ExtensionHostMaxProcesses                    int
	ExtensionHostMaxLogBytes                     int64
	ExtensionHostMaxLogEntries                   int
	ExtensionHostMaxProtocolBodyBytes            int64
	ExtensionHostMaxStorageReadBytes             int64
	ExtensionHostCrashLimit                      int
	ExtensionHostCrashWindowSeconds              int
	ExtensionHostRestartBackoffMilliseconds      int
	ExtensionSecretsKey                          string
	ExtensionHTTPMaxRequestBytes                 int64
	ExtensionHTTPMaxResponseBytes                int64
	ExtensionHTTPTimeoutSeconds                  int
	ExtensionEventsEnabled                       bool
	ExtensionEventsWorkerIntervalMilliseconds    int
	ExtensionEventsLeaseSeconds                  int
	ExtensionEventsHookTimeoutMilliseconds       int
	ExtensionEventsMaxAttempts                   int
	ExtensionEventsBaseRetryMilliseconds         int
	ExtensionEventsMaxRetrySeconds               int
	ExtensionEventsBatchSize                     int
	CORSAllowedOrigins                           []string
	Environment                                  string
	AuthTokenSecret                              string
	ValidationAttestationPublicKey0345           string
	ValidationTrustedRunnerImageSHA2560345       string
	ValidationRequiredTargetsJSON0346            string
	AuthTokenTTLHours                            int
	AuthTokenIssuer                              string
	AuthTokenAudience                            string
	AuthTokenActiveKID                           string
	AuthTokenKeysJSON                            string
	GuardReleaseAllowlistJSON                    string
	BridgeReleaseAllowlistJSON                   string
	MetricsEnabled                               bool
	PersistentSessions                           bool
	RequirePersistentStoreInProduction           bool
	DatabaseAutoMigrate                          bool
	BootstrapToken                               string
	ManifestSigningPrivateKey                    string
	RuntimeValidationKeysJSON                    string
	ServerBridgeHostTargetsFile0413              string
	ServerBridgeControlSigningPrivateKey         string
	ServerBridgeControlPreviousSigningPrivateKey string
	AuthRoutingJSON                              string
	AuthRoutingFile                              string
	AuthSQLProvidersJSON                         string
	AuthSQLProvidersFile                         string
	AuthFileProvidersJSON                        string
	AuthFileProvidersFile                        string
	AuthHTTPProvidersJSON                        string
	AuthHTTPProvidersFile                        string
	AuthOIDCProvidersJSON                        string
	AuthOIDCProvidersFile                        string
	AuthMicrosoftProvidersJSON                   string
	AuthMicrosoftProvidersFile                   string
	WebAuthnRPID                                 string
	WebAuthnRPName                               string
	WebAuthnOrigins                              []string
}

func bridgeReleaseRequiresBukkitFamily0144(version string) bool {
	var major, minor, patch int
	if _, err := fmt.Sscanf(strings.TrimSpace(strings.SplitN(version, "-", 2)[0]), "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	if major != 0 {
		return major > 0
	}
	if minor != 14 {
		return minor > 14
	}
	return patch >= 4
}

func bridgeReleaseRequiresProxyFamily0145(version string) bool {
	var major, minor, patch int
	if _, err := fmt.Sscanf(strings.TrimSpace(strings.SplitN(version, "-", 2)[0]), "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	if major != 0 {
		return major > 0
	}
	if minor != 14 {
		return minor > 14
	}
	return patch >= 5
}

func bridgeReleaseRequiresFabric0146(version string) bool {
	var major, minor, patch int
	if _, err := fmt.Sscanf(strings.TrimSpace(strings.SplitN(version, "-", 2)[0]), "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	if major != 0 {
		return major > 0
	}
	if minor != 14 {
		return minor > 14
	}
	return patch >= 6
}

func bridgeReleaseRequiresForgeFamily0147(version string) bool {
	var major, minor, patch int
	if _, err := fmt.Sscanf(strings.TrimSpace(strings.SplitN(version, "-", 2)[0]), "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	if major != 0 {
		return major > 0
	}
	if minor != 14 {
		return minor > 14
	}
	return patch >= 7
}

func bridgeReleaseRequiresUniversalAdapters0198(version string) bool {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	if major > 0 {
		return true
	}
	if minor > 19 {
		return true
	}
	if minor < 19 || len(parts) < 3 {
		return false
	}
	patchPart := strings.SplitN(parts[2], "-", 2)[0]
	patch, err := strconv.Atoi(patchPart)
	return err == nil && patch >= 8
}

// Load читает конфигурацию из переменных окружения.
func Load() Config {
	environment := env("LAUNCHER_ENV", "dev")
	redisAddr := normalizeRedisAddr(env("LAUNCHER_REDIS_ADDR", env("LAUNCHER_REDIS_URL", "localhost:6379")))
	redisURL := env("LAUNCHER_REDIS_URL", "")
	if redisURL == "" && !strings.EqualFold(strings.TrimSpace(env("LAUNCHER_REPOSITORY_DRIVER", "postgres")), "sqlite") {
		redisURL = "redis://" + redisAddr + "/0"
	}
	production := IsProductionEnvironment(environment)
	manifestSigningPrivateKey := env("LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY", "")
	serverBridgeControlSigningPrivateKey := env("LAUNCHER_SERVERBRIDGE_CONTROL_SIGNING_PRIVATE_KEY", manifestSigningPrivateKey)
	serverBridgeControlPreviousSigningPrivateKey := env("LAUNCHER_SERVERBRIDGE_CONTROL_PREVIOUS_SIGNING_PRIVATE_KEY", "")
	publicURL := env("LAUNCHER_PUBLIC_URL", "http://localhost:8080")
	webauthnRPID, webauthnOrigin := defaultWebAuthnScope(publicURL)
	corsFallback := "http://localhost:5173,http://127.0.0.1:5173"
	if production {
		corsFallback = ""
	}
	return Config{
		HTTPAddr:                                     env("LAUNCHER_HTTP_ADDR", "0.0.0.0:8080"),
		PublicURL:                                    publicURL,
		MinecraftMicrosoftClientID:                   env("LAUNCHER_MINECRAFT_MICROSOFT_CLIENT_ID", ""),
		YggdrasilSigningKeyFile:                      env("LAUNCHER_YGGDRASIL_RSA_KEY_FILE", ""),
		YggdrasilTextureDomains:                      envCSV("LAUNCHER_YGGDRASIL_TEXTURE_DOMAINS"),
		DatabaseDSN:                                  env("LAUNCHER_DATABASE_DSN", env("LAUNCHER_DATABASE_URL", "postgres://launcher:launcher@localhost:5432/launcher?sslmode=disable")),
		RepositoryDriver:                             env("LAUNCHER_REPOSITORY_DRIVER", "postgres"),
		SQLDriver:                                    env("LAUNCHER_SQL_DRIVER", "pgx"),
		RedisAddr:                                    redisAddr,
		RedisURL:                                     redisURL,
		SQLiteCoordinatorPath:                        env("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", ""),
		DeploymentMode:                               env("LAUNCHER_DEPLOYMENT_MODE", "auto"),
		DeploymentLockPath:                           env("LAUNCHER_DEPLOYMENT_LOCK_PATH", ""),
		ServerBridgeHARequired:                       envBool("LAUNCHER_SERVERBRIDGE_HA_REQUIRED", production && env("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", "") == ""),
		ServerBridgeReplicaID:                        env("LAUNCHER_REPLICA_ID", ""),
		TrustedProxyCIDRs:                            envCSV("LAUNCHER_TRUSTED_PROXY_CIDRS"),
		RateLimitEnabled:                             envBool("LAUNCHER_RATE_LIMIT_ENABLED", true),
		RateLimitGlobalPerMinute:                     envInt("LAUNCHER_RATE_LIMIT_GLOBAL_PER_MINUTE", 1200),
		RateLimitAuthPerMinute:                       envInt("LAUNCHER_RATE_LIMIT_AUTH_PER_MINUTE", 20),
		RateLimitServerBridgePerMinute:               envInt("LAUNCHER_RATE_LIMIT_SERVERBRIDGE_PER_MINUTE", 6000),
		RateLimitFailClosed:                          envBool("LAUNCHER_RATE_LIMIT_FAIL_CLOSED", production),
		StorageDriver:                                env("LAUNCHER_STORAGE_DRIVER", "local"),
		StorageLocalPath:                             env("LAUNCHER_STORAGE_LOCAL_PATH", env("LAUNCHER_STORAGE_LOCAL_ROOT", "./data/storage")),
		StorageS3Endpoint:                            env("LAUNCHER_STORAGE_S3_ENDPOINT", ""),
		StorageS3Bucket:                              env("LAUNCHER_STORAGE_S3_BUCKET", ""),
		StorageS3Region:                              env("LAUNCHER_STORAGE_S3_REGION", "ru-central1"),
		StorageS3AccessKey:                           env("LAUNCHER_STORAGE_S3_ACCESS_KEY", ""),
		StorageS3SecretKey:                           env("LAUNCHER_STORAGE_S3_SECRET_KEY", ""),
		StorageS3PublicURL:                           env("LAUNCHER_STORAGE_S3_PUBLIC_URL", ""),
		StorageS3PathStyle:                           envBool("LAUNCHER_STORAGE_S3_PATH_STYLE", true),
		StorageDeliveryMode:                          env("LAUNCHER_STORAGE_DELIVERY_MODE", "reverse-proxy"),
		StorageCDNOrigin:                             env("LAUNCHER_STORAGE_CDN_ORIGIN", ""),
		StorageMaxUploadBytes:                        envInt64("LAUNCHER_STORAGE_MAX_UPLOAD_BYTES", 512<<20),
		BackupRoot:                                   env("LAUNCHER_BACKUP_ROOT", "./data/backups"),
		ExtensionRoot:                                env("LAUNCHER_EXTENSION_ROOT", "./data/extensions"),
		ExtensionBackupRetention:                     envInt("LAUNCHER_EXTENSION_BACKUP_RETENTION", 10),
		ExtensionHostEnabled:                         envBool("LAUNCHER_EXTENSION_HOST_ENABLED", true),
		ExtensionHostListen:                          env("LAUNCHER_EXTENSION_HOST_LISTEN", "127.0.0.1:0"),
		ExtensionHostStartupTimeoutSeconds:           envInt("LAUNCHER_EXTENSION_HOST_STARTUP_TIMEOUT_SECONDS", 10),
		ExtensionHostHeartbeatTimeoutSeconds:         envInt("LAUNCHER_EXTENSION_HOST_HEARTBEAT_TIMEOUT_SECONDS", 30),
		ExtensionHostStopTimeoutSeconds:              envInt("LAUNCHER_EXTENSION_HOST_STOP_TIMEOUT_SECONDS", 5),
		ExtensionHostCapabilityTimeoutSeconds:        envInt("LAUNCHER_EXTENSION_HOST_CAPABILITY_TIMEOUT_SECONDS", 3),
		ExtensionHostMaxMemoryMB:                     envInt64("LAUNCHER_EXTENSION_HOST_MAX_MEMORY_MB", 512),
		ExtensionHostMaxProcesses:                    envInt("LAUNCHER_EXTENSION_HOST_MAX_PROCESSES", 8),
		ExtensionHostMaxLogBytes:                     envInt64("LAUNCHER_EXTENSION_HOST_MAX_LOG_BYTES", 4<<20),
		ExtensionHostMaxLogEntries:                   envInt("LAUNCHER_EXTENSION_HOST_MAX_LOG_ENTRIES", 1000),
		ExtensionHostMaxProtocolBodyBytes:            envInt64("LAUNCHER_EXTENSION_HOST_MAX_PROTOCOL_BODY_BYTES", 1<<20),
		ExtensionHostMaxStorageReadBytes:             envInt64("LAUNCHER_EXTENSION_HOST_MAX_STORAGE_READ_BYTES", 1<<20),
		ExtensionHostCrashLimit:                      envInt("LAUNCHER_EXTENSION_HOST_CRASH_LIMIT", 5),
		ExtensionHostCrashWindowSeconds:              envInt("LAUNCHER_EXTENSION_HOST_CRASH_WINDOW_SECONDS", 600),
		ExtensionHostRestartBackoffMilliseconds:      envInt("LAUNCHER_EXTENSION_HOST_RESTART_BACKOFF_MS", 1000),
		ExtensionSecretsKey:                          env("LAUNCHER_EXTENSION_SECRETS_KEY", ""),
		ExtensionHTTPMaxRequestBytes:                 envInt64("LAUNCHER_EXTENSION_HTTP_MAX_REQUEST_BYTES", 256<<10),
		ExtensionHTTPMaxResponseBytes:                envInt64("LAUNCHER_EXTENSION_HTTP_MAX_RESPONSE_BYTES", 1<<20),
		ExtensionHTTPTimeoutSeconds:                  envInt("LAUNCHER_EXTENSION_HTTP_TIMEOUT_SECONDS", 10),
		ExtensionEventsEnabled:                       envBool("LAUNCHER_EXTENSION_EVENTS_ENABLED", true),
		ExtensionEventsWorkerIntervalMilliseconds:    envInt("LAUNCHER_EXTENSION_EVENTS_WORKER_INTERVAL_MS", 250),
		ExtensionEventsLeaseSeconds:                  envInt("LAUNCHER_EXTENSION_EVENTS_LEASE_SECONDS", 30),
		ExtensionEventsHookTimeoutMilliseconds:       envInt("LAUNCHER_EXTENSION_EVENTS_HOOK_TIMEOUT_MS", 2000),
		ExtensionEventsMaxAttempts:                   envInt("LAUNCHER_EXTENSION_EVENTS_MAX_ATTEMPTS", 8),
		ExtensionEventsBaseRetryMilliseconds:         envInt("LAUNCHER_EXTENSION_EVENTS_BASE_RETRY_MS", 1000),
		ExtensionEventsMaxRetrySeconds:               envInt("LAUNCHER_EXTENSION_EVENTS_MAX_RETRY_SECONDS", 300),
		ExtensionEventsBatchSize:                     envInt("LAUNCHER_EXTENSION_EVENTS_BATCH_SIZE", 32),
		CORSAllowedOrigins:                           envCSVDefault("LAUNCHER_CORS_ALLOWED_ORIGINS", corsFallback),
		Environment:                                  environment,
		ValidationAttestationPublicKey0345:           env("LAUNCHER_VALIDATION_ATTESTATION_PUBLIC_KEY", ""),
		ValidationTrustedRunnerImageSHA2560345:       env("LAUNCHER_VALIDATION_RUNNER_IMAGE_SHA256", ""),
		ValidationRequiredTargetsJSON0346:            env("LAUNCHER_VALIDATION_REQUIRED_TARGETS_JSON", ""),
		AuthTokenSecret:                              env("LAUNCHER_AUTH_TOKEN_SECRET", env("LAUNCHER_TOKEN_SECRET", env("LAUNCHER_JWT_SECRET", "dev-only-change-me"))),
		AuthTokenTTLHours:                            envInt("LAUNCHER_AUTH_TOKEN_TTL_HOURS", 12),
		AuthTokenIssuer:                              env("LAUNCHER_AUTH_TOKEN_ISSUER", strings.TrimRight(publicURL, "/")),
		AuthTokenAudience:                            env("LAUNCHER_AUTH_TOKEN_AUDIENCE", "launcher-api"),
		AuthTokenActiveKID:                           env("LAUNCHER_AUTH_TOKEN_ACTIVE_KID", "primary"),
		AuthTokenKeysJSON:                            env("LAUNCHER_AUTH_TOKEN_KEYS_JSON", ""),
		GuardReleaseAllowlistJSON:                    env("LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON", ""),
		BridgeReleaseAllowlistJSON:                   env("LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON", ""),
		MetricsEnabled:                               envBool("LAUNCHER_METRICS_ENABLED", true),
		PersistentSessions:                           envBool("LAUNCHER_PERSISTENT_SESSIONS", true),
		RequirePersistentStoreInProduction:           envBool("LAUNCHER_REQUIRE_PERSISTENT_STORE_IN_PRODUCTION", true),
		DatabaseAutoMigrate:                          envBool("LAUNCHER_DATABASE_AUTO_MIGRATE", true),
		BootstrapToken:                               env("LAUNCHER_BOOTSTRAP_TOKEN", ""),
		ManifestSigningPrivateKey:                    manifestSigningPrivateKey,
		RuntimeValidationKeysJSON:                    env("LAUNCHER_RUNTIME_VALIDATION_KEYS_JSON", ""),
		ServerBridgeHostTargetsFile0413:              env("LAUNCHER_SERVER_BRIDGE_HOST_TARGETS_FILE", ""),
		ServerBridgeControlSigningPrivateKey:         serverBridgeControlSigningPrivateKey,
		ServerBridgeControlPreviousSigningPrivateKey: serverBridgeControlPreviousSigningPrivateKey,
		AuthRoutingJSON:                              env("LAUNCHER_AUTH_ROUTING_JSON", ""),
		AuthRoutingFile:                              env("LAUNCHER_AUTH_ROUTING_FILE", ""),
		AuthSQLProvidersJSON:                         env("LAUNCHER_AUTH_SQL_PROVIDERS_JSON", ""),
		AuthSQLProvidersFile:                         env("LAUNCHER_AUTH_SQL_PROVIDERS_FILE", ""),
		AuthFileProvidersJSON:                        env("LAUNCHER_AUTH_FILE_PROVIDERS_JSON", ""),
		AuthFileProvidersFile:                        env("LAUNCHER_AUTH_FILE_PROVIDERS_FILE", ""),
		AuthHTTPProvidersJSON:                        env("LAUNCHER_AUTH_HTTP_PROVIDERS_JSON", ""),
		AuthHTTPProvidersFile:                        env("LAUNCHER_AUTH_HTTP_PROVIDERS_FILE", ""),
		AuthOIDCProvidersJSON:                        env("LAUNCHER_AUTH_OIDC_PROVIDERS_JSON", ""),
		AuthOIDCProvidersFile:                        env("LAUNCHER_AUTH_OIDC_PROVIDERS_FILE", ""),
		AuthMicrosoftProvidersJSON:                   env("LAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON", ""),
		AuthMicrosoftProvidersFile:                   env("LAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE", ""),
		WebAuthnRPID:                                 env("LAUNCHER_WEBAUTHN_RP_ID", webauthnRPID),
		WebAuthnRPName:                               env("LAUNCHER_WEBAUTHN_RP_NAME", "Launcher"),
		WebAuthnOrigins:                              envCSVDefault("LAUNCHER_WEBAUTHN_ORIGINS", webauthnOrigin),
	}
}

func defaultWebAuthnScope(publicURL string) (string, string) {
	u, err := url.Parse(strings.TrimSpace(publicURL))
	if err != nil || u.Hostname() == "" {
		return "localhost", "http://localhost:8080"
	}
	origin := u.Scheme + "://" + u.Host
	return strings.ToLower(u.Hostname()), origin
}

// IsProductionEnvironment возвращает true для production/prod и строгого e2e-production контура.
func IsProductionEnvironment(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "production", "prod", "e2e-production":
		return true
	default:
		return false
	}
}

// ValidateProduction проверяет конфигурацию, которую нельзя безопасно исправить fallback-логикой.
// В промышленной среде ошибки считаются фатальными и должны останавливать запуск API.
func ValidateProduction(cfg Config) error {
	if !IsProductionEnvironment(cfg.Environment) {
		return nil
	}
	problems := make([]string, 0)
	driver := strings.ToLower(strings.TrimSpace(cfg.RepositoryDriver))
	sqliteMinimal := driver == "sqlite" && strings.EqualFold(strings.TrimSpace(cfg.DeploymentMode), "single-node")
	if sqliteMinimal {
		if cfg.StorageDriver != "local" || strings.TrimSpace(cfg.DatabaseDSN) == "" || !filepath.IsAbs(cfg.DatabaseDSN) || filepath.Clean(cfg.DatabaseDSN) != cfg.DatabaseDSN {
			problems = append(problems, "Для минимального режима SQLite нужны локальное хранилище и абсолютный безопасный путь к базе данных")
		}
		if strings.TrimSpace(cfg.SQLiteCoordinatorPath) == "" || !filepath.IsAbs(cfg.SQLiteCoordinatorPath) || filepath.Clean(cfg.SQLiteCoordinatorPath) != cfg.SQLiteCoordinatorPath {
			problems = append(problems, "Для минимального режима SQLite необходим абсолютный безопасный путь координатора")
		}
		if strings.TrimSpace(cfg.DatabaseDSN) == strings.TrimSpace(cfg.SQLiteCoordinatorPath) {
			problems = append(problems, "Хранилище SQLite и координатор не могут использовать один файл")
		}
		if cfg.ServerBridgeHARequired || strings.TrimSpace(cfg.RedisURL) != "" {
			problems = append(problems, "Минимальный режим SQLite не допускает ServerBridge HA и Redis")
		}
	} else {
		if driver != "postgres" && driver != "postgresql" && driver != "sql" {
			problems = append(problems, "Для рабочей среды нужен PostgreSQL или явно настроенный одноузловой SQLite")
		}
		if !strings.EqualFold(strings.TrimSpace(cfg.SQLDriver), "pgx") {
			problems = append(problems, "Для PostgreSQL в рабочей среде требуется драйвер pgx")
		}
		if strings.TrimSpace(cfg.DatabaseDSN) == "" {
			problems = append(problems, "Требуется LAUNCHER_DATABASE_DSN")
		}
	}
	secret := strings.TrimSpace(cfg.AuthTokenSecret)
	if len(secret) < 32 || secret == "dev-only-change-me" || strings.Contains(strings.ToUpper(secret), "CHANGE_ME") {
		problems = append(problems, "LAUNCHER_AUTH_TOKEN_SECRET должен содержать не менее 32 случайных символов и не быть значением по умолчанию")
	}
	if controlKey := strings.TrimSpace(cfg.ServerBridgeControlSigningPrivateKey); controlKey != "" {
		decoded, err := hex.DecodeString(controlKey)
		if err != nil || len(decoded) != 32 {
			problems = append(problems, "LAUNCHER_SERVERBRIDGE_CONTROL_SIGNING_PRIVATE_KEY должен быть 64 hex символами Ed25519 seed")
		}
	}
	if previousKey := strings.TrimSpace(cfg.ServerBridgeControlPreviousSigningPrivateKey); previousKey != "" {
		decoded, err := hex.DecodeString(previousKey)
		if err != nil || len(decoded) != 32 {
			problems = append(problems, "LAUNCHER_SERVERBRIDGE_CONTROL_PREVIOUS_SIGNING_PRIVATE_KEY должен быть 64 hex символами Ed25519 seed")
		}
		if strings.EqualFold(previousKey, strings.TrimSpace(cfg.ServerBridgeControlSigningPrivateKey)) {
			problems = append(problems, "Активный и предыдущий ключи подписи команд ServerBridge должны различаться")
		}
	}
	if raw := strings.TrimSpace(cfg.AuthTokenKeysJSON); raw != "" {
		keys := map[string]string{}
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			problems = append(problems, "LAUNCHER_AUTH_TOKEN_KEYS_JSON должен содержать объект JSON, сопоставляющий идентификаторы ключей (kid) с секретами")
		} else {
			active := strings.TrimSpace(cfg.AuthTokenActiveKID)
			if active == "" {
				active = "primary"
			}
			if strings.TrimSpace(keys[active]) == "" {
				problems = append(problems, "Идентификатор активного ключа токенов авторизации отсутствует в LAUNCHER_AUTH_TOKEN_KEYS_JSON")
			}
			for kid, key := range keys {
				if strings.TrimSpace(kid) == "" || len(strings.TrimSpace(key)) < 32 {
					problems = append(problems, fmt.Sprintf("Ключ токена авторизации %q должен содержать не менее 32 символов", kid))
				}
			}
		}
	}
	guardAllowlistRaw := strings.TrimSpace(cfg.GuardReleaseAllowlistJSON)
	if guardAllowlistRaw == "" {
		problems = append(problems, "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON обязателен в production")
	} else {
		type guardArtifactPair struct {
			GuardSHA256         string `json:"guardSha256"`
			LauncherSHA256      string `json:"launcherSha256"`
			RequireAuthenticode bool   `json:"requireAuthenticode,omitempty"`
		}
		type guardPlatform struct {
			SigningMode string              `json:"signingMode"`
			Artifacts   []guardArtifactPair `json:"artifacts"`
		}
		type guardRelease struct {
			ProtocolVersion uint32                   `json:"protocolVersion"`
			Platforms       map[string]guardPlatform `json:"platforms"`
		}
		var document struct {
			SchemaVersion string                  `json:"schemaVersion"`
			Releases      map[string]guardRelease `json:"releases"`
		}
		if err := json.Unmarshal([]byte(guardAllowlistRaw), &document); err != nil || document.SchemaVersion != "2.0" || len(document.Releases) == 0 {
			problems = append(problems, "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON должен содержать политику выпуска Guard с schemaVersion=2.0")
		} else {
			for version, release := range document.Releases {
				if strings.TrimSpace(version) == "" || release.ProtocolVersion != 4 || len(release.Platforms) == 0 {
					problems = append(problems, fmt.Sprintf("Политика выпуска Guard %q должна содержать protocolVersion=4 и platforms", version))
					continue
				}
				for platform, platformPolicy := range release.Platforms {
					platform = strings.ToLower(strings.TrimSpace(platform))
					expectedSigning := map[string]string{"windows": "authenticode", "linux": "integrity-only", "macos": "developer-id-notarized"}[platform]
					if expectedSigning == "" || platformPolicy.SigningMode != expectedSigning || len(platformPolicy.Artifacts) == 0 {
						problems = append(problems, fmt.Sprintf("Политика выпуска Guard %q: для платформы %q указан недопустимый режим подписи или набор производственных артефактов", version, platform))
						continue
					}
					for _, pair := range platformPolicy.Artifacts {
						for _, value := range []string{pair.GuardSHA256, pair.LauncherSHA256} {
							value = strings.TrimSpace(value)
							if len(value) != 64 {
								problems = append(problems, fmt.Sprintf("Политика выпуска Guard %q для платформы %q содержит SHA-256 неверной длины", version, platform))
								break
							}
							if _, err := hex.DecodeString(value); err != nil {
								problems = append(problems, fmt.Sprintf("Политика выпуска Guard %q для платформы %q содержит невалидный SHA-256", version, platform))
								break
							}
						}
						if platform == "windows" && !pair.RequireAuthenticode {
							problems = append(problems, fmt.Sprintf("Политика выпуска Guard %q: для пары производственных артефактов Windows необходимо требовать подпись Authenticode", version))
						}
					}
				}
			}
		}
	}

	// Явно выбранная одноузловая SQLite несовместима с распределённым HA. Старые
	// промышленные конфигурации сохраняют свою политику Redis/HA.
	singleNode := strings.TrimSpace(cfg.SQLiteCoordinatorPath) != ""
	if singleNode {
		if !filepath.IsAbs(cfg.SQLiteCoordinatorPath) {
			problems = append(problems, "Путь к координатору SQLite в односерверном режиме должен быть абсолютным")
		}
		if cfg.ServerBridgeHARequired {
			problems = append(problems, "SQLite single-node не поддерживает SERVERBRIDGE_HA_REQUIRED")
		}
	} else {
		haPolicySpecified := cfg.ServerBridgeHARequired || strings.TrimSpace(cfg.ServerBridgeReplicaID) != ""
		if haPolicySpecified {
			if !cfg.ServerBridgeHARequired {
				problems = append(problems, "production требует LAUNCHER_SERVERBRIDGE_HA_REQUIRED=true")
			}
			if strings.TrimSpace(cfg.RedisURL) == "" {
				problems = append(problems, "LAUNCHER_REDIS_URL обязателен для ServerBridge HA fencing")
			}
		}
	}

	ratePolicySpecified := singleNode || strings.TrimSpace(cfg.RedisURL) != "" || cfg.RateLimitEnabled || cfg.RateLimitGlobalPerMinute != 0 || cfg.RateLimitAuthPerMinute != 0 || cfg.RateLimitServerBridgePerMinute != 0 || cfg.RateLimitFailClosed
	if ratePolicySpecified {
		if !cfg.RateLimitEnabled {
			problems = append(problems, "production требует LAUNCHER_RATE_LIMIT_ENABLED=true")
		}
		if !cfg.RateLimitFailClosed {
			problems = append(problems, "production требует LAUNCHER_RATE_LIMIT_FAIL_CLOSED=true")
		}
		if !singleNode && strings.TrimSpace(cfg.RedisURL) == "" {
			problems = append(problems, "Для распределённого ограничения частоты запросов в рабочей среде необходимо указать LAUNCHER_REDIS_URL")
		}
		if cfg.RateLimitGlobalPerMinute <= 0 || cfg.RateLimitAuthPerMinute <= 0 || cfg.RateLimitServerBridgePerMinute <= 0 {
			problems = append(problems, "Ограничения частоты запросов global/auth/serverbridge в рабочей среде должны быть больше нуля")
		}
	}

	bridgeAllowlistRaw := strings.TrimSpace(cfg.BridgeReleaseAllowlistJSON)
	if bridgeAllowlistRaw == "" {
		problems = append(problems, "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON обязателен в production")
	} else {
		type bridgeReleaseEntry struct {
			VelocitySHA256   []string `json:"velocitySha256"`
			BungeeCordSHA256 []string `json:"bungeeCordSha256"`
			WaterfallSHA256  []string `json:"waterfallSha256"`
			BukkitSHA256     []string `json:"bukkitSha256"`
			SpigotSHA256     []string `json:"spigotSha256"`
			PaperSHA256      []string `json:"paperSha256"`
			PurpurSHA256     []string `json:"purpurSha256"`
			FoliaSHA256      []string `json:"foliaSha256"`
			FabricSHA256     []string `json:"fabricSha256"`
			ForgeSHA256      []string `json:"forgeSha256"`
			NeoForgeSHA256   []string `json:"neoforgeSha256"`
			QuiltSHA256      []string `json:"quiltSha256"`
			SpongeSHA256     []string `json:"spongeSha256"`
			VanillaSHA256    []string `json:"vanillaSha256"`
		}
		var probe struct {
			SchemaVersion string `json:"schemaVersion"`
		}
		_ = json.Unmarshal([]byte(bridgeAllowlistRaw), &probe)
		var bridgeAllowlist map[string]bridgeReleaseEntry
		if probe.SchemaVersion == "3.0" {
			var document struct {
				SchemaVersion            string                        `json:"schemaVersion"`
				Release                  string                        `json:"release"`
				ProtocolVersion          int                           `json:"protocolVersion"`
				MinimumProtocolVersion   int                           `json:"minimumProtocolVersion"`
				SecurityProfile          string                        `json:"securityProfile"`
				SecurityCapabilityDigest string                        `json:"securityCapabilityDigest"`
				RequiredFeatures         []string                      `json:"requiredFeatures"`
				Releases                 map[string]bridgeReleaseEntry `json:"releases"`
			}
			if err := json.Unmarshal([]byte(bridgeAllowlistRaw), &document); err != nil || document.Release != "ServerBridge 3" || document.ProtocolVersion != 3 || document.MinimumProtocolVersion != 3 || document.SecurityProfile != "serverbridge3-security-01912" || !strings.EqualFold(document.SecurityCapabilityDigest, "088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4") || !serverBridgeSecurityFeaturesExact01912(document.RequiredFeatures) {
				problems = append(problems, "Метаданные сертификации безопасности ServerBridge 3 в LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON некорректны")
			} else {
				bridgeAllowlist = document.Releases
			}
		} else if err := json.Unmarshal([]byte(bridgeAllowlistRaw), &bridgeAllowlist); err != nil {
			problems = append(problems, "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON должен содержать карту выпусков старого формата или ServerBridge 3 с schemaVersion=3.0")
		}
		if len(bridgeAllowlist) == 0 {
			problems = append(problems, "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON должен содержать непустой releases")
		} else {
			for version, entry := range bridgeAllowlist {
				if strings.TrimSpace(version) == "" || len(entry.VelocitySHA256) == 0 || len(entry.PaperSHA256) == 0 || len(entry.PurpurSHA256) == 0 {
					problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q должна содержать velocitySha256, paperSha256 и purpurSha256", version))
					continue
				}
				if bridgeReleaseRequiresBukkitFamily0144(version) && (len(entry.BukkitSHA256) == 0 || len(entry.SpigotSHA256) == 0 || len(entry.FoliaSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q для 0.14.4+ должна содержать bukkitSha256, spigotSha256 и foliaSha256", version))
					continue
				}
				if bridgeReleaseRequiresProxyFamily0145(version) && (len(entry.BungeeCordSHA256) == 0 || len(entry.WaterfallSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q для 0.14.5+ должна содержать bungeeCordSha256 и waterfallSha256", version))
					continue
				}
				if bridgeReleaseRequiresFabric0146(version) && len(entry.FabricSHA256) == 0 {
					problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q для 0.14.6+ должна содержать fabricSha256", version))
					continue
				}
				if bridgeReleaseRequiresForgeFamily0147(version) && (len(entry.ForgeSHA256) == 0 || len(entry.NeoForgeSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q для 0.14.7+ должна содержать forgeSha256 и neoforgeSha256", version))
					continue
				}
				if bridgeReleaseRequiresUniversalAdapters0198(version) && (len(entry.QuiltSHA256) == 0 || len(entry.SpongeSHA256) == 0 || len(entry.VanillaSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q для 0.19.8+ должна содержать quiltSha256, spongeSha256 и vanillaSha256", version))
					continue
				}
				values := make([]string, 0, len(entry.VelocitySHA256)+len(entry.BungeeCordSHA256)+len(entry.WaterfallSHA256)+len(entry.BukkitSHA256)+len(entry.SpigotSHA256)+len(entry.PaperSHA256)+len(entry.PurpurSHA256)+len(entry.FoliaSHA256)+len(entry.FabricSHA256)+len(entry.ForgeSHA256)+len(entry.NeoForgeSHA256)+len(entry.QuiltSHA256)+len(entry.SpongeSHA256)+len(entry.VanillaSHA256))
				values = append(values, entry.VelocitySHA256...)
				values = append(values, entry.BungeeCordSHA256...)
				values = append(values, entry.WaterfallSHA256...)
				values = append(values, entry.BukkitSHA256...)
				values = append(values, entry.SpigotSHA256...)
				values = append(values, entry.PaperSHA256...)
				values = append(values, entry.PurpurSHA256...)
				values = append(values, entry.FoliaSHA256...)
				values = append(values, entry.FabricSHA256...)
				values = append(values, entry.ForgeSHA256...)
				values = append(values, entry.NeoForgeSHA256...)
				values = append(values, entry.QuiltSHA256...)
				values = append(values, entry.SpongeSHA256...)
				values = append(values, entry.VanillaSHA256...)
				for _, value := range values {
					value = strings.TrimSpace(value)
					if len(value) != 64 {
						problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q содержит SHA-256 неверной длины", version))
						break
					}
					if _, err := hex.DecodeString(value); err != nil {
						problems = append(problems, fmt.Sprintf("Политика выпуска ServerBridge %q содержит невалидный SHA-256", version))
						break
					}
				}
			}
		}
	}

	publicURL, err := url.Parse(strings.TrimSpace(cfg.PublicURL))
	publicURLValid := err == nil && publicURL.Host != "" && publicURL.Scheme == "https"
	if !publicURLValid && isE2EProductionEnvironment(cfg.Environment) && err == nil && publicURL.Scheme == "http" && isLoopbackHost(publicURL.Hostname()) {
		publicURLValid = true
	}
	if !publicURLValid {
		problems = append(problems, "LAUNCHER_PUBLIC_URL в production должен быть абсолютным HTTPS URL (HTTP loopback разрешён только для e2e-production)")
	}
	rpID := strings.ToLower(strings.TrimSpace(cfg.WebAuthnRPID))
	if rpID == "" {
		problems = append(problems, "LAUNCHER_WEBAUTHN_RP_ID обязателен")
	} else if strings.Contains(rpID, "://") || strings.ContainsAny(rpID, "/?#") || strings.Contains(rpID, ":") {
		problems = append(problems, "LAUNCHER_WEBAUTHN_RP_ID должен быть hostname/domain без scheme, port и path")
	}
	if strings.TrimSpace(cfg.WebAuthnRPName) == "" {
		problems = append(problems, "LAUNCHER_WEBAUTHN_RP_NAME обязателен")
	}
	if len(cfg.WebAuthnOrigins) == 0 {
		problems = append(problems, "LAUNCHER_WEBAUTHN_ORIGINS обязателен")
	}
	for _, origin := range cfg.WebAuthnOrigins {
		u, parseErr := url.Parse(strings.TrimSpace(origin))
		secure := parseErr == nil && u.Host != "" && u.Scheme == "https" && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
		if !secure && isE2EProductionEnvironment(cfg.Environment) && parseErr == nil && u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
			secure = true
		}
		if !secure {
			problems = append(problems, fmt.Sprintf("некорректный WebAuthn origin: %q", origin))
			continue
		}
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if rpID != "" && host != rpID && !strings.HasSuffix(host, "."+rpID) {
			problems = append(problems, fmt.Sprintf("WebAuthn origin %q не находится внутри RP ID %q", origin, rpID))
		}
	}
	if len(cfg.CORSAllowedOrigins) == 0 {
		problems = append(problems, "LAUNCHER_CORS_ALLOWED_ORIGINS обязателен в production")
	}
	for _, origin := range cfg.CORSAllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			problems = append(problems, "CORS wildcard '*' запрещён в production")
			continue
		}
		u, parseErr := url.Parse(origin)
		if parseErr != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			problems = append(problems, fmt.Sprintf("некорректный production CORS origin: %q", origin))
		}
	}
	backupRoot := filepath.Clean(strings.TrimSpace(cfg.BackupRoot))
	if strings.TrimSpace(cfg.BackupRoot) == "" || backupRoot == "." {
		problems = append(problems, "LAUNCHER_BACKUP_ROOT обязателен")
	}
	extensionRoot := filepath.Clean(strings.TrimSpace(cfg.ExtensionRoot))
	if strings.TrimSpace(cfg.ExtensionRoot) == "" || extensionRoot == "." {
		problems = append(problems, "LAUNCHER_EXTENSION_ROOT обязателен")
	} else if pathsOverlap(extensionRoot, backupRoot) {
		problems = append(problems, "Каталог расширений должен находиться отдельно от каталога резервных копий")
	}
	if cfg.ExtensionBackupRetention < 1 || cfg.ExtensionBackupRetention > 100 {
		problems = append(problems, "LAUNCHER_EXTENSION_BACKUP_RETENTION должен быть 1..100")
	}
	if cfg.ExtensionEventsEnabled {
		if !cfg.ExtensionHostEnabled {
			problems = append(problems, "Для обработки событий расширений необходимо установить LAUNCHER_EXTENSION_HOST_ENABLED=true")
		}
		if cfg.ExtensionEventsWorkerIntervalMilliseconds < 50 || cfg.ExtensionEventsWorkerIntervalMilliseconds > 60000 {
			problems = append(problems, "Интервал обработчика событий расширений должен составлять от 50 до 60000 мс")
		}
		if cfg.ExtensionEventsLeaseSeconds < 2 || cfg.ExtensionEventsLeaseSeconds > 600 {
			problems = append(problems, "Срок аренды для событий расширений должен составлять от 2 до 600 секунд")
		}
		if cfg.ExtensionEventsHookTimeoutMilliseconds < 50 || cfg.ExtensionEventsHookTimeoutMilliseconds > 60000 {
			problems = append(problems, "Тайм-аут обработчика событий расширений должен составлять от 50 до 60000 мс")
		}
		if cfg.ExtensionEventsMaxAttempts < 1 || cfg.ExtensionEventsMaxAttempts > 100 {
			problems = append(problems, "Максимальное число попыток обработки событий расширений должно быть от 1 до 100")
		}
		if cfg.ExtensionEventsBaseRetryMilliseconds < 100 || cfg.ExtensionEventsBaseRetryMilliseconds > 60000 {
			problems = append(problems, "Базовый интервал повторной попытки для событий расширений должен быть от 100 до 60000 мс")
		}
		if cfg.ExtensionEventsMaxRetrySeconds < 1 || cfg.ExtensionEventsMaxRetrySeconds > 86400 {
			problems = append(problems, "Максимальный интервал повторной попытки для событий расширений должен составлять от 1 до 86400 секунд")
		}
		if cfg.ExtensionEventsBatchSize < 1 || cfg.ExtensionEventsBatchSize > 100 {
			problems = append(problems, "Размер пакета событий расширений должен быть от 1 до 100")
		}
	}
	if cfg.ExtensionHostEnabled {
		host, _, err := net.SplitHostPort(strings.TrimSpace(cfg.ExtensionHostListen))
		if err != nil {
			problems = append(problems, "LAUNCHER_EXTENSION_HOST_LISTEN должен быть host:port")
		} else if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			problems = append(problems, "LAUNCHER_EXTENSION_HOST_LISTEN должен быть loopback-адресом")
		}
		if cfg.ExtensionHostStartupTimeoutSeconds < 1 || cfg.ExtensionHostStartupTimeoutSeconds > 300 {
			problems = append(problems, "Тайм-аут запуска хоста расширений должен составлять от 1 до 300 секунд")
		}
		if cfg.ExtensionHostHeartbeatTimeoutSeconds < 3 || cfg.ExtensionHostHeartbeatTimeoutSeconds > 600 {
			problems = append(problems, "Тайм-аут проверки активности хоста расширений должен составлять от 3 до 600 секунд")
		}
		if cfg.ExtensionHostStopTimeoutSeconds < 1 || cfg.ExtensionHostStopTimeoutSeconds > 120 {
			problems = append(problems, "Тайм-аут остановки хоста расширений должен составлять от 1 до 120 секунд")
		}
		if cfg.ExtensionHostCapabilityTimeoutSeconds < 1 || cfg.ExtensionHostCapabilityTimeoutSeconds > 60 {
			problems = append(problems, "Тайм-аут проверки возможностей хоста расширений должен составлять от 1 до 60 секунд")
		}
		if cfg.ExtensionHostMaxMemoryMB < 32 || cfg.ExtensionHostMaxMemoryMB > 1048576 {
			problems = append(problems, "Ограничение памяти хоста расширений должно составлять от 32 до 1048576 МиБ")
		}
		if cfg.ExtensionHostMaxProcesses < 1 || cfg.ExtensionHostMaxProcesses > 1024 {
			problems = append(problems, "Ограничение числа процессов хоста расширений должно составлять от 1 до 1024")
		}
		if cfg.ExtensionHostMaxLogBytes < 65536 || cfg.ExtensionHostMaxLogBytes > 1<<30 {
			problems = append(problems, "Ограничение размера журнала хоста расширений выходит за безопасные пределы")
		}
		if cfg.ExtensionHostMaxLogEntries < 10 || cfg.ExtensionHostMaxLogEntries > 100000 {
			problems = append(problems, "Ограничение числа записей журнала хоста расширений выходит за безопасные пределы")
		}
		if cfg.ExtensionHostMaxProtocolBodyBytes < 4096 || cfg.ExtensionHostMaxProtocolBodyBytes > 16<<20 {
			problems = append(problems, "Ограничение размера тела протокольного сообщения хоста расширений выходит за безопасные пределы")
		}
		if cfg.ExtensionHostMaxStorageReadBytes < 4096 || cfg.ExtensionHostMaxStorageReadBytes > 64<<20 {
			problems = append(problems, "Ограничение чтения хранилища хоста расширений выходит за безопасные пределы")
		}
		if cfg.ExtensionHostCrashLimit < 1 || cfg.ExtensionHostCrashLimit > 100 {
			problems = append(problems, "Допустимое число аварийных завершений хоста расширений должно составлять от 1 до 100")
		}
		if cfg.ExtensionHostCrashWindowSeconds < 10 || cfg.ExtensionHostCrashWindowSeconds > 86400 {
			problems = append(problems, "Окно учёта аварийных завершений хоста расширений должно составлять от 10 до 86400 секунд")
		}
		if cfg.ExtensionHostRestartBackoffMilliseconds < 100 || cfg.ExtensionHostRestartBackoffMilliseconds > 60000 {
			problems = append(problems, "Задержка перед перезапуском хоста расширений должна составлять от 100 до 60000 мс")
		}
		if cfg.ExtensionHTTPMaxRequestBytes < 1024 || cfg.ExtensionHTTPMaxRequestBytes > 8<<20 {
			problems = append(problems, "Ограничение размера HTTP-запроса расширения должно составлять от 1024 до 8388608 байт")
		}
		if cfg.ExtensionHTTPMaxResponseBytes < 4096 || cfg.ExtensionHTTPMaxResponseBytes > 32<<20 {
			problems = append(problems, "Ограничение размера HTTP-ответа расширения должно составлять от 4096 до 33554432 байт")
		}
		if cfg.ExtensionHTTPTimeoutSeconds < 1 || cfg.ExtensionHTTPTimeoutSeconds > 60 {
			problems = append(problems, "Тайм-аут HTTP-запросов расширений должен составлять от 1 до 60 секунд")
		}
	}
	driver := strings.ToLower(strings.TrimSpace(cfg.StorageDriver))
	switch driver {
	case "local", "":
		storageRoot := filepath.Clean(strings.TrimSpace(cfg.StorageLocalPath))
		if strings.TrimSpace(cfg.StorageLocalPath) == "" || storageRoot == "." {
			problems = append(problems, "Для локального хранилища необходимо указать LAUNCHER_STORAGE_LOCAL_PATH")
		} else if pathsOverlap(storageRoot, backupRoot) {
			problems = append(problems, "Каталог резервных копий должен находиться отдельно от каталога локального хранилища")
		} else if strings.TrimSpace(cfg.ExtensionRoot) != "" && extensionRoot != "." && pathsOverlap(storageRoot, extensionRoot) {
			problems = append(problems, "Каталог расширений должен находиться отдельно от каталога локального хранилища")
		}
	case "s3", "s3-compatible":
		if strings.TrimSpace(cfg.StorageS3Endpoint) == "" || strings.TrimSpace(cfg.StorageS3Bucket) == "" || strings.TrimSpace(cfg.StorageS3AccessKey) == "" || strings.TrimSpace(cfg.StorageS3SecretKey) == "" {
			problems = append(problems, "Для S3 обязательны адрес сервиса, имя корзины, ключ доступа и секретный ключ")
		}
	default:
		problems = append(problems, fmt.Sprintf("неподдерживаемый LAUNCHER_STORAGE_DRIVER=%q", cfg.StorageDriver))
	}
	if len(problems) > 0 {
		return errors.New("небезопасная production-конфигурация: " + strings.Join(problems, "; "))
	}
	return nil
}

func isE2EProductionEnvironment(environment string) bool {
	return strings.EqualFold(strings.TrimSpace(environment), "e2e-production")
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func pathsOverlap(a, b string) bool {
	aAbs, errA := filepath.Abs(a)
	bAbs, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return a == b
	}
	if aAbs == bAbs {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(aAbs, bAbs+sep) || strings.HasPrefix(bAbs, aAbs+sep)
}

func normalizeRedisAddr(value string) string {
	if len(value) > len("redis://") && value[:len("redis://")] == "redis://" {
		trimmed := value[len("redis://"):]
		for i, ch := range trimmed {
			if ch == '/' {
				return trimmed[:i]
			}
		}
		return trimmed
	}
	return value
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "no", "NO", "off", "OFF":
		return false
	default:
		return fallback
	}
}

func envInt64(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envCSV(key string) []string {
	return splitCSV(os.Getenv(key))
}

func envCSVDefault(key, fallback string) []string {
	value, ok := os.LookupEnv(key)
	if !ok {
		value = fallback
	}
	return splitCSV(value)
}

func splitCSV(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	items := make([]string, 0)
	seen := map[string]struct{}{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		items = append(items, item)
	}
	return items
}

func serverBridgeSecurityFeaturesExact01912(features []string) bool {
	want := map[string]struct{}{
		"security.protocol-v3-signing-domain":      {},
		"security.capability-downgrade-protection": {},
		"security.command-signatures-v3":           {},
		"security.event-signatures-v3":             {},
		"security.runtime-instance-binding-v3":     {},
		"security.online-key-rotation-v1":          {},
	}
	if len(features) != len(want) {
		return false
	}
	seen := make(map[string]struct{}, len(features))
	for _, feature := range features {
		feature = strings.TrimSpace(feature)
		if _, ok := want[feature]; !ok {
			return false
		}
		if _, duplicate := seen[feature]; duplicate {
			return false
		}
		seen[feature] = struct{}{}
	}
	return len(seen) == len(want)
}
