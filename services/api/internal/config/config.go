package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	DatabaseDSN                                  string
	RepositoryDriver                             string
	SQLDriver                                    string
	RedisAddr                                    string
	RedisURL                                     string
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
	CORSAllowedOrigins                           []string
	Environment                                  string
	AuthTokenSecret                              string
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
	ServerBridgeControlSigningPrivateKey         string
	ServerBridgeControlPreviousSigningPrivateKey string
	AuthSQLProvidersJSON                         string
	AuthSQLProvidersFile                         string
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
	environment := env("NEVERLAUNCHER_ENV", "dev")
	redisAddr := normalizeRedisAddr(env("NEVERLAUNCHER_REDIS_ADDR", env("NEVERLAUNCHER_REDIS_URL", "localhost:6379")))
	redisURL := env("NEVERLAUNCHER_REDIS_URL", "")
	if redisURL == "" {
		redisURL = "redis://" + redisAddr + "/0"
	}
	production := IsProductionEnvironment(environment)
	manifestSigningPrivateKey := env("NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY", "")
	serverBridgeControlSigningPrivateKey := env("NEVERLAUNCHER_SERVERBRIDGE_CONTROL_SIGNING_PRIVATE_KEY", manifestSigningPrivateKey)
	serverBridgeControlPreviousSigningPrivateKey := env("NEVERLAUNCHER_SERVERBRIDGE_CONTROL_PREVIOUS_SIGNING_PRIVATE_KEY", "")
	publicURL := env("NEVERLAUNCHER_PUBLIC_URL", "http://localhost:8080")
	webauthnRPID, webauthnOrigin := defaultWebAuthnScope(publicURL)
	corsFallback := "http://localhost:5173,http://127.0.0.1:5173"
	if production {
		corsFallback = ""
	}
	return Config{
		HTTPAddr:                             env("NEVERLAUNCHER_HTTP_ADDR", "0.0.0.0:8080"),
		PublicURL:                            publicURL,
		DatabaseDSN:                          env("NEVERLAUNCHER_DATABASE_DSN", env("NEVERLAUNCHER_DATABASE_URL", "postgres://neverlauncher:neverlauncher@localhost:5432/neverlauncher?sslmode=disable")),
		RepositoryDriver:                     env("NEVERLAUNCHER_REPOSITORY_DRIVER", "postgres"),
		SQLDriver:                            env("NEVERLAUNCHER_SQL_DRIVER", "pgx"),
		RedisAddr:                            redisAddr,
		RedisURL:                             redisURL,
		ServerBridgeHARequired:               envBool("NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED", production),
		ServerBridgeReplicaID:                env("NEVERLAUNCHER_REPLICA_ID", ""),
		TrustedProxyCIDRs:                    envCSV("NEVERLAUNCHER_TRUSTED_PROXY_CIDRS"),
		RateLimitEnabled:                     envBool("NEVERLAUNCHER_RATE_LIMIT_ENABLED", true),
		RateLimitGlobalPerMinute:             envInt("NEVERLAUNCHER_RATE_LIMIT_GLOBAL_PER_MINUTE", 1200),
		RateLimitAuthPerMinute:               envInt("NEVERLAUNCHER_RATE_LIMIT_AUTH_PER_MINUTE", 20),
		RateLimitServerBridgePerMinute:       envInt("NEVERLAUNCHER_RATE_LIMIT_SERVERBRIDGE_PER_MINUTE", 6000),
		RateLimitFailClosed:                  envBool("NEVERLAUNCHER_RATE_LIMIT_FAIL_CLOSED", production),
		StorageDriver:                        env("NEVERLAUNCHER_STORAGE_DRIVER", "local"),
		StorageLocalPath:                     env("NEVERLAUNCHER_STORAGE_LOCAL_PATH", env("NEVERLAUNCHER_STORAGE_LOCAL_ROOT", "./data/storage")),
		StorageS3Endpoint:                    env("NEVERLAUNCHER_STORAGE_S3_ENDPOINT", ""),
		StorageS3Bucket:                      env("NEVERLAUNCHER_STORAGE_S3_BUCKET", ""),
		StorageS3Region:                      env("NEVERLAUNCHER_STORAGE_S3_REGION", "ru-central1"),
		StorageS3AccessKey:                   env("NEVERLAUNCHER_STORAGE_S3_ACCESS_KEY", ""),
		StorageS3SecretKey:                   env("NEVERLAUNCHER_STORAGE_S3_SECRET_KEY", ""),
		StorageS3PublicURL:                   env("NEVERLAUNCHER_STORAGE_S3_PUBLIC_URL", ""),
		StorageS3PathStyle:                   envBool("NEVERLAUNCHER_STORAGE_S3_PATH_STYLE", true),
		StorageDeliveryMode:                  env("NEVERLAUNCHER_STORAGE_DELIVERY_MODE", "reverse-proxy"),
		StorageCDNOrigin:                     env("NEVERLAUNCHER_STORAGE_CDN_ORIGIN", ""),
		StorageMaxUploadBytes:                envInt64("NEVERLAUNCHER_STORAGE_MAX_UPLOAD_BYTES", 512<<20),
		BackupRoot:                           env("NEVERLAUNCHER_BACKUP_ROOT", "./data/backups"),
		ExtensionRoot:                        env("NEVERLAUNCHER_EXTENSION_ROOT", "./data/extensions"),
		ExtensionBackupRetention:             envInt("NEVERLAUNCHER_EXTENSION_BACKUP_RETENTION", 10),
		CORSAllowedOrigins:                   envCSVDefault("NEVERLAUNCHER_CORS_ALLOWED_ORIGINS", corsFallback),
		Environment:                          environment,
		AuthTokenSecret:                      env("NEVERLAUNCHER_AUTH_TOKEN_SECRET", env("NEVERLAUNCHER_TOKEN_SECRET", env("NEVERLAUNCHER_JWT_SECRET", "dev-only-change-me"))),
		AuthTokenTTLHours:                    envInt("NEVERLAUNCHER_AUTH_TOKEN_TTL_HOURS", 12),
		AuthTokenIssuer:                      env("NEVERLAUNCHER_AUTH_TOKEN_ISSUER", strings.TrimRight(publicURL, "/")),
		AuthTokenAudience:                    env("NEVERLAUNCHER_AUTH_TOKEN_AUDIENCE", "neverlauncher-api"),
		AuthTokenActiveKID:                   env("NEVERLAUNCHER_AUTH_TOKEN_ACTIVE_KID", "primary"),
		AuthTokenKeysJSON:                    env("NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON", ""),
		GuardReleaseAllowlistJSON:            env("NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON", ""),
		BridgeReleaseAllowlistJSON:           env("NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON", ""),
		MetricsEnabled:                       envBool("NEVERLAUNCHER_METRICS_ENABLED", true),
		PersistentSessions:                   envBool("NEVERLAUNCHER_PERSISTENT_SESSIONS", true),
		RequirePersistentStoreInProduction:   envBool("NEVERLAUNCHER_REQUIRE_PERSISTENT_STORE_IN_PRODUCTION", true),
		DatabaseAutoMigrate:                  envBool("NEVERLAUNCHER_DATABASE_AUTO_MIGRATE", true),
		BootstrapToken:                       env("NEVERLAUNCHER_BOOTSTRAP_TOKEN", ""),
		ManifestSigningPrivateKey:            manifestSigningPrivateKey,
		ServerBridgeControlSigningPrivateKey: serverBridgeControlSigningPrivateKey,
		ServerBridgeControlPreviousSigningPrivateKey: serverBridgeControlPreviousSigningPrivateKey,
		AuthSQLProvidersJSON:                         env("NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON", ""),
		AuthSQLProvidersFile:                         env("NEVERLAUNCHER_AUTH_SQL_PROVIDERS_FILE", ""),
		AuthHTTPProvidersJSON:                        env("NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON", ""),
		AuthHTTPProvidersFile:                        env("NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_FILE", ""),
		AuthOIDCProvidersJSON:                        env("NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_JSON", ""),
		AuthOIDCProvidersFile:                        env("NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_FILE", ""),
		AuthMicrosoftProvidersJSON:                   env("NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON", ""),
		AuthMicrosoftProvidersFile:                   env("NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE", ""),
		WebAuthnRPID:                                 env("NEVERLAUNCHER_WEBAUTHN_RP_ID", webauthnRPID),
		WebAuthnRPName:                               env("NEVERLAUNCHER_WEBAUTHN_RP_NAME", "NeverLauncher"),
		WebAuthnOrigins:                              envCSVDefault("NEVERLAUNCHER_WEBAUTHN_ORIGINS", webauthnOrigin),
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
// В production ошибки считаются фатальными и должны останавливать запуск API.
func ValidateProduction(cfg Config) error {
	if !IsProductionEnvironment(cfg.Environment) {
		return nil
	}
	problems := make([]string, 0)
	if strings.ToLower(strings.TrimSpace(cfg.RepositoryDriver)) != "postgres" && strings.ToLower(strings.TrimSpace(cfg.RepositoryDriver)) != "postgresql" && strings.ToLower(strings.TrimSpace(cfg.RepositoryDriver)) != "sql" {
		problems = append(problems, "production требует PostgreSQL repository")
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.SQLDriver), "pgx") {
		problems = append(problems, "production требует NEVERLAUNCHER_SQL_DRIVER=pgx")
	}
	if strings.TrimSpace(cfg.DatabaseDSN) == "" {
		problems = append(problems, "NEVERLAUNCHER_DATABASE_DSN обязателен")
	}
	secret := strings.TrimSpace(cfg.AuthTokenSecret)
	if len(secret) < 32 || secret == "dev-only-change-me" || strings.Contains(strings.ToUpper(secret), "CHANGE_ME") {
		problems = append(problems, "NEVERLAUNCHER_AUTH_TOKEN_SECRET должен содержать не менее 32 случайных символов и не быть значением по умолчанию")
	}
	if controlKey := strings.TrimSpace(cfg.ServerBridgeControlSigningPrivateKey); controlKey != "" {
		decoded, err := hex.DecodeString(controlKey)
		if err != nil || len(decoded) != 32 {
			problems = append(problems, "NEVERLAUNCHER_SERVERBRIDGE_CONTROL_SIGNING_PRIVATE_KEY должен быть 64 hex символами Ed25519 seed")
		}
	}
	if previousKey := strings.TrimSpace(cfg.ServerBridgeControlPreviousSigningPrivateKey); previousKey != "" {
		decoded, err := hex.DecodeString(previousKey)
		if err != nil || len(decoded) != 32 {
			problems = append(problems, "NEVERLAUNCHER_SERVERBRIDGE_CONTROL_PREVIOUS_SIGNING_PRIVATE_KEY должен быть 64 hex символами Ed25519 seed")
		}
		if strings.EqualFold(previousKey, strings.TrimSpace(cfg.ServerBridgeControlSigningPrivateKey)) {
			problems = append(problems, "активный и previous ServerBridge control signing keys должны различаться")
		}
	}
	if raw := strings.TrimSpace(cfg.AuthTokenKeysJSON); raw != "" {
		keys := map[string]string{}
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			problems = append(problems, "NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON должен быть JSON object kid->secret")
		} else {
			active := strings.TrimSpace(cfg.AuthTokenActiveKID)
			if active == "" {
				active = "primary"
			}
			if strings.TrimSpace(keys[active]) == "" {
				problems = append(problems, "active auth token kid отсутствует в NEVERLAUNCHER_AUTH_TOKEN_KEYS_JSON")
			}
			for kid, key := range keys {
				if strings.TrimSpace(kid) == "" || len(strings.TrimSpace(key)) < 32 {
					problems = append(problems, fmt.Sprintf("auth token key %q должен содержать не менее 32 символов", kid))
				}
			}
		}
	}
	guardAllowlistRaw := strings.TrimSpace(cfg.GuardReleaseAllowlistJSON)
	if guardAllowlistRaw == "" {
		problems = append(problems, "NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON обязателен в production")
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
			problems = append(problems, "NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON должен быть NeverGuard release policy schemaVersion=2.0")
		} else {
			for version, release := range document.Releases {
				if strings.TrimSpace(version) == "" || release.ProtocolVersion != 4 || len(release.Platforms) == 0 {
					problems = append(problems, fmt.Sprintf("Guard release policy %q должна содержать protocolVersion=4 и platforms", version))
					continue
				}
				for platform, platformPolicy := range release.Platforms {
					platform = strings.ToLower(strings.TrimSpace(platform))
					expectedSigning := map[string]string{"windows": "authenticode", "linux": "integrity-only", "macos": "developer-id-notarized"}[platform]
					if expectedSigning == "" || platformPolicy.SigningMode != expectedSigning || len(platformPolicy.Artifacts) == 0 {
						problems = append(problems, fmt.Sprintf("Guard release policy %q platform %q имеет недопустимый production signingMode/artifact set", version, platform))
						continue
					}
					for _, pair := range platformPolicy.Artifacts {
						for _, value := range []string{pair.GuardSHA256, pair.LauncherSHA256} {
							value = strings.TrimSpace(value)
							if len(value) != 64 {
								problems = append(problems, fmt.Sprintf("Guard release policy %q platform %q содержит SHA-256 неверной длины", version, platform))
								break
							}
							if _, err := hex.DecodeString(value); err != nil {
								problems = append(problems, fmt.Sprintf("Guard release policy %q platform %q содержит невалидный SHA-256", version, platform))
								break
							}
						}
						if platform == "windows" && !pair.RequireAuthenticode {
							problems = append(problems, fmt.Sprintf("Guard release policy %q Windows production artifact pair должна требовать Authenticode", version))
						}
					}
				}
			}
		}
	}

	// Production loaded through Load() always carries an explicit rate-limit
	// policy. Require Redis-backed fail-closed limiting there; the all-zero case
	// is retained only for backwards-compatible direct Config construction in
	// unit/integration harnesses.
	haPolicySpecified := cfg.ServerBridgeHARequired || strings.TrimSpace(cfg.ServerBridgeReplicaID) != ""
	if haPolicySpecified {
		if !cfg.ServerBridgeHARequired {
			problems = append(problems, "production требует NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED=true")
		}
		if strings.TrimSpace(cfg.RedisURL) == "" {
			problems = append(problems, "NEVERLAUNCHER_REDIS_URL обязателен для ServerBridge HA fencing")
		}
	}

	ratePolicySpecified := strings.TrimSpace(cfg.RedisURL) != "" || cfg.RateLimitEnabled || cfg.RateLimitGlobalPerMinute != 0 || cfg.RateLimitAuthPerMinute != 0 || cfg.RateLimitServerBridgePerMinute != 0 || cfg.RateLimitFailClosed
	if ratePolicySpecified {
		if !cfg.RateLimitEnabled {
			problems = append(problems, "production требует NEVERLAUNCHER_RATE_LIMIT_ENABLED=true")
		}
		if !cfg.RateLimitFailClosed {
			problems = append(problems, "production требует NEVERLAUNCHER_RATE_LIMIT_FAIL_CLOSED=true")
		}
		if strings.TrimSpace(cfg.RedisURL) == "" {
			problems = append(problems, "NEVERLAUNCHER_REDIS_URL обязателен для distributed production rate limiting")
		}
		if cfg.RateLimitGlobalPerMinute <= 0 || cfg.RateLimitAuthPerMinute <= 0 || cfg.RateLimitServerBridgePerMinute <= 0 {
			problems = append(problems, "production rate-limit budgets global/auth/serverbridge должны быть > 0")
		}
	}

	bridgeAllowlistRaw := strings.TrimSpace(cfg.BridgeReleaseAllowlistJSON)
	if bridgeAllowlistRaw == "" {
		problems = append(problems, "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON обязателен в production")
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
				problems = append(problems, "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON ServerBridge 3 security certification metadata некорректна")
			} else {
				bridgeAllowlist = document.Releases
			}
		} else if err := json.Unmarshal([]byte(bridgeAllowlistRaw), &bridgeAllowlist); err != nil {
			problems = append(problems, "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON должен быть legacy release map или ServerBridge 3 schemaVersion=3.0")
		}
		if len(bridgeAllowlist) == 0 {
			problems = append(problems, "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON должен содержать непустой releases")
		} else {
			for version, entry := range bridgeAllowlist {
				if strings.TrimSpace(version) == "" || len(entry.VelocitySHA256) == 0 || len(entry.PaperSHA256) == 0 || len(entry.PurpurSHA256) == 0 {
					problems = append(problems, fmt.Sprintf("ServerBridge release policy %q должна содержать velocitySha256, paperSha256 и purpurSha256", version))
					continue
				}
				if bridgeReleaseRequiresBukkitFamily0144(version) && (len(entry.BukkitSHA256) == 0 || len(entry.SpigotSHA256) == 0 || len(entry.FoliaSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("ServerBridge release policy %q для 0.14.4+ должна содержать bukkitSha256, spigotSha256 и foliaSha256", version))
					continue
				}
				if bridgeReleaseRequiresProxyFamily0145(version) && (len(entry.BungeeCordSHA256) == 0 || len(entry.WaterfallSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("ServerBridge release policy %q для 0.14.5+ должна содержать bungeeCordSha256 и waterfallSha256", version))
					continue
				}
				if bridgeReleaseRequiresFabric0146(version) && len(entry.FabricSHA256) == 0 {
					problems = append(problems, fmt.Sprintf("ServerBridge release policy %q для 0.14.6+ должна содержать fabricSha256", version))
					continue
				}
				if bridgeReleaseRequiresForgeFamily0147(version) && (len(entry.ForgeSHA256) == 0 || len(entry.NeoForgeSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("ServerBridge release policy %q для 0.14.7+ должна содержать forgeSha256 и neoforgeSha256", version))
					continue
				}
				if bridgeReleaseRequiresUniversalAdapters0198(version) && (len(entry.QuiltSHA256) == 0 || len(entry.SpongeSHA256) == 0 || len(entry.VanillaSHA256) == 0) {
					problems = append(problems, fmt.Sprintf("ServerBridge release policy %q для 0.19.8+ должна содержать quiltSha256, spongeSha256 и vanillaSha256", version))
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
						problems = append(problems, fmt.Sprintf("ServerBridge release policy %q содержит SHA-256 неверной длины", version))
						break
					}
					if _, err := hex.DecodeString(value); err != nil {
						problems = append(problems, fmt.Sprintf("ServerBridge release policy %q содержит невалидный SHA-256", version))
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
		problems = append(problems, "NEVERLAUNCHER_PUBLIC_URL в production должен быть абсолютным HTTPS URL (HTTP loopback разрешён только для e2e-production)")
	}
	rpID := strings.ToLower(strings.TrimSpace(cfg.WebAuthnRPID))
	if rpID == "" {
		problems = append(problems, "NEVERLAUNCHER_WEBAUTHN_RP_ID обязателен")
	} else if strings.Contains(rpID, "://") || strings.ContainsAny(rpID, "/?#") || strings.Contains(rpID, ":") {
		problems = append(problems, "NEVERLAUNCHER_WEBAUTHN_RP_ID должен быть hostname/domain без scheme, port и path")
	}
	if strings.TrimSpace(cfg.WebAuthnRPName) == "" {
		problems = append(problems, "NEVERLAUNCHER_WEBAUTHN_RP_NAME обязателен")
	}
	if len(cfg.WebAuthnOrigins) == 0 {
		problems = append(problems, "NEVERLAUNCHER_WEBAUTHN_ORIGINS обязателен")
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
		problems = append(problems, "NEVERLAUNCHER_CORS_ALLOWED_ORIGINS обязателен в production")
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
		problems = append(problems, "NEVERLAUNCHER_BACKUP_ROOT обязателен")
	}
	extensionRoot := filepath.Clean(strings.TrimSpace(cfg.ExtensionRoot))
	if strings.TrimSpace(cfg.ExtensionRoot) == "" || extensionRoot == "." {
		problems = append(problems, "NEVERLAUNCHER_EXTENSION_ROOT обязателен")
	} else if pathsOverlap(extensionRoot, backupRoot) {
		problems = append(problems, "extension root должен быть отделён от backup root")
	}
	if cfg.ExtensionBackupRetention < 1 || cfg.ExtensionBackupRetention > 100 {
		problems = append(problems, "NEVERLAUNCHER_EXTENSION_BACKUP_RETENTION должен быть 1..100")
	}
	driver := strings.ToLower(strings.TrimSpace(cfg.StorageDriver))
	switch driver {
	case "local", "":
		storageRoot := filepath.Clean(strings.TrimSpace(cfg.StorageLocalPath))
		if strings.TrimSpace(cfg.StorageLocalPath) == "" || storageRoot == "." {
			problems = append(problems, "NEVERLAUNCHER_STORAGE_LOCAL_PATH обязателен для local storage")
		} else if pathsOverlap(storageRoot, backupRoot) {
			problems = append(problems, "backup root должен быть отделён от local storage root")
		} else if strings.TrimSpace(cfg.ExtensionRoot) != "" && extensionRoot != "." && pathsOverlap(storageRoot, extensionRoot) {
			problems = append(problems, "extension root должен быть отделён от local storage root")
		}
	case "s3", "s3-compatible":
		if strings.TrimSpace(cfg.StorageS3Endpoint) == "" || strings.TrimSpace(cfg.StorageS3Bucket) == "" || strings.TrimSpace(cfg.StorageS3AccessKey) == "" || strings.TrimSpace(cfg.StorageS3SecretKey) == "" {
			problems = append(problems, "для S3 обязательны endpoint, bucket, access key и secret key")
		}
	default:
		problems = append(problems, fmt.Sprintf("неподдерживаемый NEVERLAUNCHER_STORAGE_DRIVER=%q", cfg.StorageDriver))
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
