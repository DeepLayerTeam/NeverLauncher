package config

import (
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
	HTTPAddr                           string
	PublicURL                          string
	DatabaseDSN                        string
	RepositoryDriver                   string
	SQLDriver                          string
	RedisAddr                          string
	RedisURL                           string
	TrustedProxyCIDRs                  []string
	RateLimitEnabled                   bool
	RateLimitGlobalPerMinute           int
	RateLimitAuthPerMinute             int
	RateLimitFailClosed                bool
	StorageDriver                      string
	StorageLocalPath                   string
	StorageS3Endpoint                  string
	StorageS3Bucket                    string
	StorageS3Region                    string
	StorageS3AccessKey                 string
	StorageS3SecretKey                 string
	StorageS3PublicURL                 string
	StorageS3PathStyle                 bool
	StorageDeliveryMode                string
	StorageCDNOrigin                   string
	StorageMaxUploadBytes              int64
	BackupRoot                         string
	CORSAllowedOrigins                 []string
	Environment                        string
	AuthTokenSecret                    string
	AuthTokenTTLHours                  int
	MetricsEnabled                     bool
	PersistentSessions                 bool
	RequirePersistentStoreInProduction bool
	DatabaseAutoMigrate                bool
	BootstrapToken                     string
	ManifestSigningPrivateKey          string
	AuthSQLProvidersJSON               string
	AuthSQLProvidersFile               string
	AuthHTTPProvidersJSON              string
	AuthHTTPProvidersFile              string
	AuthOIDCProvidersJSON              string
	AuthOIDCProvidersFile              string
	AuthMicrosoftProvidersJSON         string
	AuthMicrosoftProvidersFile         string
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
	corsFallback := "http://localhost:5173,http://127.0.0.1:5173"
	if production {
		corsFallback = ""
	}
	return Config{
		HTTPAddr:                           env("NEVERLAUNCHER_HTTP_ADDR", "0.0.0.0:8080"),
		PublicURL:                          env("NEVERLAUNCHER_PUBLIC_URL", "http://localhost:8080"),
		DatabaseDSN:                        env("NEVERLAUNCHER_DATABASE_DSN", env("NEVERLAUNCHER_DATABASE_URL", "postgres://neverlauncher:neverlauncher@localhost:5432/neverlauncher?sslmode=disable")),
		RepositoryDriver:                   env("NEVERLAUNCHER_REPOSITORY_DRIVER", "postgres"),
		SQLDriver:                          env("NEVERLAUNCHER_SQL_DRIVER", "pgx"),
		RedisAddr:                          redisAddr,
		RedisURL:                           redisURL,
		TrustedProxyCIDRs:                  envCSV("NEVERLAUNCHER_TRUSTED_PROXY_CIDRS"),
		RateLimitEnabled:                   envBool("NEVERLAUNCHER_RATE_LIMIT_ENABLED", true),
		RateLimitGlobalPerMinute:           envInt("NEVERLAUNCHER_RATE_LIMIT_GLOBAL_PER_MINUTE", 1200),
		RateLimitAuthPerMinute:             envInt("NEVERLAUNCHER_RATE_LIMIT_AUTH_PER_MINUTE", 20),
		RateLimitFailClosed:                envBool("NEVERLAUNCHER_RATE_LIMIT_FAIL_CLOSED", production),
		StorageDriver:                      env("NEVERLAUNCHER_STORAGE_DRIVER", "local"),
		StorageLocalPath:                   env("NEVERLAUNCHER_STORAGE_LOCAL_PATH", env("NEVERLAUNCHER_STORAGE_LOCAL_ROOT", "./data/storage")),
		StorageS3Endpoint:                  env("NEVERLAUNCHER_STORAGE_S3_ENDPOINT", ""),
		StorageS3Bucket:                    env("NEVERLAUNCHER_STORAGE_S3_BUCKET", ""),
		StorageS3Region:                    env("NEVERLAUNCHER_STORAGE_S3_REGION", "ru-central1"),
		StorageS3AccessKey:                 env("NEVERLAUNCHER_STORAGE_S3_ACCESS_KEY", ""),
		StorageS3SecretKey:                 env("NEVERLAUNCHER_STORAGE_S3_SECRET_KEY", ""),
		StorageS3PublicURL:                 env("NEVERLAUNCHER_STORAGE_S3_PUBLIC_URL", ""),
		StorageS3PathStyle:                 envBool("NEVERLAUNCHER_STORAGE_S3_PATH_STYLE", true),
		StorageDeliveryMode:                env("NEVERLAUNCHER_STORAGE_DELIVERY_MODE", "reverse-proxy"),
		StorageCDNOrigin:                   env("NEVERLAUNCHER_STORAGE_CDN_ORIGIN", ""),
		StorageMaxUploadBytes:              envInt64("NEVERLAUNCHER_STORAGE_MAX_UPLOAD_BYTES", 512<<20),
		BackupRoot:                         env("NEVERLAUNCHER_BACKUP_ROOT", "./data/backups"),
		CORSAllowedOrigins:                 envCSVDefault("NEVERLAUNCHER_CORS_ALLOWED_ORIGINS", corsFallback),
		Environment:                        environment,
		AuthTokenSecret:                    env("NEVERLAUNCHER_AUTH_TOKEN_SECRET", env("NEVERLAUNCHER_TOKEN_SECRET", env("NEVERLAUNCHER_JWT_SECRET", "dev-only-change-me"))),
		AuthTokenTTLHours:                  envInt("NEVERLAUNCHER_AUTH_TOKEN_TTL_HOURS", 12),
		MetricsEnabled:                     envBool("NEVERLAUNCHER_METRICS_ENABLED", true),
		PersistentSessions:                 envBool("NEVERLAUNCHER_PERSISTENT_SESSIONS", true),
		RequirePersistentStoreInProduction: envBool("NEVERLAUNCHER_REQUIRE_PERSISTENT_STORE_IN_PRODUCTION", true),
		DatabaseAutoMigrate:                envBool("NEVERLAUNCHER_DATABASE_AUTO_MIGRATE", true),
		BootstrapToken:                     env("NEVERLAUNCHER_BOOTSTRAP_TOKEN", ""),
		ManifestSigningPrivateKey:          env("NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY", ""),
		AuthSQLProvidersJSON:               env("NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON", ""),
		AuthSQLProvidersFile:               env("NEVERLAUNCHER_AUTH_SQL_PROVIDERS_FILE", ""),
		AuthHTTPProvidersJSON:              env("NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON", ""),
		AuthHTTPProvidersFile:              env("NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_FILE", ""),
		AuthOIDCProvidersJSON:              env("NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_JSON", ""),
		AuthOIDCProvidersFile:              env("NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_FILE", ""),
		AuthMicrosoftProvidersJSON:         env("NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON", ""),
		AuthMicrosoftProvidersFile:         env("NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE", ""),
	}
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
	publicURL, err := url.Parse(strings.TrimSpace(cfg.PublicURL))
	publicURLValid := err == nil && publicURL.Host != "" && publicURL.Scheme == "https"
	if !publicURLValid && isE2EProductionEnvironment(cfg.Environment) && err == nil && publicURL.Scheme == "http" && isLoopbackHost(publicURL.Hostname()) {
		publicURLValid = true
	}
	if !publicURLValid {
		problems = append(problems, "NEVERLAUNCHER_PUBLIC_URL в production должен быть абсолютным HTTPS URL (HTTP loopback разрешён только для e2e-production)")
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
	driver := strings.ToLower(strings.TrimSpace(cfg.StorageDriver))
	switch driver {
	case "local", "":
		storageRoot := filepath.Clean(strings.TrimSpace(cfg.StorageLocalPath))
		if strings.TrimSpace(cfg.StorageLocalPath) == "" || storageRoot == "." {
			problems = append(problems, "NEVERLAUNCHER_STORAGE_LOCAL_PATH обязателен для local storage")
		} else if pathsOverlap(storageRoot, backupRoot) {
			problems = append(problems, "backup root должен быть отделён от local storage root")
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
