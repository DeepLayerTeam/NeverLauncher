package sqlconnector

import (
	"errors"
	"fmt"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector/configmigration"
	"os"
	"regexp"
	"strings"
	"time"
)

const defaultProviderVersion = "0.11.3"

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Columns struct {
	ID            string `json:"id"`
	Username      string `json:"username,omitempty"`
	Email         string `json:"email,omitempty"`
	Password      string `json:"password"`
	Status        string `json:"status,omitempty"`
	DisplayName   string `json:"displayName,omitempty"`
	Groups        string `json:"groups,omitempty"`
	Roles         string `json:"roles,omitempty"`
	MinecraftUUID string `json:"minecraftUuid,omitempty"`
}

type PasswordConfig struct {
	Algorithm         string `json:"algorithm"`
	AllowLegacySHA256 bool   `json:"allowLegacySha256,omitempty"`
	// Legacy verifiers must be opted into explicitly. No automatic algorithm detection.
	AllowLegacyHashes bool   `json:"allowLegacyHashes,omitempty"`
	DigestAlgorithm   string `json:"digestAlgorithm,omitempty"`
	DigestEncoding    string `json:"digestEncoding,omitempty"`
	// Gravit doubleDigest: hash the lowercase hex representation of the first digest
	// (true), or its binary bytes (false).
	DoubleDigestHex     bool `json:"doubleDigestHex,omitempty"`
	PBKDF2MinIterations int  `json:"pbkdf2MinIterations,omitempty"`
}

type ProvisioningConfig struct {
	Mode        string `json:"mode,omitempty"`
	DefaultRole string `json:"defaultRole,omitempty"`
}

type Config struct {
	ID                 string             `json:"id"`
	DisplayName        string             `json:"displayName,omitempty"`
	Driver             string             `json:"driver"`
	DSN                string             `json:"dsn,omitempty"`
	DSNEnv             string             `json:"dsnEnv,omitempty"`
	Table              string             `json:"table"`
	Columns            Columns            `json:"columns"`
	Password           PasswordConfig     `json:"password"`
	ActiveStatusValues []string           `json:"activeStatusValues,omitempty"`
	RequireTLS         *bool              `json:"requireTls,omitempty"`
	AllowInsecureTLS   bool               `json:"allowInsecureTls,omitempty"`
	ConnectTimeout     string             `json:"connectTimeout,omitempty"`
	QueryTimeout       string             `json:"queryTimeout,omitempty"`
	MaxOpenConns       int                `json:"maxOpenConns,omitempty"`
	MaxIdleConns       int                `json:"maxIdleConns,omitempty"`
	ConnMaxLifetime    string             `json:"connMaxLifetime,omitempty"`
	Provisioning       ProvisioningConfig `json:"provisioning,omitempty"`
}

type RuntimeConfig struct {
	Config
	ConnectTimeoutDuration  time.Duration
	QueryTimeoutDuration    time.Duration
	ConnMaxLifetimeDuration time.Duration
}

func LoadConfigs(jsonValue, filePath string) ([]Config, error) {
	jsonValue = strings.TrimSpace(jsonValue)
	filePath = strings.TrimSpace(filePath)
	if jsonValue != "" && filePath != "" {
		return nil, errors.New("configure only one of NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON or NEVERLAUNCHER_AUTH_SQL_PROVIDERS_FILE")
	}
	if jsonValue == "" && filePath == "" {
		return nil, nil
	}
	raw := []byte(jsonValue)
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read SQL auth providers file: %w", err)
		}
		raw = data
	}
	configs, err := configmigration.Decode[Config](raw)
	if err != nil {
		return nil, fmt.Errorf("decode configured sqlconnector auth providers: %w", err)
	}
	return configs, nil
}

func Normalize(input Config) (RuntimeConfig, error) {
	cfg := input
	cfg.ID = strings.ToLower(strings.TrimSpace(cfg.ID))
	cfg.DisplayName = strings.TrimSpace(cfg.DisplayName)
	cfg.Driver = strings.ToLower(strings.TrimSpace(cfg.Driver))
	cfg.DSN = strings.TrimSpace(cfg.DSN)
	cfg.DSNEnv = strings.TrimSpace(cfg.DSNEnv)
	cfg.Table = strings.TrimSpace(cfg.Table)
	cfg.Password.Algorithm = strings.ToLower(strings.TrimSpace(cfg.Password.Algorithm))
	cfg.Password.DigestAlgorithm = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(cfg.Password.DigestAlgorithm), "-", ""))
	cfg.Password.DigestEncoding = strings.ToLower(strings.TrimSpace(cfg.Password.DigestEncoding))
	cfg.Provisioning.Mode = strings.ToLower(strings.TrimSpace(cfg.Provisioning.Mode))
	cfg.Provisioning.DefaultRole = strings.TrimSpace(cfg.Provisioning.DefaultRole)

	if cfg.ID == "" || cfg.ID == "local" {
		return RuntimeConfig{}, errors.New("SQL connector id is required and cannot be 'local'")
	}
	if len(cfg.ID) > 64 {
		return RuntimeConfig{}, fmt.Errorf("SQL connector id %q exceeds 64 characters", cfg.ID)
	}
	for _, r := range cfg.ID {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return RuntimeConfig{}, fmt.Errorf("SQL connector id %q contains unsupported character %q", cfg.ID, r)
		}
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.ID
	}
	switch cfg.Driver {
	case "postgres", "postgresql":
		cfg.Driver = "postgresql"
	case "mysql":
	case "mariadb":
	default:
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: unsupported driver %q", cfg.ID, cfg.Driver)
	}
	if cfg.DSN != "" && cfg.DSNEnv != "" {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: configure only one of dsn or dsnEnv", cfg.ID)
	}
	if cfg.DSN == "" && cfg.DSNEnv != "" {
		cfg.DSN = strings.TrimSpace(os.Getenv(cfg.DSNEnv))
		if cfg.DSN == "" {
			return RuntimeConfig{}, fmt.Errorf("SQL connector %q: environment variable %s is empty", cfg.ID, cfg.DSNEnv)
		}
	}
	if cfg.DSN == "" {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: dsn or dsnEnv is required", cfg.ID)
	}
	if err := validateTableIdentifier(cfg.Table); err != nil {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: %w", cfg.ID, err)
	}
	if err := validateColumns(cfg.Columns); err != nil {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: %w", cfg.ID, err)
	}
	switch cfg.Password.Algorithm {
	case "argon2id":
		if !argon2idAvailable() {
			return RuntimeConfig{}, fmt.Errorf("SQL connector %q: argon2id verification is unavailable in this build", cfg.ID)
		}
	case "bcrypt", "pbkdf2-sha256":
	case "digest", "gravit-digest", "doubledigest", "double-digest", "gravit-double-digest", "phpass", "gravit-phpass":
		if !cfg.Password.AllowLegacyHashes {
			return RuntimeConfig{}, fmt.Errorf("SQL connector %q: legacy password verifier requires password.allowLegacyHashes=true", cfg.ID)
		}
		switch cfg.Password.Algorithm {
		case "gravit-digest":
			cfg.Password.Algorithm = "digest"
		case "doubledigest", "gravit-double-digest":
			cfg.Password.Algorithm = "double-digest"
		case "gravit-phpass":
			cfg.Password.Algorithm = "phpass"
		}
		if cfg.Password.Algorithm == "digest" || cfg.Password.Algorithm == "double-digest" {
			switch cfg.Password.DigestAlgorithm {
			case "md5", "sha1", "sha256", "sha512":
			default:
				return RuntimeConfig{}, fmt.Errorf("SQL connector %q: digestAlgorithm must be one of md5, sha1, sha256, sha512", cfg.ID)
			}
			if cfg.Password.DigestEncoding == "" {
				cfg.Password.DigestEncoding = "hex"
			}
			if cfg.Password.DigestEncoding != "hex" && cfg.Password.DigestEncoding != "base64" {
				return RuntimeConfig{}, fmt.Errorf("SQL connector %q: digestEncoding must be hex or base64", cfg.ID)
			}
		}
	case "sha256", "legacy-sha256":
		if !cfg.Password.AllowLegacySHA256 {
			return RuntimeConfig{}, fmt.Errorf("SQL connector %q: legacy SHA-256 requires password.allowLegacySha256=true", cfg.ID)
		}
		cfg.Password.Algorithm = "legacy-sha256"
	default:
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: unsupported password algorithm %q", cfg.ID, cfg.Password.Algorithm)
	}
	if cfg.Password.Algorithm == "digest" && cfg.Password.DoubleDigestHex {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: doubleDigestHex applies only to double-digest", cfg.ID)
	}
	if cfg.Password.Algorithm != "digest" && cfg.Password.Algorithm != "double-digest" && (cfg.Password.DigestAlgorithm != "" || cfg.Password.DigestEncoding != "" || cfg.Password.DoubleDigestHex) {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: digest configuration is only valid for digest/double-digest", cfg.ID)
	}
	if cfg.Password.PBKDF2MinIterations <= 0 {
		cfg.Password.PBKDF2MinIterations = 10000
	}
	if cfg.Password.PBKDF2MinIterations > 10_000_000 {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: pbkdf2MinIterations exceeds safety limit", cfg.ID)
	}
	if cfg.Provisioning.Mode == "" {
		cfg.Provisioning.Mode = "jit"
	}
	switch cfg.Provisioning.Mode {
	case "jit", "explicit-only":
	default:
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q: unsupported provisioning mode %q", cfg.ID, cfg.Provisioning.Mode)
	}
	if cfg.Provisioning.DefaultRole == "" {
		cfg.Provisioning.DefaultRole = "player"
	}
	if cfg.RequireTLS == nil {
		required := true
		cfg.RequireTLS = &required
	}
	if len(cfg.ActiveStatusValues) == 0 {
		cfg.ActiveStatusValues = []string{"active", "enabled", "1", "true"}
	}
	for i := range cfg.ActiveStatusValues {
		cfg.ActiveStatusValues[i] = strings.ToLower(strings.TrimSpace(cfg.ActiveStatusValues[i]))
	}
	connectTimeout, err := parseDurationDefault(cfg.ConnectTimeout, 5*time.Second)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q connectTimeout: %w", cfg.ID, err)
	}
	queryTimeout, err := parseDurationDefault(cfg.QueryTimeout, 3*time.Second)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q queryTimeout: %w", cfg.ID, err)
	}
	lifetime, err := parseDurationDefault(cfg.ConnMaxLifetime, 4*time.Minute)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q connMaxLifetime: %w", cfg.ID, err)
	}
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = 10
	}
	if cfg.MaxOpenConns > 512 {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q maxOpenConns exceeds 512", cfg.ID)
	}
	if cfg.MaxIdleConns < 0 {
		return RuntimeConfig{}, fmt.Errorf("SQL connector %q maxIdleConns cannot be negative", cfg.ID)
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 2
	}
	if cfg.MaxIdleConns > cfg.MaxOpenConns {
		cfg.MaxIdleConns = cfg.MaxOpenConns
	}
	return RuntimeConfig{Config: cfg, ConnectTimeoutDuration: connectTimeout, QueryTimeoutDuration: queryTimeout, ConnMaxLifetimeDuration: lifetime}, nil
}

func validateTableIdentifier(value string) error {
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 2 {
		return fmt.Errorf("table %q must be table or schema.table", value)
	}
	for _, part := range parts {
		// PostgreSQL silently truncates identifiers above 63 bytes. Reject
		// before building any SQL instead of accidentally selecting another field.
		if len(part) > 63 {
			return fmt.Errorf("SQL identifier %q exceeds 63 bytes", part)
		}
		if !identifierPattern.MatchString(part) {
			return fmt.Errorf("table identifier %q is invalid", value)
		}
	}
	return nil
}

func validateColumns(columns Columns) error {
	if columns.ID == "" || columns.Password == "" {
		return errors.New("columns.id and columns.password are required")
	}
	if columns.Username == "" && columns.Email == "" {
		return errors.New("at least one of columns.username or columns.email is required")
	}
	values := []struct {
		name  string
		value string
	}{
		{"id", columns.ID}, {"username", columns.Username}, {"email", columns.Email}, {"password", columns.Password},
		{"status", columns.Status}, {"displayName", columns.DisplayName}, {"groups", columns.Groups}, {"roles", columns.Roles}, {"minecraftUuid", columns.MinecraftUUID},
	}
	seen := map[string]string{}
	for _, item := range values {
		if item.value == "" {
			continue
		}
		if len(item.value) > 63 {
			return fmt.Errorf("column %s identifier exceeds 63 bytes", item.name)
		}
		if !identifierPattern.MatchString(item.value) {
			return fmt.Errorf("column %s=%q is invalid", item.name, item.value)
		}
		lower := strings.ToLower(item.value)
		if previous, ok := seen[lower]; ok && previous != item.name {
			return fmt.Errorf("columns %s and %s map to the same database column %q", previous, item.name, item.value)
		}
		seen[lower] = item.name
	}
	return nil
}

func parseDurationDefault(value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		if err == nil {
			err = errors.New("duration must be positive")
		}
		return 0, err
	}
	return parsed, nil
}
