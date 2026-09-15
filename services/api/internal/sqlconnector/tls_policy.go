package sqlconnector

import (
	"fmt"
	"net/url"
	"strings"
)

func validatePostgresTLS(cfg RuntimeConfig) error {
	if cfg.RequireTLS == nil || !*cfg.RequireTLS {
		return nil
	}
	dsn := strings.TrimSpace(cfg.DSN)
	mode := ""
	if parsed, err := url.Parse(dsn); err == nil && parsed.Scheme != "" {
		mode = strings.ToLower(strings.TrimSpace(parsed.Query().Get("sslmode")))
	} else {
		for _, field := range strings.Fields(dsn) {
			pair := strings.SplitN(field, "=", 2)
			if len(pair) == 2 && strings.EqualFold(pair[0], "sslmode") {
				mode = strings.ToLower(strings.Trim(strings.TrimSpace(pair[1]), "'\""))
				break
			}
		}
	}
	if mode == "" {
		mode = "prefer"
	}
	if cfg.AllowInsecureTLS {
		switch mode {
		case "require", "verify-ca", "verify-full":
			return nil
		default:
			return fmt.Errorf("PostgreSQL TLS is required: sslmode=%s may use plaintext; use sslmode=require/verify-ca/verify-full", mode)
		}
	}
	switch mode {
	case "verify-full", "verify-ca":
		return nil
	default:
		return fmt.Errorf("PostgreSQL TLS verification is required: use sslmode=verify-full/verify-ca or explicitly allowInsecureTls")
	}
}

func validateMySQLTLSMode(cfg RuntimeConfig, tlsMode string) error {
	if cfg.RequireTLS == nil || !*cfg.RequireTLS {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(tlsMode))
	if mode == "" || mode == "false" {
		return fmt.Errorf("MySQL/MariaDB TLS is required: configure tls=true")
	}
	if cfg.AllowInsecureTLS {
		switch mode {
		case "true", "skip-verify":
			return nil
		default:
			return fmt.Errorf("MySQL/MariaDB TLS is required without plaintext fallback; tls=%s is not allowed", mode)
		}
	}
	switch mode {
	case "true":
		return nil
	case "skip-verify", "preferred":
		return fmt.Errorf("MySQL/MariaDB TLS verification is required; tls=%s is not allowed", mode)
	default:
		return fmt.Errorf("MySQL/MariaDB TLS verification requires tls=true; custom TLS config %q is not registered by NeverLauncher", mode)
	}
}
