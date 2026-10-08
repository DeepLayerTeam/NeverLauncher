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
			return fmt.Errorf("PostgreSQL TLS является обязательный: sslmode=%s может использовать открытый текст; использовать sslmode=require/verify-ca/verify-full", mode)
		}
	}
	switch mode {
	case "verify-full", "verify-ca":
		return nil
	default:
		return fmt.Errorf("PostgreSQL TLS проверка является обязательный: использовать sslmode=verify-full/verify-ca или явно allowInsecureTls")
	}
}

func validateMySQLTLSMode(cfg RuntimeConfig, tlsMode string) error {
	if cfg.RequireTLS == nil || !*cfg.RequireTLS {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(tlsMode))
	if mode == "" || mode == "false" {
		return fmt.Errorf("MySQL/MariaDB TLS является обязательный: настраивать TLS=true")
	}
	if cfg.AllowInsecureTLS {
		switch mode {
		case "true", "skip-verify":
			return nil
		default:
			return fmt.Errorf("MySQL/MariaDB TLS является обязательный без открытый текст резервный вариант; TLS=%s является не разрешён", mode)
		}
	}
	switch mode {
	case "true":
		return nil
	case "skip-verify", "preferred":
		return fmt.Errorf("MySQL/MariaDB TLS проверка является обязательный; TLS=%s является не разрешён", mode)
	default:
		return fmt.Errorf("MySQL/MariaDB TLS проверка требует TLS=true; custom TLS конфигурация %q является не регистрировать через NeverLauncher", mode)
	}
}
