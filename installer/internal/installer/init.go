package installer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func validEnvField(s string) bool { return s != "" && !strings.ContainsAny(s, "\x00\r\n\"'`$\\# ") }
func validatePublicURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("Публичный URL должен содержать только схему, хост и порт, без пути и параметров")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("Публичный URL должен использовать HTTPS (HTTP разрешён только для loopback)")
}

// Init создаёт производственную конфигурацию PostgreSQL одной эксклюзивной
// операцией записи 0600. Установка PostgreSQL и соответствие специфическим
// политикам подписания Guard/Bridge здесь не утверждаются.
func Init(dest, publicURL, dsn, storageDir string) error {
	if !filepath.IsAbs(dest) || filepath.Clean(dest) != dest || !filepath.IsAbs(storageDir) || !validEnvField(dsn) {
		return errors.New("Необходимы абсолютные пути вывода и хранения, а также безопасная для оболочки строка подключения PostgreSQL DSN")
	}
	if err := validatePublicURL(publicURL); err != nil {
		return err
	}
	parsed, _ := url.Parse(publicURL)
	if parsed.Scheme != "https" {
		return errors.New("Для рабочей конфигурации требуется HTTPS-источник")
	}
	for _, segment := range []string{filepath.Dir(dest), filepath.Dir(storageDir)} {
		st, e := os.Lstat(segment)
		if e != nil {
			return e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return errors.New("Пути конфигурации должны иметь существующие родительские каталоги без права записи для группы")
		}
	}
	if !validEnvField(storageDir) {
		return errors.New("Недопустимый путь хранилища")
	}
	secret, err := randomHex(32)
	if err != nil {
		return err
	}
	token, err := randomHex(32)
	if err != nil {
		return err
	}
	signing, err := randomHex(32)
	if err != nil {
		return err
	}
	bridge, err := randomHex(32)
	if err != nil {
		return err
	}
	extensions, err := randomHex(32)
	if err != nil {
		return err
	}
	fields := [][2]string{
		{"LAUNCHER_ENV", "production"}, {"LAUNCHER_PUBLIC_URL", publicURL},
		{"LAUNCHER_DEPLOYMENT_MODE", "standard"},
		{"LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", filepath.Join(filepath.Dir(storageDir), "coordinator", "state.db")},
		{"LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "false"},
		{"LAUNCHER_RATE_LIMIT_ENABLED", "true"}, {"LAUNCHER_RATE_LIMIT_FAIL_CLOSED", "true"},
		{"LAUNCHER_WEBAUTHN_RP_ID", parsed.Hostname()}, {"LAUNCHER_WEBAUTHN_RP_NAME", "Launcher"},
		{"LAUNCHER_WEBAUTHN_ORIGINS", publicURL}, {"LAUNCHER_CORS_ALLOWED_ORIGINS", publicURL},
		{"LAUNCHER_BACKUP_ROOT", filepath.Join(filepath.Dir(storageDir), "backups")},
		{"LAUNCHER_EXTENSION_ROOT", filepath.Join(filepath.Dir(storageDir), "extensions")}, {"LAUNCHER_REPOSITORY_DRIVER", "postgres"}, {"LAUNCHER_SQL_DRIVER", "pgx"}, {"LAUNCHER_DATABASE_DSN", dsn}, {"LAUNCHER_DATABASE_AUTO_MIGRATE", "true"}, {"LAUNCHER_STORAGE_DRIVER", "local"}, {"LAUNCHER_STORAGE_LOCAL_PATH", storageDir}, {"LAUNCHER_AUTH_TOKEN_SECRET", secret}, {"LAUNCHER_BOOTSTRAP_TOKEN", token}, {"LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY", signing}, {"LAUNCHER_SERVERBRIDGE_CONTROL_SIGNING_PRIVATE_KEY", bridge}, {"LAUNCHER_EXTENSION_SECRETS_KEY", extensions},
	}
	var b bytes.Buffer
	b.WriteString("# Launcher: GENERATED SECRETS. Permissions 0600. Keep in safe backup.\n# Supply verified LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON and LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON before production startup.\n")
	for _, f := range fields {
		if !validEnvField(f[1]) {
			return fmt.Errorf("Небезопасное значение переменной окружения %s", f[0])
		}
		fmt.Fprintf(&b, "%s=%s\n", f[0], f[1])
	}
	file, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(dest)
		}
	}()
	if _, err = file.Write(b.Bytes()); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	ok = true
	return syncDir(filepath.Dir(dest))
}
