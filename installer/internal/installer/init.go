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
		return errors.New("public URL must be an origin")
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
	return errors.New("public URL must use HTTPS (HTTP allowed on loopback only)")
}

// Init creates a PostgreSQL production configuration in one exclusive 0600
// operation. It deliberately does not claim to install PostgreSQL or satisfy
// release-specific Guard/Bridge signing policies.
func Init(dest, publicURL, dsn, storageDir string) error {
	if !filepath.IsAbs(dest) || filepath.Clean(dest) != dest || !filepath.IsAbs(storageDir) || !validEnvField(dsn) {
		return errors.New("require absolute output/storage paths and shell-safe PostgreSQL DSN")
	}
	if err := validatePublicURL(publicURL); err != nil {
		return err
	}
	parsed, _ := url.Parse(publicURL)
	if parsed.Scheme != "https" {
		return errors.New("production configuration requires HTTPS origin")
	}
	for _, segment := range []string{filepath.Dir(dest), filepath.Dir(storageDir)} {
		st, e := os.Lstat(segment)
		if e != nil {
			return e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return errors.New("configuration paths require real, non-group-writable parent directories")
		}
	}
	if !validEnvField(storageDir) {
		return errors.New("invalid storage path")
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
		{"NEVERLAUNCHER_ENV", "production"}, {"NEVERLAUNCHER_PUBLIC_URL", publicURL},
		{"NEVERLAUNCHER_DEPLOYMENT_MODE", "standard"},
		{"NEVERLAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH", filepath.Join(filepath.Dir(storageDir), "coordinator", "state.db")},
		{"NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED", "false"},
		{"NEVERLAUNCHER_RATE_LIMIT_ENABLED", "true"}, {"NEVERLAUNCHER_RATE_LIMIT_FAIL_CLOSED", "true"},
		{"NEVERLAUNCHER_WEBAUTHN_RP_ID", parsed.Hostname()}, {"NEVERLAUNCHER_WEBAUTHN_RP_NAME", "Launcher"},
		{"NEVERLAUNCHER_WEBAUTHN_ORIGINS", publicURL}, {"NEVERLAUNCHER_CORS_ALLOWED_ORIGINS", publicURL},
		{"NEVERLAUNCHER_BACKUP_ROOT", filepath.Join(filepath.Dir(storageDir), "backups")},
		{"NEVERLAUNCHER_EXTENSION_ROOT", filepath.Join(filepath.Dir(storageDir), "extensions")}, {"NEVERLAUNCHER_REPOSITORY_DRIVER", "postgres"}, {"NEVERLAUNCHER_SQL_DRIVER", "pgx"}, {"NEVERLAUNCHER_DATABASE_DSN", dsn}, {"NEVERLAUNCHER_DATABASE_AUTO_MIGRATE", "true"}, {"NEVERLAUNCHER_STORAGE_DRIVER", "local"}, {"NEVERLAUNCHER_STORAGE_LOCAL_PATH", storageDir}, {"NEVERLAUNCHER_AUTH_TOKEN_SECRET", secret}, {"NEVERLAUNCHER_BOOTSTRAP_TOKEN", token}, {"NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY", signing}, {"NEVERLAUNCHER_SERVERBRIDGE_CONTROL_SIGNING_PRIVATE_KEY", bridge}, {"NEVERLAUNCHER_EXTENSION_SECRETS_KEY", extensions},
	}
	var b bytes.Buffer
	b.WriteString("# Launcher: GENERATED SECRETS. Permissions 0600. Keep in safe backup.\n# Supply verified NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON and NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON before production startup.\n")
	for _, f := range fields {
		if !validEnvField(f[1]) {
			return fmt.Errorf("unsafe environment value for %s", f[0])
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
