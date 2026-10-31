package installer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteSystemdUnit generates a service unit that cannot run as root. It never
// executes systemctl; operators retain control over enable/start/reload.
func WriteSystemdUnit(output, binary, envFile string) error {
	for _, p := range []string{output, binary, envFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\r\n\t %\\\"'") {
			return errors.New("unit paths must be absolute, clean, unescaped")
		}
	}
	app, err := os.Lstat(binary)
	if err != nil {
		return err
	}
	if !app.Mode().IsRegular() || app.Mode().Perm()&0111 == 0 || app.Mode()&os.ModeSymlink != 0 {
		return errors.New("API binary must be regular and executable")
	}
	config, err := os.Lstat(envFile)
	if err != nil {
		return err
	}
	if !config.Mode().IsRegular() || config.Mode().Perm()&0077 != 0 {
		return errors.New("environment must be a private 0600 file")
	}
	unit := fmt.Sprintf(`[Unit]
Description=Launcher Backend API
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=launcher
Group=launcher
EnvironmentFile=%s
ExecStart=%s
WorkingDirectory=/var/lib/launcher
StateDirectory=launcher
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
Restart=on-failure
RestartSec=5
TimeoutStopSec=35

[Install]
WantedBy=multi-user.target
`, envFile, binary)
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(output)
		}
	}()
	if _, err = f.WriteString(unit); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return syncDir(filepath.Dir(output))
}
