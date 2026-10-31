//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const hostServiceMarker02811 = "# Managed by Launcher Host Service Installer 0.28.11"

var hostServiceName02811 = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

// Isolated for the installer integration tests. No shell interpreter is involved.
var hostSystemctl02811 = func(args ...string) error {
	cmd := exec.Command("/usr/bin/systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type hostServiceSpec02811 struct {
	Name, Root, Binary, Scope, User, Group, Component string
	Listen, TLSCert, TLSKey, ClientCA                 string
	Sources                                           []string
	StopSeconds                                       int
}

func hostServiceFile02811(scope, name string) (string, error) {
	if !hostServiceName02811.MatchString(name) {
		return "", errors.New("--name must be 1-48 lowercase ASCII letters, digits or hyphens, starting with a letter")
	}
	unit := "launcher-" + name + ".service"
	if scope == "system" {
		return filepath.Join("/etc/systemd/system", unit), nil
	}
	if scope != "user" {
		return "", errors.New("--scope must be user or system")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config/systemd/user", unit), nil
}

func hostUnitValue02811(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\n\r\x00") {
		return "", errors.New("empty or multiline value forbidden in systemd unit")
	}
	// Escape both systemd specifiers and the quoted-word parser; no shell involved.
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return "\"" + value + "\"", nil
}

func hostServiceUnit02811(spec hostServiceSpec02811) (string, error) {
	if !hostServiceName02811.MatchString(spec.Name) {
		return "", errors.New("invalid service name")
	}
	if spec.Component != "host" && spec.Component != "remote" {
		return "", errors.New("invalid component")
	}
	if !filepath.IsAbs(spec.Root) || !filepath.IsAbs(spec.Binary) {
		return "", errors.New("service root and binary must be absolute")
	}
	root, err := hostUnitValue02811(spec.Root)
	if err != nil {
		return "", err
	}
	binary, err := hostUnitValue02811(spec.Binary)
	if err != nil {
		return "", err
	}
	command := binary + " server-bridge host"
	if spec.Component == "host" {
		command += " run --server-root " + root
	} else {
		cert, err := hostUnitValue02811(spec.TLSCert)
		if err != nil {
			return "", err
		}
		key, err := hostUnitValue02811(spec.TLSKey)
		if err != nil {
			return "", err
		}
		listen, err := hostUnitValue02811(spec.Listen)
		if err != nil {
			return "", err
		}
		command += " remote serve --server-root " + root + " --listen " + listen + " --tls-cert " + cert + " --tls-key " + key
		if spec.ClientCA != "" {
			ca, err := hostUnitValue02811(spec.ClientCA)
			if err != nil {
				return "", err
			}
			command += " --client-ca " + ca
		}
		for _, source := range spec.Sources {
			v, err := hostUnitValue02811(source)
			if err != nil {
				return "", err
			}
			command += " --allow-source " + v
		}
	}
	workingDirectory := strings.ReplaceAll(spec.Root, "%", "%%")
	if strings.ContainsAny(workingDirectory, `\"`) {
		return "", errors.New("working directory contains characters unsupported by systemd")
	}
	unit := hostServiceMarker02811 + "\n" +
		"[Unit]\nDescription=Launcher " + strings.ToUpper(spec.Component[:1]) + spec.Component[1:] + " (" + spec.Name + ")\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n" +
		"[Service]\nType=simple\nWorkingDirectory=" + workingDirectory + "\nExecStart=" + command + "\n" +
		"Restart=on-failure\nRestartSec=5s\n" +
		"UMask=0077\nNoNewPrivileges=yes\nRestrictSUIDSGID=yes\n" +
		"KillMode=mixed\nTimeoutStopSec=" + strconv.Itoa(spec.StopSeconds+15) + "s\n"
	if spec.Component == "host" {
		unit = strings.Replace(unit, "Type=simple", "Type=notify\nNotifyAccess=main\nWatchdogSec=30s", 1)
	} else {
		// The HTTPS agent can start the independently supervised JVM host.
		// Killing its entire cgroup on remote-agent reload would kill healthy
		// game servers. The host itself is managed by its own supervisor.
		unit = strings.Replace(unit, "KillMode=mixed", "KillMode=process", 1)
		// The HTTPS server drains already accepted, journaled commands for up
		// to 90s on SIGTERM; the unit must not SIGKILL it at the default 45s.
		unit = strings.Replace(unit, "TimeoutStopSec="+strconv.Itoa(spec.StopSeconds+15)+"s", "TimeoutStopSec=105s", 1)
	}
	if spec.Scope == "system" {
		if spec.User == "" || spec.User == "root" || spec.User == "0" || !hostServiceName02811.MatchString(spec.Group) {
			return "", errors.New("system service requires an explicitly selected non-root --service-user")
		}
		unit += "User=" + spec.User + "\nGroup=" + spec.Group + "\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nReadWritePaths=" + root + "\n"
	}
	unit += "\n[Install]\nWantedBy="
	if spec.Scope == "system" {
		unit += "multi-user.target\n"
	} else {
		unit += "default.target\n"
	}
	return unit, nil
}

func hostServiceSystemctl02811(scope string, args ...string) error {
	if scope == "user" {
		return hostSystemctl02811(append([]string{"--user"}, args...)...)
	}
	return hostSystemctl02811(args...)
}

func hostServiceAbsoluteFile02811(input string) (string, error) {
	if input == "" {
		return "", errors.New("required file path missing")
	}
	path, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("expected regular file: " + path)
	}
	return path, nil
}

func hostServiceValidateIdentity02811(spec hostServiceSpec02811) error {
	if spec.Scope != "system" {
		if os.Geteuid() == 0 {
			return errors.New("root must not install a user-scoped service")
		}
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("system service installation requires root; no implicit privilege escalation")
	}
	if !hostServiceName02811.MatchString(spec.User) {
		return errors.New("--service-user must name an existing unprivileged account")
	}
	u, err := user.Lookup(spec.User)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	if uid == 0 {
		return errors.New("refusing root service account")
	}
	group, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return err
	}
	if !hostServiceName02811.MatchString(group.Name) {
		return errors.New("service account primary group name is not safe for systemd unit")
	}
	// The private host-state root is a trust boundary, not a general shared directory.
	fi, err := os.Stat(spec.Root)
	if err != nil {
		return err
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(uid) {
		return errors.New("server root must be owned by the unprivileged service account")
	}
	return nil
}

func hostServiceHandle02811(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nl server-bridge host service install|uninstall|start|stop|restart|status [--scope user|system] [--name host-<id>] [--server-root path]")
	}
	action := args[0]
	switch action {
	case "install", "uninstall", "start", "stop", "restart", "status":
	default:
		return fmt.Errorf("unknown service action %q", action)
	}
	scope := flagValue(args, "--scope", "user")
	name := flagValue(args, "--name", "host")
	path, err := hostServiceFile02811(scope, name)
	if err != nil {
		return err
	}
	unit := filepath.Base(path)
	if action != "install" {
		if action == "uninstall" && scope == "system" && os.Geteuid() != 0 {
			return errors.New("system service removal requires root")
		}
		if action == "uninstall" {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if !strings.HasPrefix(string(data), hostServiceMarker02811+"\n") {
				return errors.New("refusing to remove service not managed by Launcher")
			}
			if err = hostServiceSystemctl02811(scope, "disable", "--now", unit); err != nil {
				return err
			}
			if err = os.Remove(path); err != nil {
				return err
			}
			return hostServiceSystemctl02811(scope, "daemon-reload")
		}
		if action == "status" {
			parameters := []string{"show", unit, "--property=ActiveState,SubState,MainPID,Result"}
			if scope == "user" {
				parameters = append([]string{"--user"}, parameters...)
			}
			output, e := exec.Command("/usr/bin/systemctl", parameters...).CombinedOutput()
			if e != nil {
				return fmt.Errorf("service status: %w: %s", e, strings.TrimSpace(string(output)))
			}
			fmt.Print(string(output))
			return nil
		}
		return hostServiceSystemctl02811(scope, action, unit)
	}
	if _, err = os.Lstat(path); err == nil {
		return errors.New("service already installed; uninstall before replacing it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = hostServiceAbsoluteFile02811(binary)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, binary)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("service binary must reside outside writable game server root")
	}
	component := flagValue(args, "--component", "host")
	spec := hostServiceSpec02811{Name: name, Root: root, Binary: binary, Scope: scope, Component: component, User: flagValue(args, "--service-user", ""), StopSeconds: 30}
	if component == "host" {
		conf, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
		if err != nil {
			return fmt.Errorf("configure host before installing service: %w", err)
		}
		if err = validateServerBridgeHostConfig01910(conf); err != nil {
			return err
		}
		spec.StopSeconds = hostDefaultInt0282(conf.StopTimeoutSeconds, 30)
	} else if component == "remote" {
		if _, err = remoteLoad0284(root); err != nil {
			return fmt.Errorf("initialize RemoteControl before installing: %w", err)
		}
		spec.TLSCert, err = hostServiceAbsoluteFile02811(flagValue(args, "--tls-cert", ""))
		if err != nil {
			return err
		}
		spec.TLSKey, err = hostServiceAbsoluteFile02811(flagValue(args, "--tls-key", ""))
		if err != nil {
			return err
		}
		if err = remoteCheckFile0284(spec.TLSKey); err != nil {
			return err
		}
		spec.Listen = flagValue(args, "--listen", "127.0.0.1:9443")
		address, _, e := net.SplitHostPort(spec.Listen)
		if e != nil || net.ParseIP(address) == nil {
			return errors.New("--listen must be a numeric IP:port")
		}
		spec.Sources = multiFlagValues01910(args, "--allow-source")
		if len(spec.Sources) == 0 {
			spec.Sources = []string{"127.0.0.0/8", "::1/128"}
		}
		if _, err = remoteParseSources0284(spec.Sources); err != nil {
			return err
		}
		if ca := flagValue(args, "--client-ca", ""); ca != "" {
			spec.ClientCA, err = hostServiceAbsoluteFile02811(ca)
			if err != nil {
				return err
			}
		}
	} else {
		return errors.New("--component must be host or remote")
	}
	if err = hostServiceValidateIdentity02811(spec); err != nil {
		return err
	}
	if spec.Component == "remote" && spec.Scope == "system" {
		account, lookupErr := user.Lookup(spec.User)
		if lookupErr != nil {
			return lookupErr
		}
		uid, _ := strconv.Atoi(account.Uid)
		keyInfo, statErr := os.Stat(spec.TLSKey)
		if statErr != nil {
			return statErr
		}
		stat, ok := keyInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(uid) || keyInfo.Mode().Perm()&0400 == 0 {
			return errors.New("remote TLS private key must be readable and owned by the selected non-root service account")
		}
	}
	if spec.Scope == "system" {
		u, _ := user.Lookup(spec.User)
		g, _ := user.LookupGroupId(u.Gid)
		spec.Group = g.Name
	}
	content, err := hostServiceUnit02811(spec)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, closeErr)
	}
	rollback := func(e error) error {
		_ = hostServiceSystemctl02811(scope, "disable", "--now", unit)
		_ = os.Remove(path)
		_ = hostServiceSystemctl02811(scope, "daemon-reload")
		return e
	}
	if err = hostServiceSystemctl02811(scope, "daemon-reload"); err != nil {
		return rollback(err)
	}
	enable := []string{"enable", unit}
	if flagBool(args, "--now", false) {
		enable = []string{"enable", "--now", unit}
	}
	if err = hostServiceSystemctl02811(scope, enable...); err != nil {
		return rollback(err)
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"status": "installed", "unit": unit, "path": path, "scope": scope, "component": component, "started": flagBool(args, "--now", false)})
}
