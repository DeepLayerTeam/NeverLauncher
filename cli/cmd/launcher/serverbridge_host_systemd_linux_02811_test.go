//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHostSystemdUnit02811(t *testing.T) {
	spec := hostServiceSpec02811{Name: "host-test", Root: "/srv/minecraft world", Binary: "/usr/local/bin/nl", Scope: "system", Component: "host", User: "minecraft", Group: "minecraft", StopSeconds: 25}
	unit, err := hostServiceUnit02811(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Type=notify", "NotifyAccess=main", "WatchdogSec=30s", "KillMode=mixed", "TimeoutStopSec=40s", "User=minecraft", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=", "ReadWritePaths=\"/srv/minecraft world\"", "ExecStart=\"/usr/local/bin/nl\" server-bridge host run --server-root \"/srv/minecraft world\"",
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("missing %q in %s", expected, unit)
		}
	}
	spec.Scope = "user"
	spec.User = ""
	unit, err = hostServiceUnit02811(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unit, "User=") || !strings.Contains(unit, "WantedBy=default.target") {
		t.Fatal("user-service privilege escalation or wrong target", unit)
	}
	spec.Component = "remote"
	spec.TLSCert = "/certs/cert.pem"
	spec.TLSKey = "/certs/key.pem"
	spec.Listen = "127.0.0.1:9443"
	spec.Sources = []string{"127.0.0.0/8"}
	unit, err = hostServiceUnit02811(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unit, "WatchdogSec") || !strings.Contains(unit, "Type=simple") || !strings.Contains(unit, "remote serve") || !strings.Contains(unit, "KillMode=process") || !strings.Contains(unit, "--allow-source \"127.0.0.0/8\"") {
		t.Fatal("remote unit wrong", unit)
	}
}
func TestHostSystemdUnitRejectsInjection02811(t *testing.T) {
	cases := []string{"../bad", "AAA", "x unit", "", "x\\x", "a/b"}
	for _, s := range cases {
		if _, err := hostServiceFile02811("user", s); err == nil {
			t.Errorf("accepted name %q", s)
		}
	}
	for _, s := range []string{"", "/tmp/a\nExecStart=/bin/sh", "/tmp/x\r", "/tmp/\x00secret"} {
		if _, err := hostUnitValue02811(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	s, err := hostUnitValue02811(`/data/my %world "`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "%%") || !strings.Contains(s, `\"`) {
		t.Fatal("bad unit escaping", s)
	}
	if _, err := hostServiceUnit02811(hostServiceSpec02811{Name: "host", Root: "/srv/a", Binary: "/bin/nl", Component: "host", Scope: "system", User: "root", StopSeconds: 5}); err == nil {
		t.Fatal("root service not rejected")
	}
}
func TestHostSystemdNotifySocketAndWatchdog02811(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "notify.sock")
	addr := &net.UnixAddr{Name: socket, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", socket)
	hostServiceReady02811(serverBridgeHostRuntime01910{ProcessPID: 1234})
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "READY=1") || !strings.Contains(got, "pid=1234") {
		t.Fatalf("message=%q", got)
	}
	hostServiceStopping02811()
	n, _, err = listener.ReadFromUnix(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "STOPPING=1") {
		t.Fatalf("stopping=%q %v", buf[:n], err)
	}
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()+1))
	t.Setenv("WATCHDOG_USEC", "30000000")
	if hostWatchdogInterval02811() != 0 {
		t.Fatal("unrelated watchdog PID accepted")
	}
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	if hostWatchdogInterval02811() != 5*time.Second {
		t.Fatal("unexpected watchdog period")
	}
	t.Setenv("WATCHDOG_USEC", "bad")
	if hostWatchdogInterval02811() != 0 {
		t.Fatal("bad WATCHDOG_USEC accepted")
	}
}

func TestHostServiceUserInstallLifecycle02811(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("user service installers must be tested as an unprivileged user")
	}
	root := t.TempDir()
	jar := filepath.Join(root, "paper.jar")
	if err := os.WriteFile(jar, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeJava01910(t, root, "exit 0")
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--java", java, "--server-jar", jar, "--restart-policy", "never"}); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	// os.UserHomeDir caches HOME? Unix Go consults HOME on each call.
	prev := hostSystemctl02811
	t.Cleanup(func() { hostSystemctl02811 = prev })
	var calls []string
	hostSystemctl02811 = func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }
	args := []string{"install", "--scope", "user", "--name", "host-world", "--server-root", root, "--now"}
	if err := hostServiceHandle02811(args); err != nil {
		t.Fatal(err)
	}
	file, err := hostServiceFile02811("user", "host-world")
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), hostServiceMarker02811) || !strings.Contains(string(content), "Type=notify") {
		t.Fatal("wrong unit content", string(content))
	}
	if strings.Join(calls, "|") != "--user daemon-reload|--user enable --now launcher-host-world.service" {
		t.Fatal("systemctl sequence", calls)
	}
	if err := hostServiceHandle02811(args); err == nil {
		t.Fatal("reinstalled over existing unit")
	}
	if err := hostServiceHandle02811([]string{"uninstall", "--scope", "user", "--name", "host-world"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("unit not removed: %v", err)
	}
	if strings.Join(calls[2:], "|") != "--user disable --now launcher-host-world.service|--user daemon-reload" {
		t.Fatal("uninstall sequence", calls)
	}
	// Failed enable must not leave a partially installed service.
	hostSystemctl02811 = func(args ...string) error {
		if len(args) > 1 && args[1] == "enable" {
			return fmt.Errorf("simulated failure")
		}
		return nil
	}
	if err := hostServiceHandle02811(args); err == nil {
		t.Fatal("enabled after failure")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("install failure did not rollback")
	}
}

func TestHostSystemdUnitParser02811(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "space dir")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	content, err := hostServiceUnit02811(hostServiceSpec02811{Name: "verify", Root: root, Binary: binary, Scope: "system", Component: "host", User: "nobody", Group: "nogroup", StopSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(t.TempDir(), "launcher-verify.service")
	if err = os.WriteFile(unit, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("systemd-analyze", "verify", unit).CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-analyze verify: %v: %s", err, out)
	}
	if strings.Contains(string(out), "Unknown key name") {
		t.Fatalf("unsupported unit directive: %s", out)
	}
}
