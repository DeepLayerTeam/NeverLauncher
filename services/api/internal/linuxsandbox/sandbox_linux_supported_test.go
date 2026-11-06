//go:build linux && (amd64 || arm64)

package linuxsandbox

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func validOptions0319(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "run")
	if e := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); e != nil {
		t.Fatal(e)
	}
	return Options{PayloadRoot: root, Entrypoint: p, HostURL: "http://127.0.0.1:9091", HostHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }),
		Policy: Policy{FilesystemRead: []string{"package"}, FilesystemWrite: []string{"scratch"}, MaxMemoryBytes: 128 << 20, MaxProcesses: 4, MaxCPUPercent: 25, TimeoutSeconds: 30}}
}
func TestPolicyGateAndHostPaths0319(t *testing.T) {
	opt := validOptions0319(t)
	if e := validate(opt); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*Options){
		"backend-secret-path":  func(o *Options) { o.Policy.FilesystemRead = []string{"/var/lib/launcher/.env"} },
		"invalid-shared-mount": func(o *Options) { o.Policy.FilesystemWrite = []string{"shared:../../etc"} },
		"invalid-network":      func(o *Options) { o.Policy.NetworkOutbound = []string{"*.example.com:443"} },
		"invalid-secret":       func(o *Options) { o.Policy.Secrets = []string{"../database"} },
		"unlimited-cpu":        func(o *Options) { o.Policy.MaxCPUPercent = 0 },
		"unlimited-processes":  func(o *Options) { o.Policy.MaxProcesses = 0 },
		"unlimited-memory":     func(o *Options) { o.Policy.MaxMemoryBytes = 0 },
		"unlimited-lifetime":   func(o *Options) { o.Policy.TimeoutSeconds = 0 },
		"non-loopback-host":    func(o *Options) { o.HostURL = "http://0.0.0.0:9091" },
		"out-of-package":       func(o *Options) { o.Entrypoint = "/bin/sh" },
		"missing-handler":      func(o *Options) { o.HostHandler = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := opt
			c.Policy = opt.Policy
			mutate(&c)
			if err := validate(c); err == nil {
				t.Fatalf("Ошибочно принята небезопасная конфигурация: %+v", c)
			}
		})
	}
}
func TestConfigFDIsSealedAndNotOnFilesystem0319(t *testing.T) {
	f, e := sealedConfigFD()
	if e != nil {
		t.Skipf("memfd disabled: %v", e)
	}
	defer f.Close()
	if _, e := f.WriteString("launcher-extension-credential"); e != nil {
		t.Fatal(e)
	}
	if _, e := f.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	const fAddSeals = 1033
	const seals = 1 | 2 | 4 | 8
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), fAddSeals, seals)
	if errno != 0 {
		t.Fatal(errno)
	}
	if _, e := f.WriteString("tamper"); !errors.Is(e, syscall.EPERM) {
		t.Fatalf("sealed FD mutable: %v", e)
	}
}
func TestLinuxIsolationLive0319(t *testing.T) {
	if os.Getenv("NL_RUN_LIVE_LINUX_SANDBOX") != "1" {
		t.Skip("Требуются делегированные cgroup v2 и пространства имён пользователей; запускайте на подготовленном сервере Linux")
	}
	if e := Available(); e != nil {
		t.Fatalf("Возможность запуска изолированной среды недоступна: %v", e)
	}
	opt := validOptions0319(t)
	script := `#!/bin/sh
set -eu
[ ! -e /etc/passwd ] || exit 70
[ ! -e /var/lib/launcher/backend-secrets ] || exit 71
[ ! -e /home ] || exit 72
test -r /package/run
test -w /scratch
! touch /package/forbidden
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
grep -q '^Seccomp:[[:space:]]*2$' /proc/self/status
grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
printf 'sandbox-evidence-ok\n'
`
	if e := os.WriteFile(opt.Entrypoint, []byte(script), 0o700); e != nil {
		t.Fatal(e)
	}
	var stdout, stderr bytes.Buffer
	h, e := Prepare(opt)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	h.Cmd.Stdout = &stdout
	h.Cmd.Stderr = &stderr
	if e := h.Cmd.Start(); e != nil {
		t.Fatal(e)
	}
	if e := h.Started(); e != nil {
		t.Fatalf("Настройка изолированной среды: %v, stderr=%s", e, stderr.String())
	}
	done := make(chan error, 1)
	go func() { done <- h.Cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("Выполнение в изолированной среде: %v, stderr=%s", e, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Изолированная среда не завершилась")
	}
	if !strings.Contains(stdout.String(), "sandbox-evidence-ok") {
		t.Fatalf("Изолированная среда не обеспечила заявленные ограничения: %q %s", stdout.String(), stderr.String())
	}
}

func TestUnsupportedKernelOrMissingDelegationFailsClosed0319(t *testing.T) {
	if Available() == nil {
		t.Skip("Предварительная проверка ядра доступна; соблюдение ограничений проверяется реальным тестом")
	}
	opts := validOptions0319(t)
	h, err := Prepare(opts)
	if err == nil {
		if h != nil {
			h.Close()
		}
		t.Fatal("Сервер без необходимой поддержки ошибочно принял изолированный пакет")
	}
}

func TestBrokerGrantsAcceptedInPrivateNamespace03110(t *testing.T) {
	o := validOptions0319(t)
	o.Policy.FilesystemRead = []string{"package", "shared:reports"}
	o.Policy.FilesystemWrite = []string{"scratch", "shared:reports"}
	o.Policy.NetworkOutbound = []string{"api.example.com:443"}
	o.Policy.Secrets = []string{"api_token"}
	if err := validate(o); err != nil {
		t.Fatalf("valid broker-only grants rejected: %v", err)
	}
}

// Проверяет политику системных вызовов текущей архитектуры; не заменяет запуск
// границы безопасности ядра на целевом оборудовании.
func containsDeniedSyscall0439(n uint32) bool {
	for _, denied := range sandboxDeniedSyscalls {
		if denied == n {
			return true
		}
	}
	return false
}
