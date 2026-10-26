//go:build windows

package windowssandbox

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testOptions03111(root, entry string) Options {
	return Options{PayloadRoot: root, Entrypoint: entry, HostURL: "http://127.0.0.1:7000", HostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("broker-ok")) }), Policy: Policy{FilesystemRead: []string{"package"}, FilesystemWrite: []string{"scratch"}, MaxMemoryBytes: 256 << 20, MaxProcesses: 1, MaxCPUPercent: 75, TimeoutSeconds: 30}}
}
func TestFailClosedWindowsSandboxPolicy03111(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "app.exe")
	_ = os.WriteFile(entry, []byte("fixture"), 0600)
	for name, edit := range map[string]func(*Options){
		"no-memory":            func(o *Options) { o.Policy.MaxMemoryBytes = 0 },
		"no-job-pids":          func(o *Options) { o.Policy.MaxProcesses = 0 },
		"no-cpu-limit":         func(o *Options) { o.Policy.MaxCPUPercent = 0 },
		"no-lifetime":          func(o *Options) { o.Policy.TimeoutSeconds = 0 },
		"outside-executable":   func(o *Options) { o.Entrypoint = `C:\\Windows\\System32\\calc.exe` },
		"script-target":        func(o *Options) { o.Entrypoint = filepath.Join(root, "app.ps1") },
		"missing-handler":      func(o *Options) { o.HostHandler = nil },
		"non-loopback-backend": func(o *Options) { o.HostURL = "http://0.0.0.0:7000" },
	} {
		t.Run(name, func(t *testing.T) {
			o := testOptions03111(root, entry)
			edit(&o)
			if e := validate(o); e == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func TestChildIsolation03111(t *testing.T) {
	if os.Getenv("NL_WIN_SANDBOX_CHILD") != "1" {
		return
	}
	pipe := os.Getenv("NEVERLAUNCHER_EXTENSION_HOST_PIPE")
	if !strings.HasPrefix(pipe, `\\.\pipe\LOCAL\NeverLauncher-Extension-`) {
		t.Fatal("missing named broker pipe")
	}
	handle, err := syscall.CreateFile(syscall.StringToUTF16Ptr(pipe), syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("broker pipe inaccessible: %v", err)
	}
	f := os.NewFile(uintptr(handle), "host-pipe")
	defer f.Close()
	_, err = f.Write([]byte("GET /health HTTP/1.1\r\nHost: internal\r\nConnection: close\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil || !strings.Contains(string(b), "broker-ok") {
		t.Fatalf("broker response %v %q", err, string(b))
	}
	if _, err = os.ReadFile(os.Getenv("NL_WIN_PRIVATE_FILE")); err == nil {
		t.Fatal("private backend file readable")
	}
	if err = os.WriteFile(os.Getenv("NL_WIN_PACKAGE_EXECUTABLE"), []byte("tampered"), 0600); err == nil {
		t.Fatal("immutable package writable")
	}
	c, done := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer done()
	conn, err := (&net.Dialer{}).DialContext(c, "tcp", "1.1.1.1:443")
	if err == nil {
		conn.Close()
		t.Fatal("direct outbound connection possible")
	}
	cmd := exec.Command(os.Getenv("NL_WIN_PACKAGE_EXECUTABLE"), "-test.run=NoSuchTest")
	if err = cmd.Run(); err == nil {
		t.Fatal("process tree escaped active-process job limit")
	}
}
func TestRealWindowsAppContainerAndJob03111(t *testing.T) {
	if os.Getenv("NL_RUN_LIVE_WIN_SANDBOX") != "1" {
		t.Skip("requires actual Windows AppContainer + Job Object; enable in Windows acceptance CI")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	entry := filepath.Join(root, "fixture.exe")
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(entry, data, 0700); err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(t.TempDir(), "backend-secret.txt")
	if err = os.WriteFile(priv, []byte("do-not-read"), 0600); err != nil {
		t.Fatal(err)
	}
	o := testOptions03111(root, entry)
	o.Args = []string{"-test.run=^TestChildIsolation03111$", "-test.v"}
	o.Environment = []string{"NL_WIN_SANDBOX_CHILD=1", "NL_WIN_PRIVATE_FILE=" + priv, "NL_WIN_PACKAGE_EXECUTABLE=" + entry, "SystemRoot=" + os.Getenv("SystemRoot"), "PATH=" + os.Getenv("PATH")}
	h, err := Prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var output strings.Builder
	h.Cmd.Stdout = &output
	h.Cmd.Stderr = &output
	if err = h.Cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err = h.Started(); err != nil {
		t.Fatalf("token+job+pipe not enforced: %v; %s", err, output.String())
	}
	if h.PID() <= 0 {
		t.Fatal("missing true isolated process PID")
	}
	if err = h.Cmd.Wait(); err != nil {
		t.Fatalf("child test failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "PASS") {
		t.Fatalf("child did not complete: %s", output.String())
	}
}
