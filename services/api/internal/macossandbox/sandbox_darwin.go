//go:build darwin

package macossandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxExecutable = 64 << 20

type Policy struct {
	FilesystemRead, FilesystemWrite, NetworkOutbound, Secrets []string
	MaxMemoryBytes                                            int64
	MaxProcesses, MaxCPUPercent, TimeoutSeconds               int
}
type Options struct {
	Policy                  Policy
	PayloadRoot, Entrypoint string
	Args, Environment       []string
	HostURL                 string
	HostHandler             http.Handler
}
type payloadHeader struct {
	Size           int      `json:"size"`
	SHA256         string   `json:"sha256"`
	Args           []string `json:"args"`
	Environment    []string `json:"environment"`
	MemoryBytes    int64    `json:"memoryBytes"`
	CPUPercent     int      `json:"cpuPercent"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}
type Handle struct {
	Cmd                                                             *exec.Cmd
	guest, hostFile, configRead, configWrite, readyRead, readyWrite *os.File
	server                                                          *http.Server
	httpConn                                                        net.Conn
	id                                                              string
	data                                                            []byte
	header                                                          []byte
	pid                                                             int
	timer                                                           *time.Timer
	mu                                                              sync.Mutex
	closed                                                          bool
}

func (h *Handle) HostPipe() string {
	if h == nil {
		return ""
	}
	return h.id
}
func (h *Handle) PID() int { h.mu.Lock(); defer h.mu.Unlock(); return h.pid }
func (h *Handle) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	if h.timer != nil {
		h.timer.Stop()
	}
	pid := 0
	if h.Cmd != nil && h.Cmd.Process != nil {
		pid = h.Cmd.Process.Pid
	}
	h.mu.Unlock()
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	} // helper and descendants share process group
	if h.server != nil {
		_ = h.server.Close()
	}
	if h.httpConn != nil {
		_ = h.httpConn.Close()
	}
	for _, f := range []*os.File{h.guest, h.hostFile, h.configRead, h.configWrite, h.readyRead, h.readyWrite} {
		if f != nil {
			_ = f.Close()
		}
	}
}
func teamID() (string, error) {
	v := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_MACOS_SANDBOX_TEAM_ID"))
	if len(v) != 10 {
		return "", errors.New("sandbox-macos-signed-team-id-required")
	}
	for _, c := range v {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return "", errors.New("sandbox-macos-invalid-team-id")
		}
	}
	return v, nil
}
func helperPath() (string, error) {
	p := strings.TrimSpace(os.Getenv("NEVERLAUNCHER_MACOS_SANDBOX_HELPER"))
	if !filepath.IsAbs(p) {
		return "", errors.New("sandbox-macos-absolute-helper-path-required")
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 {
		return "", errors.New("sandbox-macos-helper-not-regular-or-is-group-writable")
	}
	return p, nil
}
func signedHelper() (string, error) {
	p, err := helperPath()
	if err != nil {
		return "", err
	}
	team, err := teamID()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := `anchor apple generic and certificate leaf[subject.OU] = "` + team + `"`
	if b, e := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--verbose=2", "--test-requirement", req, p).CombinedOutput(); e != nil {
		return "", fmt.Errorf("sandbox-macos-helper-signature: %w: %.300s", e, b)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	b, e := exec.CommandContext(ctx2, "/usr/bin/codesign", "--display", "--entitlements", ":-", p).CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("sandbox-macos-helper-entitlements: %w", e)
	}
	start := bytes.Index(b, []byte("<?xml"))
	end := bytes.Index(b, []byte("</plist>"))
	if start < 0 || end < start {
		return "", errors.New("sandbox-macos-helper-entitlements-xml-required")
	}
	xml := b[start : end+len("</plist>")]
	cmd := exec.CommandContext(ctx2, "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	cmd.Stdin = bytes.NewReader(xml)
	parsed, e := cmd.Output()
	if e != nil {
		return "", fmt.Errorf("sandbox-macos-helper-invalid-entitlements: %w", e)
	}
	var entries map[string]any
	if e = json.Unmarshal(parsed, &entries); e != nil {
		return "", e
	}
	if entries["com.apple.security.app-sandbox"] != true || entries["com.apple.security.inherit"] != nil {
		return "", errors.New("sandbox-macos-helper-missing-app-sandbox-or-inherits")
	}
	for k := range entries {
		switch k {
		case "com.apple.security.app-sandbox", "com.apple.application-identifier", "com.apple.developer.team-identifier":
		default:
			return "", fmt.Errorf("sandbox-macos-helper-overprivileged-entitlement: %s", k)
		}
	}
	return p, nil
}
func Available() error { _, e := signedHelper(); return e }
func Prepare(o Options) (_ *Handle, err error) {
	if o.HostHandler == nil || !strings.HasPrefix(o.HostURL, "http://127.0.0.1:") {
		return nil, errors.New("sandbox-macos-host-handler-and-loopback-required")
	}
	if e := ValidateGrants(o.Policy.FilesystemRead, o.Policy.FilesystemWrite, o.Policy.NetworkOutbound, o.Policy.Secrets); e != nil {
		return nil, e
	}
	if o.Policy.MaxMemoryBytes < 64<<20 || o.Policy.MaxProcesses < 1 || o.Policy.MaxCPUPercent < 1 || o.Policy.MaxCPUPercent > 100 || o.Policy.TimeoutSeconds < 1 {
		return nil, errors.New("sandbox-macos-finite-resource-policy-required")
	}
	if !IsInside(o.PayloadRoot, o.Entrypoint) {
		return nil, errors.New("sandbox-macos-entrypoint-must-be-within-package")
	}
	if len(o.Args) > 128 {
		return nil, errors.New("sandbox-macos-too-many-arguments")
	}
	for _, a := range o.Args {
		if len(a) > 16384 || strings.IndexByte(a, 0) >= 0 {
			return nil, errors.New("sandbox-macos-invalid-argument")
		}
	}
	fi, e := os.Lstat(o.Entrypoint)
 if e != nil { return nil,e }
 if !fi.Mode().IsRegular() || fi.Size() <= 0 || fi.Size() > maxExecutable {return nil,errors.New("sandbox-macos-native-executable-size-or-file-type-unsupported")}
 executable, e := os.ReadFile(o.Entrypoint)
	if e != nil {
		return nil, e
	}
	if len(executable) == 0 || len(executable) > maxExecutable {
		return nil, errors.New("sandbox-macos-native-executable-size-unsupported")
	}
	parsed, e := macho.NewFile(bytes.NewReader(executable))
	if e != nil {
		return nil, fmt.Errorf("sandbox-macos-native-mach-o-required: %w", e)
	}
	defer parsed.Close()
	if parsed.Type != macho.TypeExec {
		return nil, errors.New("sandbox-macos-requires-native-mach-o-executable")
	}
	if runtime.GOARCH == "arm64" && parsed.Cpu != macho.CpuArm64 || runtime.GOARCH == "amd64" && parsed.Cpu != macho.CpuAmd64 {
		return nil, errors.New("sandbox-macos-architecture-mismatch")
	}
	helper, e := signedHelper()
	if e != nil {
		return nil, e
	}
	var rnd [16]byte
	if _, e = rand.Read(rnd[:]); e != nil {
		return nil, e
	}
	digest := sha256.Sum256(executable)
	header, e := json.Marshal(payloadHeader{Size: len(executable), SHA256: hex.EncodeToString(digest[:]), Args: o.Args, Environment: o.Environment, MemoryBytes: o.Policy.MaxMemoryBytes, CPUPercent: o.Policy.MaxCPUPercent, TimeoutSeconds: o.Policy.TimeoutSeconds})
	if e != nil {
		return nil, e
	}
	if len(header) > 32<<10 {
		return nil, errors.New("sandbox-macos-header-too-large")
	}
	pair, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if e != nil {
		return nil, e
	}
	h := &Handle{data: executable, header: append(header, '\n'), id: "nlmac:" + hex.EncodeToString(rnd[:])}
	defer func() {
		if err != nil {
			h.Close()
		}
	}()
	h.hostFile = os.NewFile(uintptr(pair[0]), "macos-host-http")
	h.guest = os.NewFile(uintptr(pair[1]), "macos-guest-http")
	h.configRead, h.configWrite, e = os.Pipe()
	if e != nil {
		err = e
		return nil, err
	}
	h.readyRead, h.readyWrite, e = os.Pipe()
	if e != nil {
		err = e
		return nil, err
	}
	h.Cmd = exec.Command(helper)
	h.Cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	h.Cmd.ExtraFiles = []*os.File{h.configRead, h.guest, h.readyWrite}
	h.Cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	conn, e := net.FileConn(h.hostFile)
	if e != nil {
		err = e
		return nil, err
	}
	h.httpConn = conn
	h.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.RemoteAddr = h.id; o.HostHandler.ServeHTTP(w, r) }), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 12 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = h.server.Serve(&singleListener{conn: conn, done: make(chan struct{})}) }()
	return h, nil
}

type singleListener struct {
	conn     net.Conn
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	accepted bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error   { l.once.Do(func() { close(l.done) }); return l.conn.Close() }
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }
func (h *Handle) Started() error {
	if h.Cmd == nil || h.Cmd.Process == nil {
		return errors.New("sandbox-macos-helper-not-started")
	}
	_ = h.configRead.Close()
	_ = h.guest.Close()
	_ = h.readyWrite.Close()
	send := make(chan error, 1)
	go func() {
		_, e := h.configWrite.Write(h.header)
		if e == nil {
			_, e = io.Copy(h.configWrite, bytes.NewReader(h.data))
		}
		_ = h.configWrite.Close()
		send <- e
	}()
	ready := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		n, e := h.readyRead.Read(buf)
		if e != nil {
			ready <- e
			return
		}
		s := strings.TrimSpace(string(buf[:n]))
		if !strings.HasPrefix(s, "ready ") {
			ready <- fmt.Errorf("sandbox-macos-helper-refused: %.110s", s)
			return
		}
		pid, e := strconv.Atoi(strings.TrimPrefix(s, "ready "))
		if e != nil || pid <= 0 {
			ready <- errors.New("sandbox-macos-helper-invalid-child-pid")
			return
		}
		h.mu.Lock()
		h.pid = pid
		h.mu.Unlock()
		ready <- nil
	}()
	select {
	case e := <-send:
		if e != nil {
			h.Close()
			return fmt.Errorf("sandbox-macos-payload: %w", e)
		}
	case <-time.After(8 * time.Second):
		h.Close()
		return errors.New("sandbox-macos-payload-timeout")
	}
	select {
	case e := <-ready:
		if e != nil {
			h.Close()
			return e
		}
	case <-time.After(8 * time.Second):
		h.Close()
		return errors.New("sandbox-macos-helper-ready-timeout")
	}
	h.mu.Lock()
	if !h.closed {
		h.timer = time.AfterFunc(time.Duration(hPayloadTimeout(h.header))*time.Second, func() { h.Close() })
	}
	h.mu.Unlock()
	return nil
}
func hPayloadTimeout(raw []byte) int {
	var p payloadHeader
	if json.Unmarshal(bytes.TrimSpace(raw), &p) != nil {
		return 1
	}
	return p.TimeoutSeconds
}
