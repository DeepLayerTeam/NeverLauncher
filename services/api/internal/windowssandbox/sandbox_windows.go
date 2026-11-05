//go:build windows

package windowssandbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const marker = "LAUNCHER_INTERNAL_WIN_ISOLATION_03111"

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
type childConfig struct {
	Policy                        Policy
	PayloadRoot, Entrypoint       string
	Args, Environment             []string
	Pipe, Ready, Scratch, Profile string
}
type Handle struct {
	Cmd                       *exec.Cmd
	pipe                      *pipeListener
	server                    *http.Server
	ready                     uintptr
	profile, root, entry, sid string
	scratch                   string
	pid                       int
	mu                        sync.Mutex
	closed                    bool
}

func randomName() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func Available() error {
	if err := createProfile.Find(); err != nil {
		return fmt.Errorf("AppContainer API: %w", err)
	}
	if err := initAttrs.Find(); err != nil {
		return fmt.Errorf("Недоступно: STARTUPINFOEX: %w", err)
	}
	if err := createJob.Find(); err != nil {
		return fmt.Errorf("Недоступно: «Job Objects»: %w", err)
	}
	return nil
}
func validate(o Options) error {
	if o.HostHandler == nil {
		return errors.New("sandbox-host-handler-required")
	}
	p := o.Policy
	if p.MaxMemoryBytes < 8<<20 || p.MaxProcesses < 1 || p.MaxCPUPercent < 1 || p.MaxCPUPercent > 100 || p.TimeoutSeconds < 1 {
		return errors.New("sandbox-requires-finite-memory-cpu-pids-time")
	}
	if !filepath.IsAbs(o.PayloadRoot) || !filepath.IsAbs(o.Entrypoint) {
		return errors.New("sandbox-paths-must-be-absolute")
	}
	rel, e := filepath.Rel(o.PayloadRoot, o.Entrypoint)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return errors.New("sandbox-entrypoint-outside-package")
	}
	if !strings.EqualFold(filepath.Ext(o.Entrypoint), ".exe") {
		return errors.New("sandbox-windows-only-exe-target-supported")
	}
	if !strings.HasPrefix(o.HostURL, "http://127.0.0.1:") {
		return errors.New("sandbox-host-must-use-localhost")
	} // к этому адресу обращается только родительский процесс
	for _, x := range p.FilesystemRead {
		if x != "package" {
			return errors.New("sandbox-invalid-filesystem-read")
		}
	}
	for _, x := range p.FilesystemWrite {
		if x != "scratch" {
			return errors.New("sandbox-invalid-filesystem-write")
		}
	}
	if e = validatePackageTree(o.PayloadRoot, o.Entrypoint); e != nil {
		return e
	}
	return nil
}

// icacls /T работает рекурсивно и на некоторых конфигурациях файловой системы переходит по reparse points.
// Никогда не выдавать sandbox SID разрешения через junction,
// символьную ссылку, точку монтирования или иной reparse tag, включая родительский каталог пакета.
func validatePackageTree(root, entry string) error {
	for dir := filepath.Clean(root); ; dir = filepath.Dir(dir) {
		if err := rejectReparsePoint(dir); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("sandbox-package-not-directory")
	}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return rejectReparsePoint(path)
	}); err != nil {
		return err
	}
	info, err = os.Stat(entry)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("sandbox-entrypoint-not-regular-file")
	}
	return nil
}

// Использовать системные инструменты ОС, а не выбранный по PATH исполняемый файл, который
// менее привилегированная учётная запись могла бы разместить перед доверенным системным каталогом.
func systemICACLS() (string, error) {
	root := os.Getenv("SystemRoot")
	if !filepath.IsAbs(root) {
		return "", errors.New("sandbox-SystemRoot-unavailable")
	}
	tool := filepath.Join(root, "System32", "icacls.exe")
	if err := rejectReparsePoint(tool); err != nil {
		return "", err
	}
	return tool, nil
}

func createPipe(path, sid string, firstInstance bool) (uintptr, error) {
	// Явный SID экземпляра: без wildcard AppContainer, анонимных пользователей или сетевых клиентов.
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")S:(ML;;NW;;;LW)"
	sd, e := securityDescriptor(sddl)
	if e != nil {
		return 0, e
	}
	defer localFree.Call(sd)
	sa := struct {
		Length     uint32
		Descriptor uintptr
		Inherit    uint32
	}{uint32(unsafe.Sizeof(uint32(0)) + 2*unsafe.Sizeof(uintptr(0))), sd, 0}
	// Смещение SECURITY_ATTRIBUTES после Length в 64-битном варианте равно 8; используйте структуру нативной раскладки.
	sa.Length = uint32(unsafe.Sizeof(sa))
	openMode := uintptr(0x00000003) // PIPE_ACCESS_DUPLEX, synchronous
	if firstInstance {
		openMode |= 0x00080000
	} // FILE_FLAG_FIRST_PIPE_INSTANCE
	h, _, err := createNamedPipe.Call(uintptr(unsafe.Pointer(utf16(path))), openMode,
		0x00000008, 255, 64<<10, 64<<10, 0, uintptr(unsafe.Pointer(&sa))) // PIPE_REJECT_REMOTE_CLIENTS
	if h == ^uintptr(0) {
		return 0, fmt.Errorf("CreateNamedPipe: %w", err)
	}
	return h, nil
}
func acceptPipe(h uintptr) error {
	r, _, e := connectNamedPipe.Call(h, 0)
	if r != 0 {
		return nil
	}
	if e == syscall.Errno(535) {
		return nil
	} // ERROR_PIPE_CONNECTED
	return fmt.Errorf("ConnectNamedPipe: %w", e)
}

type pipeAddr string

func (p pipeAddr) Network() string { return "winpipe" }
func (p pipeAddr) String() string  { return string(p) }

type pipeConn struct {
	f    *os.File
	addr string
}

func (c *pipeConn) Read(b []byte) (int, error)       { return c.f.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error)      { return c.f.Write(b) }
func (c *pipeConn) Close() error                     { return c.f.Close() }
func (c *pipeConn) LocalAddr() net.Addr              { return pipeAddr(c.addr) }
func (c *pipeConn) RemoteAddr() net.Addr             { return pipeAddr(c.addr) }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeListener struct {
	path, sid string
	mu        sync.Mutex
	closed    bool
	pending   uintptr
}

func (l *pipeListener) Accept() (net.Conn, error) {
	h, e := createPipe(l.path, l.sid, false)
	if e != nil {
		return nil, e
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		closeHandle(h)
		return nil, net.ErrClosed
	}
	l.pending = h
	l.mu.Unlock()
	e = acceptPipe(h)
	l.mu.Lock()
	l.pending = 0
	closed := l.closed
	l.mu.Unlock()
	if e != nil || closed {
		closeHandle(h)
		if closed {
			return nil, net.ErrClosed
		}
		return nil, e
	}
	return &pipeConn{f: os.NewFile(h, "extension-host-winpipe"), addr: l.path}, nil
}
func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.pending != 0 {
		closeHandle(l.pending)
		l.pending = 0
	}
	return nil
}
func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.path) }
func (h *Handle) HostPipe() string {
	if h.pipe == nil {
		return ""
	}
	return h.pipe.path
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
	h.mu.Unlock()
	if h.Cmd != nil && h.Cmd.Process != nil {
		_ = h.Cmd.Process.Kill()
	}
	if h.server != nil {
		_ = h.server.Close()
	}
	if h.pipe != nil {
		_ = h.pipe.Close()
	}
	if h.ready != 0 {
		closeHandle(h.ready)
	}
	if h.root != "" && h.sid != "" {
		if tool, err := systemICACLS(); err == nil {
			// Пакет мог измениться, пока расширение работало.
			// При очистке никогда не обходить рекурсивно недавно вставленный junction.
			if validatePackageTree(h.root, h.entry) == nil {
				_ = exec.Command(tool, h.root, "/remove:g", "*"+h.sid, "/T").Run()
			}
		}
	}
	if h.profile != "" {
		destroyProfile(h.profile)
	}
}
func (h *Handle) Started() error {
	if h.ready == 0 {
		return errors.New("sandbox-not-initialized")
	}
	// Канал ready создан со случайным именем и ACL. Это рукопожатие
	// отправляется только после помещения целевого процесса в Job и его возобновления.
	ch := make(chan error, 1)
	go func() {
		if e := acceptPipe(h.ready); e != nil {
			ch <- e
			return
		}
		b := make([]byte, 512)
		n, e := syscall.Read(syscall.Handle(h.ready), b)
		if e != nil {
			ch <- e
			return
		}
		v := strings.TrimSpace(string(b[:n]))
		if strings.HasPrefix(v, "OK ") {
			pid, e := strconv.Atoi(strings.TrimPrefix(v, "OK "))
			if e == nil && pid > 0 {
				h.mu.Lock()
				h.pid = pid
				h.mu.Unlock()
				// Целевой процесс ещё не возобновлён. Явный ACK делает
				// невозможной гонку /v1/hello с регистрацией PID.
				var written uint32
				if e := syscall.WriteFile(syscall.Handle(h.ready), []byte("RESUME\n"), &written, nil); e != nil {
					ch <- e
					return
				}
				m := make([]byte, 256)
				n, e := syscall.Read(syscall.Handle(h.ready), m)
				if e != nil {
					ch <- e
					return
				}
				if strings.TrimSpace(string(m[:n])) != "ACTIVE" {
					ch <- fmt.Errorf("sandbox child did not resume: %s", strings.TrimSpace(string(m[:n])))
					return
				}
				ch <- nil
				return
			}
		}
		ch <- fmt.Errorf("Ошибка: «sandbox launch»: %s", v)
	}()
	select {
	case e := <-ch:
		if e != nil {
			h.Close()
		}
		return e
	case <-time.After(15 * time.Second):
		h.Close()
		return errors.New("sandbox child startup timeout")
	}
}
func Prepare(o Options) (*Handle, error) {
	if e := validate(o); e != nil {
		return nil, e
	}
	if e := Available(); e != nil {
		return nil, e
	}
	id := randomName()
	if id == "" {
		return nil, errors.New("Недоступно: «secure random»")
	}
	profile := "LauncherExt" + id
	sidPtr, sid, e := newProfile(profile)
	if e != nil {
		return nil, e
	}
	defer freeSID(sidPtr)
	h := &Handle{profile: profile, root: o.PayloadRoot, entry: o.Entrypoint, sid: sid}
	fail := func(err error) (*Handle, error) { h.Close(); return nil, err }
	scratch, e := profilePath(sidPtr)
	if e != nil {
		return fail(e)
	}
	h.scratch = scratch
	if e = os.MkdirAll(scratch, 0o700); e != nil {
		return fail(e)
	}
	// Разрешение чтения/исполнения выдаётся ТОЛЬКО подписанному неизменяемому пакету; общие каталоги хоста
	// получают ACL. Общие файлы доступны через брокер.
	tool, e := systemICACLS()
	if e != nil {
		return fail(e)
	}
	// Повторно проверить непосредственно перед рекурсивной выдачей прав. Без /C: любая
	// ошибка подкаталога фатальна, а не незаметно частично открытый пакет.
	if e = validatePackageTree(o.PayloadRoot, o.Entrypoint); e != nil {
		return fail(e)
	}
	if output, e := exec.Command(tool, o.PayloadRoot, "/grant", "*"+sid+":(OI)(CI)(RX)", "/T").CombinedOutput(); e != nil {
		return fail(fmt.Errorf("package AppContainer ACL: %w: %s", e, string(output)))
	}
	pipeName := `\\.\pipe\LOCAL\Launcher-Extension-` + id
	readyName := `\\.\pipe\LOCAL\Launcher-Ready-` + id
	ready, e := createPipe(readyName, "AU", true)
	if e != nil {
		return fail(e)
	}
	h.ready = ready
	h.pipe = &pipeListener{path: pipeName, sid: sid}
	h.server = &http.Server{Handler: o.HostHandler, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() { _ = h.server.Serve(h.pipe) }()
	config := childConfig{Policy: o.Policy, PayloadRoot: o.PayloadRoot, Entrypoint: o.Entrypoint, Args: o.Args, Environment: o.Environment, Pipe: pipeName, Ready: readyName, Scratch: scratch, Profile: profile}
	raw, e := json.Marshal(config)
	if e != nil {
		return fail(e)
	}
	exe, e := os.Executable()
	if e != nil {
		return fail(e)
	}
	cmd := exec.Command(exe, "--launcher-windows-sandbox-03111")
	cmd.Env = []string{marker + "=1", "SystemRoot=" + os.Getenv("SystemRoot"), "WINDIR=" + os.Getenv("WINDIR")}
	cmd.Stdin = bytes.NewReader(raw)
	h.Cmd = cmd
	return h, nil
}
func signalReady(path, msg string) {
	p := utf16(path)
	h, err := syscall.CreateFile(p, syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(h)
	b := []byte(msg)
	var n uint32
	_ = syscall.WriteFile(h, b, &n, nil)
}
func runChild() {
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 256<<10))
	if e != nil {
		os.Exit(110)
	}
	var c childConfig
	if e = json.Unmarshal(raw, &c); e != nil {
		os.Exit(111)
	}
	if c.Profile == "" || c.Ready == "" || c.Pipe == "" || c.Policy.MaxProcesses < 1 {
		os.Exit(112)
	}
	sidPtr, _, e := newProfile(c.Profile)
	if e != nil {
		signalReady(c.Ready, "ERROR profile: "+e.Error())
		os.Exit(113)
	}
	defer freeSID(sidPtr)
	proc, thread, job, pid, e := createIsolatedProcess(c, sidPtr)
	if e != nil {
		signalReady(c.Ready, "ERROR launch: "+e.Error())
		os.Exit(114)
	}
	defer closeHandle(proc)
	defer closeHandle(job)
	defer closeHandle(thread)
	pipeHandle, e := syscall.CreateFile(utf16(c.Ready), syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		terminateJob.Call(job, 1)
		os.Exit(118)
	}
	defer syscall.CloseHandle(pipeHandle)
	send := func(msg string) error { var n uint32; return syscall.WriteFile(pipeHandle, []byte(msg), &n, nil) }
	if e = send("OK " + strconv.FormatUint(uint64(pid), 10) + "\n"); e != nil {
		terminateJob.Call(job, 1)
		os.Exit(119)
	}
	ack := make([]byte, 32)
	n, e := syscall.Read(pipeHandle, ack)
	if e != nil || strings.TrimSpace(string(ack[:n])) != "RESUME" {
		terminateJob.Call(job, 1)
		os.Exit(120)
	}
	r, _, resumeErr := resumeThread.Call(thread)
	if r == ^uintptr(0) {
		_ = send("ERROR resume: " + resumeErr.Error())
		terminateJob.Call(job, 1)
		os.Exit(121)
	}
	if e = send("ACTIVE\n"); e != nil {
		terminateJob.Call(job, 1)
		os.Exit(122)
	}
	closeHandle(thread)
	thread = 0
	// Дескриптор Job остаётся открытым весь срок работы помощника. Закрытие последнего дескриптора
	// заставляет ядро завершить всех потомков (без флагов BREAKAWAY).
	ms := uintptr(c.Policy.TimeoutSeconds) * 1000
	r, _, _ = waitObject.Call(proc, ms)
	if r == 0x102 {
		terminateJob.Call(job, 1)
		os.Exit(115)
	} // WAIT_TIMEOUT
	if r != 0 {
		terminateJob.Call(job, 1)
		os.Exit(116)
	}
	var code uint32
	ok, _, _ := getExitCode.Call(proc, uintptr(unsafe.Pointer(&code)))
	if ok == 0 {
		os.Exit(117)
	}
	os.Exit(int(code))
}
func init() {
	if os.Getenv(marker) == "1" {
		runChild()
	}
}
