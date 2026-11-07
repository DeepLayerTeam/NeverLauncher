//go:build linux && (amd64 || arm64)

// Пакет linuxsandbox запускает недоверенные расширения в linux/amd64 и linux/arm64 внутри пространств имён
// user/mount/pid/ipc/uts/network с ограничениями ядра и cgroup v2. Он намеренно не поддерживает общие
// разрешения до готовности брокера с ограниченными полномочиями. Группа процессов никогда не считается
// песочницей.
package linuxsandbox

import (
	"bufio"
	"context"
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
	"unsafe"
)

const marker = "LAUNCHER_INTERNAL_LINUX_SANDBOX_0319"

type Policy struct {
	FilesystemRead  []string
	FilesystemWrite []string
	NetworkOutbound []string
	Secrets         []string
	MaxMemoryBytes  int64
	MaxProcesses    int
	MaxCPUPercent   int
	TimeoutSeconds  int
}
type Options struct {
	Policy      Policy
	PayloadRoot string
	Entrypoint  string
	Args        []string
	Environment []string
	HostURL     string
	HostHandler http.Handler
}

type Handle struct {
	Cmd        *exec.Cmd
	cgroup     string
	rootDir    string
	sources    []*os.File
	hostConn   net.Conn
	hostServer *http.Server
	mu         sync.Mutex
	closed     bool
	timer      *time.Timer
	lifetime   time.Duration
}

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
	h.mu.Unlock()
	// cgroup.kill завершает процессы, даже если они покинули исходную группу процессов.
	if h.cgroup != "" {
		_ = os.WriteFile(filepath.Join(h.cgroup, "cgroup.kill"), []byte("1"), 0o600)
	}
	if h.hostServer != nil {
		_ = h.hostServer.Close()
	}
	if h.hostConn != nil {
		_ = h.hostConn.Close()
	}
	for _, f := range h.sources {
		_ = f.Close()
	}
	if h.cgroup != "" {
		for i := 0; i < 30; i++ {
			if err := os.Remove(h.cgroup); err == nil || errors.Is(err, os.ErrNotExist) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if h.rootDir != "" {
		_ = os.RemoveAll(h.rootDir)
	}
}

// Available — только предварительная проверка, не доказательство изоляции. Ready() ниже подтверждает
// настройку пространств имён, монтирования, no_new_privs и seccomp.
func Available() error {
	if os.Geteuid() == 0 {
		return errors.New("sandbox-requires-unprivileged-service-identity")
	}
	if _, err := os.Stat("/proc/self/ns/user"); err != nil {
		return errors.New("sandbox-user-namespaces-unavailable")
	}
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if n == 0 {
			return errors.New("sandbox-user-namespaces-disabled")
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(b)) == "0" {
		return errors.New("sandbox-unprivileged-userns-disabled")
	}
	_, err := delegatedCgroup()
	return err
}
func delegatedCgroup() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	var rel string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if rel == "" || !strings.HasPrefix(rel, "/") {
		return "", errors.New("sandbox-cgroup-v2-required")
	}
	root := "/sys/fs/cgroup"
	path := filepath.Join(root, rel)
	if path != root && !strings.HasPrefix(path, root+"/") {
		return "", errors.New("sandbox-invalid-cgroup-path")
	}
	for _, v := range []string{"memory", "pids", "cpu"} {
		b, err := os.ReadFile(filepath.Join(path, "cgroup.controllers"))
		if err != nil {
			return "", fmt.Errorf("sandbox-cgroup-delegation: %w", err)
		}
		found := false
		for _, controller := range strings.Fields(string(b)) {
			if controller == v {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("sandbox-cgroup-controller-%s-unavailable", v)
		}
	}
	// Создание дочернего процесса — единственный надёжный способ проверить делегирование. Наличие читаемой
	// файловой системы cgroup без права записи не доказывает изоляцию.
	return path, nil
}
func validate(o Options) error {
	p := o.Policy
	if p.MaxMemoryBytes <= 0 || p.MaxProcesses <= 0 || p.MaxCPUPercent <= 0 || p.MaxCPUPercent > 100 || p.TimeoutSeconds <= 0 {
		return errors.New("sandbox-requires-finite-memory-pids-cpu-time")
	}
	// Разрешения с ограниченной областью передаются исключительно брокеру возможностей хоста через
	// аутентифицированную пару сокетов. В этом пространстве имён нет сети хоста и общих монтирований, поэтому
	// проверки политики брокера обойти нельзя.
	for _, grant := range p.FilesystemRead {
		if grant != "package" && !validSharedGrant03110(grant) {
			return errors.New("sandbox-invalid-read-grant")
		}
	}
	for _, grant := range p.FilesystemWrite {
		if grant != "scratch" && !validSharedGrant03110(grant) {
			return errors.New("sandbox-invalid-write-grant")
		}
	}
	for _, grant := range p.Secrets {
		if !validResourceName03110(grant) {
			return errors.New("sandbox-invalid-secret-grant")
		}
	}
	for _, grant := range p.NetworkOutbound {
		if !validDestination03110(grant) {
			return errors.New("sandbox-invalid-network-grant")
		}
	}
	if o.HostHandler == nil {
		return errors.New("sandbox-host-handler-required")
	}
	if !strings.HasPrefix(o.HostURL, "http://127.0.0.1:") {
		return errors.New("sandbox-requires-loopback-host-protocol")
	}
	if len(o.Args) > 129 {
		return errors.New("sandbox-too-many-arguments")
	}
	if !filepath.IsAbs(o.PayloadRoot) || !filepath.IsAbs(o.Entrypoint) {
		return errors.New("sandbox-paths-must-be-absolute")
	}
	rel, err := filepath.Rel(o.PayloadRoot, o.Entrypoint)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return errors.New("sandbox-entrypoint-outside-package")
	}
	if _, err := os.Stat(o.Entrypoint); err != nil {
		return err
	}
	return nil
}
func makeCgroup(p Policy) (string, *os.File, error) {
	parent, err := delegatedCgroup()
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(parent, "nl-ext-0319-")
	if err != nil {
		return "", nil, fmt.Errorf("sandbox-cgroup-not-delegated: %w", err)
	}
	fail := func(err error) (string, *os.File, error) { _ = os.Remove(dir); return "", nil, err }
	for key, val := range map[string]string{
		"memory.max":      strconv.FormatInt(p.MaxMemoryBytes, 10),
		"memory.swap.max": "0",
		"pids.max":        strconv.Itoa(p.MaxProcesses + 1), // bootstrap supervisor occupies one PID
		"cpu.max":         fmt.Sprintf("%d 100000", 100000*p.MaxCPUPercent/100),
	} {
		if e := os.WriteFile(filepath.Join(dir, key), []byte(val), 0o600); e != nil {
			return fail(fmt.Errorf("sandbox-cgroup-%s: %w", key, e))
		}
	}
	// cgroup.kill обязателен, это не необязательная очистка. Без него расширение, создавшее другую группу
	// процессов, может пережить Close() или истечение срока.
	if err := requireCgroupKill03120(dir); err != nil {
		return fail(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		return fail(err)
	}
	return dir, f, nil
}
func requireCgroupKill03120(path string) error {
	fi, err := os.Stat(filepath.Join(path, "cgroup.kill"))
	if err != nil {
		return fmt.Errorf("sandbox-cgroup-kill-required: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return errors.New("sandbox-cgroup-kill-not-regular")
	}
	// На этом этапе новая cgroup пуста. Запись 1 доказывает, что делегирование действительно позволяет позже
	// завершать всех потомков, а не просто наличие псевдофайла cgroup.kill.
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0); err != nil {
		return fmt.Errorf("sandbox-cgroup-kill-not-writable: %w", err)
	}
	return nil
}

func Prepare(o Options) (*Handle, error) {
	if err := validate(o); err != nil {
		return nil, err
	}
	if err := Available(); err != nil {
		return nil, err
	}
	cgroup, cfd, err := makeCgroup(o.Policy)
	if err != nil {
		return nil, err
	}
	h := &Handle{cgroup: cgroup, sources: []*os.File{cfd}, lifetime: time.Duration(o.Policy.TimeoutSeconds) * time.Second}
	defer func() {
		if err != nil {
			h.Close()
		}
	}()
	root, e := os.MkdirTemp("/tmp", "nl-sandbox-0319-")
	if e != nil {
		err = e
		return nil, err
	}
	h.rootDir = root
	pair, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		err = e
		return nil, err
	}
	hostFile := os.NewFile(uintptr(pair[0]), "host-http")
	guestFile := os.NewFile(uintptr(pair[1]), "guest-http")
	h.sources = append(h.sources, hostFile, guestFile)
	configFile, e := sealedConfigFD()
	if e != nil {
		err = e
		return nil, err
	}
	h.sources = append(h.sources, configFile)
	readyReader, readyWriter, e := os.Pipe()
	if e != nil {
		err = e
		return nil, err
	}
	h.sources = append(h.sources, readyReader, readyWriter)
	exe, e := os.Executable()
	if e != nil {
		err = e
		return nil, err
	}
	data, e := json.Marshal(childConfig{PayloadRoot: o.PayloadRoot, RootDir: root, Entrypoint: o.Entrypoint, Args: o.Args, Environment: o.Environment, HostURL: o.HostURL, Policy: o.Policy})
	if e != nil {
		err = e
		return nil, err
	}
	cmd := exec.Command(exe, "--launcher-extension-sandbox-0319")
	cmd.Env = []string{marker + "=1", "PATH=/usr/bin:/bin"}
	cmd.ExtraFiles = []*os.File{configFile, guestFile, readyWriter}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		UseCgroupFD:                true, CgroupFD: int(cfd.Fd()), Pdeathsig: syscall.SIGKILL, Setpgid: true,
	}
	h.Cmd = cmd
	// Супервизор владеет HTTP-протоколом, гостевой процесс — лишь одной стороной пары сокетов; пространство
	// сети хоста и путь Unix-сокета хоста внутрь песочницы не монтируются.
	conn, e := net.FileConn(hostFile)
	if e != nil {
		err = e
		return nil, err
	}
	h.hostConn = conn
	handlerServer := &http.Server{Handler: o.HostHandler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	h.hostServer = handlerServer
	go func() { _ = handlerServer.Serve(&oneConnListener{conn: conn, done: make(chan struct{})}) }()
	// cmd.Start вызывается после установки stdout/stderr вызывающей стороной. Полностью запишите конфигурацию
	// до Start; учётные данные не должны передаваться через argv.
	if len(data) > 65536 {
		err = errors.New("sandbox-configuration-too-large")
		return nil, err
	}
	if _, e := configFile.Write(data); e != nil {
		err = e
		return nil, err
	}
	if _, e := configFile.Seek(0, io.SeekStart); e != nil {
		err = e
		return nil, err
	}
	const fAddSeals = 1033
	const fSealSeal = 0x0001
	const fSealShrink = 0x0002
	const fSealGrow = 0x0004
	const fSealWrite = 0x0008
	if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, configFile.Fd(), fAddSeals, fSealSeal|fSealShrink|fSealGrow|fSealWrite); e != 0 {
		err = e
		return nil, err
	}
	// Файловые дескрипторы сохраняются, пока Started не закроет неиспользуемые концы.
	return h, nil
}
func (h *Handle) Started() error {
	// Закройте унаследованные концы в родителе; ядро удерживает их у потомка. Порядок h.sources: cfd,
	// далее по порядку: hostFile, guestFile, sealedConfig, readyReader, readyWriter.
	for _, i := range []int{2, 3, 5} {
		_ = h.sources[i].Close()
	}
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		n, e := h.sources[4].Read(buf)
		if e != nil {
			result <- e
			return
		}
		if string(buf[:n]) != "ready\n" {
			result <- fmt.Errorf("Изолированная среда: настройка отклонена: %s", strings.TrimSpace(string(buf[:n])))
			return
		}
		result <- nil
	}()
	select {
	case e := <-result:
		if e != nil {
			h.Close()
			return e
		}
		h.mu.Lock()
		if !h.closed && h.lifetime > 0 {
			cgroup := h.cgroup
			h.timer = time.AfterFunc(h.lifetime, func() { _ = os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), []byte("1"), 0o600) })
		}
		h.mu.Unlock()
		return nil
	case <-time.After(8 * time.Second):
		h.Close()
		return errors.New("sandbox-init-timeout")
	}
}
func (h *Handle) Abort() { h.Close() }

type childConfig struct {
	PayloadRoot string
	RootDir     string
	Entrypoint  string
	Args        []string
	Environment []string
	HostURL     string
	Policy      Policy
}
type oneConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.conn.Close()
}
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func init() {
	mode := os.Getenv(marker)
	if len(os.Args) != 2 {
		return
	}
	switch {
	case mode == "1" && os.Args[1] == "--launcher-extension-sandbox-0319":
		if e := childMain(); e != nil {
			_, _ = fmt.Fprintln(os.NewFile(5, "ready"), "error:", e)
			_, _ = fmt.Fprintln(os.Stderr, "Песочница расширений:", e)
			os.Exit(126)
		}
		os.Exit(0)
	case mode == "proxy" && os.Args[1] == "--launcher-extension-proxy-0319":
		if e := proxyMain(); e != nil {
			_, _ = fmt.Fprintln(os.Stderr, "IPC песочницы расширений:", e)
			os.Exit(127)
		}
		os.Exit(0)
	}
}
func proxyMain() error {
	if os.Getpid() <= 1 {
		return errors.New("proxy-requires-private-pid-namespace")
	}
	f := os.NewFile(3, "guest-host-ipc")
	conn, e := net.FileConn(f)
	if e != nil {
		return e
	}
	_ = f.Close()
	defer conn.Close()
	listenerFile := os.NewFile(4, "private-loopback-listener")
	l, e := net.FileListener(listenerFile)
	if e != nil {
		return e
	}
	_ = listenerFile.Close()
	defer l.Close()
	runtime.LockOSThread()
	if e := lockdown(); e != nil {
		return e
	}
	if e := verifyLocked(); e != nil {
		return e
	}
	ready := os.NewFile(5, "proxy-ready")
	if _, e := ready.WriteString("ready\n"); e != nil {
		return e
	}
	_ = ready.Close()
	server := &http.Server{Handler: newIPCProxy(conn), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	return server.Serve(l)
}
func childMain() error {
	if os.Getpid() != 1 {
		return errors.New("sandbox-pid-namespace-not-enforced")
	}
	var cfg childConfig
	f := os.NewFile(3, "config")
	if f == nil {
		return errors.New("sandbox-config-fd-absent")
	}
	if e := json.NewDecoder(io.LimitReader(f, 65536)).Decode(&cfg); e != nil {
		return e
	}
	_ = f.Close()
	if e := setupMounts(cfg); e != nil {
		return e
	}
	if e := enableLoopback(); e != nil {
		return e
	}
	guest := os.NewFile(4, "host-ipc")
	hostPort := strings.TrimPrefix(cfg.HostURL, "http://127.0.0.1:")
	if _, e := strconv.Atoi(hostPort); e != nil {
		return e
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:"+hostPort)
	if e != nil {
		return e
	}
	listenerFile, e := ln.(*net.TCPListener).File()
	if e != nil {
		return e
	}
	_ = ln.Close()
	// Изолированный прокси — доверенная программа без секретов, с ограниченным состоянием разрешений и без
	// сетевого доступа к хосту за пределами этой пары сокетов.
	readyRead, readyWrite, e := os.Pipe()
	if e != nil {
		return e
	}
	defer readyRead.Close()
	proxy := exec.Command("/proc/self/exe", "--launcher-extension-proxy-0319")
	proxy.Env = []string{marker + "=proxy", "PATH=/usr/bin:/bin"}
	proxy.ExtraFiles = []*os.File{guest, listenerFile, readyWrite}
	proxy.Stdout = os.Stderr
	proxy.Stderr = os.Stderr
	if e := proxy.Start(); e != nil {
		_ = readyWrite.Close()
		return fmt.Errorf("Ошибка запуска изолированного IPC-прокси: %w", e)
	}
	_ = readyWrite.Close()
	_ = guest.Close()
	_ = listenerFile.Close()
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		n, e := readyRead.Read(buf)
		if e != nil {
			result <- e
			return
		}
		if string(buf[:n]) != "ready\n" {
			result <- errors.New("proxy-did-not-confirm-seccomp-and-nnp")
			return
		}
		result <- nil
	}()
	select {
	case e := <-result:
		if e != nil {
			return fmt.Errorf("sandbox-ipc-proxy: %w", e)
		}
	case <-time.After(5 * time.Second):
		return errors.New("sandbox-ipc-proxy-setup-timeout")
	}

	// exec на этом ЗАКРЕПЛЁННОМ потоке гарантирует наследование расширением NNP, нулевых
	// разрешённых/действующих capabilities и установленного фильтра seccomp.
	runtime.LockOSThread()
	if e := lockdown(); e != nil {
		return e
	}
	if e := verifyLocked(); e != nil {
		return e
	}
	ready := os.NewFile(5, "ready")
	if _, e := ready.WriteString("ready\n"); e != nil {
		return e
	}
	_ = ready.Close()
	relative, _ := filepath.Rel(cfg.PayloadRoot, cfg.Entrypoint)
	path := filepath.Join("/package", relative)
	env := make([]string, 0, len(cfg.Environment)+4)
	for _, s := range cfg.Environment {
		if strings.HasPrefix(s, "HOME=") || strings.HasPrefix(s, "TMPDIR=") || strings.HasPrefix(s, "TMP=") || strings.HasPrefix(s, "PATH=") {
			continue
		}
		env = append(env, s)
	}
	env = append(env, "HOME=/scratch", "TMPDIR=/tmp", "TMP=/tmp", "PATH=/usr/bin:/bin")
	return syscall.Exec(path, append([]string{path}, cfg.Args...), env)
}
func newIPCProxy(conn net.Conn) http.Handler {
	var mu sync.Mutex
	reader := bufio.NewReader(conn)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "" && r.URL.Host != r.Host {
			http.Error(w, "Некорректное значение: хост", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		clone := r.Clone(context.Background())
		clone.RequestURI = ""
		clone.Close = false
		clone.Header.Del("Connection")
		if err := clone.Write(conn); err != nil {
			http.Error(w, "Недоступно: «межпроцессное взаимодействие хоста»", 502)
			return
		}
		resp, err := http.ReadResponse(reader, clone)
		if err != nil {
			http.Error(w, "IPC-запрос хоста отклонён", 502)
			return
		}
		defer resp.Body.Close()
		for k, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 2<<20))
	})
}

// memfd не допускает записи токена возможностей хоста на постоянный носитель и блокировки канала до начала
// чтения дочерним процессом.
func sealedConfigFD() (*os.File, error) {
	name := []byte("nl-extension-config-0319\x00")
	fd, _, e := syscall.RawSyscall(sandboxMemfdCreateSyscall, uintptr(unsafe.Pointer(&name[0])), uintptr(1|2), 0) // MFD_CLOEXEC|MFD_ALLOW_SEALING
	if e != 0 {
		return nil, fmt.Errorf("sandbox-memfd-unavailable: %w", e)
	}
	return os.NewFile(fd, "sealed-sandbox-config"), nil
}
