package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Рабочий процесс сборки использует отдельный процесс ОС, даже при вызове из go
// test. Родитель передаёт ограниченный приватный запрос через stdin; рабочий
// процесс не принимает сетевые запросы или произвольные команды оболочки.
const internalWorkerArgument0273 = "__internal-client-factory-worker-0273"
const workerRequestLimit0273 = 128 << 10
const workerLogLimit0273 = 2 << 20

type processorWorkerRequest0273 struct {
	Java           string   `json:"java"`
	Args           []string `json:"args"`
	Directory      string   `json:"directory"`
	TempDirectory  string   `json:"tempDirectory"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
	HeapMiB        int      `json:"heapMiB"`
	StrictSandbox  bool     `json:"strictSandbox,omitempty"`
}

func init() {
	if len(os.Args) < 2 || os.Args[1] != internalWorkerArgument0273 {
		return
	}
	if os.Getenv("LAUNCHER_INTERNAL_WORKER_0273") != "1" {
		fmt.Fprintln(os.Stderr, "Неавторизованный запуск внутреннего рабочего процесса сборки")
		os.Exit(125)
	}
	if err := runInternalProcessorWorker0273(); err != nil {
		fmt.Fprintln(os.Stderr, "worker:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func workerEnvironment0273(tmp string) []string {
	// Не передавайте токены API, облачные учётные данные и флаги
	// внедрения Java в недоверенные обработчики сторонних установщиков.
	allowed := []string{"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}
	env := []string{"LAUNCHER_BUILD_WORKER=1", "TMPDIR=" + tmp, "TMP=" + tmp, "TEMP=" + tmp, "LANG=C", "LC_ALL=C"}
	for _, k := range allowed {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func runInternalProcessorWorker0273() error {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, workerRequestLimit0273+1))
	if err != nil {
		return err
	}
	if len(input) > workerRequestLimit0273 {
		return errors.New("Превышен допустимый размер: запрос рабочего процесса")
	}
	var req processorWorkerRequest0273
	if err := json.Unmarshal(input, &req); err != nil {
		return err
	}
	if !filepath.IsAbs(req.Java) || !filepath.IsAbs(req.Directory) || !filepath.IsAbs(req.TempDirectory) || req.HeapMiB < 128 || req.HeapMiB > 8192 || req.TimeoutSeconds < 1 || req.TimeoutSeconds > 3600 || len(req.Args) < 3 || len(req.Args) > 4096 {
		return errors.New("Некорректное значение: запрос рабочего процесса сборки")
	}
	if err := limitWorkerResources0273(req.TimeoutSeconds); err != nil {
		return fmt.Errorf("Ошибка ограничений ресурсов: %w", err)
	}
	if err := os.MkdirAll(req.TempDirectory, 0o700); err != nil {
		return err
	}
	// Процесс уже изолирован от CLI: другой PID, очищенное
	// окружение, ограничения ресурсов и отдельный жизненный цикл.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	args := append([]string{"-Xmx" + strconv.Itoa(req.HeapMiB) + "m", "-Djava.io.tmpdir=" + req.TempDirectory}, req.Args...)
	var cmd *exec.Cmd
	if req.StrictSandbox {
		cmd, err = strictSandboxJavaCommand0273(ctx, req, args)
		if err != nil {
			return fmt.Errorf("Ошибка строгой изоляции рабочего процесса: %w", err)
		}
	} else {
		cmd = exec.CommandContext(ctx, req.Java, args...)
	}
	cmd.Dir = req.Directory
	cmd.Env = workerEnvironment0273(req.TempDirectory)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	prepareJavaChild0273(cmd)
	// Если родитель аварийно завершён, процесс наследует его канал; остановка дерева
	// процессов находится под управлением специализированного обработчика ОС родителя.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("Превышено время ожидания Java: %w", ctx.Err())
		}
		return fmt.Errorf("Ошибка: Java процессор: %w", err)
	}
	return nil
}

type boundedWorkerLog0273 struct {
	mu    sync.Mutex
	out   io.Writer
	total int
	tail  []byte
}

func (b *boundedWorkerLog0273) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	length := len(p)
	tail := append(b.tail, p...)
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	b.tail = append([]byte(nil), tail...)
	if b.total < workerLogLimit0273 {
		chunk := p
		if len(chunk) > workerLogLimit0273-b.total {
			chunk = chunk[:workerLogLimit0273-b.total]
		}
		n, err := b.out.Write(chunk)
		b.total += n
		if err != nil {
			return n, err
		}
	}
	return length, nil
}
func (b *boundedWorkerLog0273) Tail() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.tail) }

// Функция runIsolatedProcessor0273 применяется Forge и NeoForge, включая общий
// Client Factory. Процессоры не выполняются внутри PID API или CLI.
func runIsolatedProcessor0273(ctx context.Context, pc forgeProcessorContext, index int, args []string) (string, error) {
	java, err := filepath.Abs(pc.JavaExecutable)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(pc.ClientDir)
	if err != nil {
		return "", err
	}
	logs := filepath.Join(root, ".launcher", "worker-logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		return "", err
	}
	logPath := filepath.Join(logs, fmt.Sprintf("processor-%03d.log", index))
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer log.Close()
	limited := &boundedWorkerLog0273{out: log}
	tmp, err := os.MkdirTemp(filepath.Join(root, ".launcher"), "worker-tmp-")
	if err != nil {
		return logPath, err
	}
	defer os.RemoveAll(tmp)
	timeout := pc.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	seconds := int((timeout + time.Second - 1) / time.Second)
	req := processorWorkerRequest0273{Java: java, Args: args, Directory: root, TempDirectory: tmp, TimeoutSeconds: seconds, HeapMiB: 2048, StrictSandbox: pc.StrictSandbox}
	payload, err := json.Marshal(req)
	if err != nil {
		return logPath, err
	}
	if len(payload) > workerRequestLimit0273 {
		return logPath, errors.New("Запрос обработчика превышает лимит протокола рабочего процесса")
	}
	workerExe, err := os.Executable()
	if err != nil {
		return logPath, err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout+3*time.Second)
	defer cancel()
	cmd := exec.Command(workerExe, internalWorkerArgument0273)
	cmd.Dir = root
	cmd.Env = append(workerEnvironment0273(tmp), "LAUNCHER_INTERNAL_WORKER_0273=1")
	cmd.Stdin = strings.NewReader(string(payload))
	cmd.Stdout, cmd.Stderr = limited, limited
	prepareWorkerProcess0273(cmd)
	started := time.Now().UTC()
	_, _ = fmt.Fprintf(log, "start=%s processor=%d worker=separate-process\n", started.Format(time.RFC3339Nano), index)
	if err := cmd.Start(); err != nil {
		return logPath, err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			terminateWorkerTree0273(cmd.Process)
		case <-done:
		}
	}()
	waitErr := cmd.Wait()
	close(done)
	_, _ = fmt.Fprintf(log, "finish=%s elapsed=%s success=%t\n", time.Now().UTC().Format(time.RFC3339Nano), time.Since(started).Round(time.Millisecond), waitErr == nil && runCtx.Err() == nil)
	if err := log.Sync(); err != nil {
		return logPath, err
	}
	if runCtx.Err() != nil {
		return logPath, fmt.Errorf("Рабочий процесс обработчика прерван: %w", runCtx.Err())
	}
	if waitErr != nil {
		return logPath, fmt.Errorf("Рабочий процесс обработчика завершился: %w; конец журнала: %s", waitErr, limited.Tail())
	}
	return logPath, nil
}

// Хеш содержимого каждого исполняемого входа запрещает повторно использовать
// журнал кэша при изменении JAR или classpath с той же версией установщика.
func hashProcessorInputs0273(java string, classpath []string) (string, error) {
	h := sha256.New()
	for _, f := range append([]string{java}, classpath...) {
		digest, size, err := hashFile(f)
		if err != nil {
			return "", fmt.Errorf("Ошибка входного файла обработчика %s: %w", filepath.Base(f), err)
		}
		_, _ = io.WriteString(h, digest+":"+strconv.FormatInt(size, 10)+"\n")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
