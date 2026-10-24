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

// The build worker uses a separate OS process even when invoked by go test.
// The parent sends a bounded, private request over stdin; the worker never
// accepts remote requests or arbitrary shell commands.
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
	if os.Getenv("NEVERLAUNCHER_INTERNAL_WORKER_0273") != "1" {
		fmt.Fprintln(os.Stderr, "unauthorized internal build worker invocation")
		os.Exit(125)
	}
	if err := runInternalProcessorWorker0273(); err != nil {
		fmt.Fprintln(os.Stderr, "worker:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func workerEnvironment0273(tmp string) []string {
	// Do not leak API tokens, cloud credentials, or Java injection flags into
	// untrusted upstream installer processors.
	allowed := []string{"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}
	env := []string{"NEVERLAUNCHER_BUILD_WORKER=1", "TMPDIR=" + tmp, "TMP=" + tmp, "TEMP=" + tmp, "LANG=C", "LC_ALL=C"}
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
		return errors.New("worker request too large")
	}
	var req processorWorkerRequest0273
	if err := json.Unmarshal(input, &req); err != nil {
		return err
	}
	if !filepath.IsAbs(req.Java) || !filepath.IsAbs(req.Directory) || !filepath.IsAbs(req.TempDirectory) || req.HeapMiB < 128 || req.HeapMiB > 8192 || req.TimeoutSeconds < 1 || req.TimeoutSeconds > 3600 || len(req.Args) < 3 || len(req.Args) > 4096 {
		return errors.New("invalid build worker request")
	}
	if err := limitWorkerResources0273(req.TimeoutSeconds); err != nil {
		return fmt.Errorf("resource limits: %w", err)
	}
	if err := os.MkdirAll(req.TempDirectory, 0o700); err != nil {
		return err
	}
	// The process is already isolated from the CLI, with a different PID,
	// sanitized environment, resource limits and an independent lifetime.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	args := append([]string{"-Xmx" + strconv.Itoa(req.HeapMiB) + "m", "-Djava.io.tmpdir=" + req.TempDirectory}, req.Args...)
	var cmd *exec.Cmd
	if req.StrictSandbox {
		cmd, err = strictSandboxJavaCommand0273(ctx, req, args)
		if err != nil {
			return fmt.Errorf("strict worker sandbox: %w", err)
		}
	} else {
		cmd = exec.CommandContext(ctx, req.Java, args...)
	}
	cmd.Dir = req.Directory
	cmd.Env = workerEnvironment0273(req.TempDirectory)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	prepareJavaChild0273(cmd)
	// In case the parent is killed, this process inherits the parent's pipe;
	// process-tree teardown is owned by the parent's OS-specific runner.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("java timed out: %w", ctx.Err())
		}
		return fmt.Errorf("java processor failed: %w", err)
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

// runIsolatedProcessor0273 is used by Forge and NeoForge, including the
// unified Client Factory pipeline. No processor executes in the API/CLI PID.
func runIsolatedProcessor0273(ctx context.Context, pc forgeProcessorContext, index int, args []string) (string, error) {
	java, err := filepath.Abs(pc.JavaExecutable)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(pc.ClientDir)
	if err != nil {
		return "", err
	}
	logs := filepath.Join(root, ".neverlauncher", "worker-logs")
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
	tmp, err := os.MkdirTemp(filepath.Join(root, ".neverlauncher"), "worker-tmp-")
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
		return logPath, errors.New("processor request exceeds worker protocol limit")
	}
	workerExe, err := os.Executable()
	if err != nil {
		return logPath, err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout+3*time.Second)
	defer cancel()
	cmd := exec.Command(workerExe, internalWorkerArgument0273)
	cmd.Dir = root
	cmd.Env = append(workerEnvironment0273(tmp), "NEVERLAUNCHER_INTERNAL_WORKER_0273=1")
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
		return logPath, fmt.Errorf("processor worker interrupted: %w", runCtx.Err())
	}
	if waitErr != nil {
		return logPath, fmt.Errorf("processor worker exited: %w; log tail: %s", waitErr, limited.Tail())
	}
	return logPath, nil
}

// A content hash of every executable input invalidates cache journal reuse
// if a JAR (or its classpath) changes while an installer version stays fixed.
func hashProcessorInputs0273(java string, classpath []string) (string, error) {
	h := sha256.New()
	for _, f := range append([]string{java}, classpath...) {
		digest, size, err := hashFile(f)
		if err != nil {
			return "", fmt.Errorf("processor input %s: %w", filepath.Base(f), err)
		}
		_, _ = io.WriteString(h, digest+":"+strconv.FormatInt(size, 10)+"\n")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
