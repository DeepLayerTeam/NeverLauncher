package devtools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ComponentOptions struct {
	Jar       string
	Java      string
	Isolation string
	Timeout   time.Duration
	HeapMB    int
	Args      []string
}
type ComponentResult struct {
	Isolation  string `json:"isolation"`
	ExitCode   int    `json:"exitCode"`
	DurationMS int64  `json:"durationMs"`
	TimedOut   bool   `json:"timedOut"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Truncated  bool   `json:"truncated"`
}
type cappedBuffer struct {
	bytes.Buffer
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	before := b.Len()
	if b.Len() < b.max {
		left := b.max - b.Len()
		if left > len(p) {
			left = len(p)
		}
		b.Buffer.Write(p[:left])
	}
	if n > b.max-before {
		b.truncated = true
	}
	return n, nil
}
func validJavaPath(s string) error {
	if s == "" {
		return errors.New("java executable required")
	}
	return nil
}
func javaCommandArgs(jar, work string, heap int, appArgs []string) []string {
	a := []string{"-Xmx" + strconv.Itoa(heap) + "m", "-XX:MaxMetaspaceSize=128m", "-Djava.io.tmpdir=" + work, "-Duser.home=" + work, "-jar", jar}
	return append(a, appArgs...)
}
func RunComponent(parent context.Context, opt ComponentOptions) (ComponentResult, error) {
	res := ComponentResult{Isolation: opt.Isolation, ExitCode: -1}
	if opt.Isolation != "process" && opt.Isolation != "sandbox" {
		return res, errors.New("--isolation must be process or sandbox")
	}
	if opt.Timeout <= 0 || opt.Timeout > 2*time.Minute {
		return res, errors.New("timeout must be 1s..2m")
	}
	if opt.HeapMB < 32 || opt.HeapMB > 2048 {
		return res, errors.New("heap must be 32..2048 MiB")
	}
	if e := validJavaPath(opt.Java); e != nil {
		return res, e
	}
	if _, e := AnalyzeJar(opt.Jar); e != nil {
		return res, fmt.Errorf("JAR preflight: %w", e)
	}
	jar, e := filepath.Abs(opt.Jar)
	if e != nil {
		return res, e
	}
	java, e := exec.LookPath(opt.Java)
	if e != nil {
		return res, e
	}
	java, e = filepath.Abs(java)
	if e != nil {
		return res, e
	}
	work, e := os.MkdirTemp("", "never-devtools-component-")
	if e != nil {
		return res, e
	}
	defer os.RemoveAll(work)
	ctx, cancel := context.WithTimeout(parent, opt.Timeout)
	defer cancel()
	var cmd *exec.Cmd
	if opt.Isolation == "sandbox" {
		if runtime.GOOS != "linux" {
			return res, errors.New("bubblewrap sandbox requires Linux")
		}
		bwrap, e := exec.LookPath("bwrap")
		if e != nil {
			return res, errors.New("sandbox unavailable: install bubblewrap; process isolation is NOT a security sandbox")
		}
		args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/work", "--dir", "/app", "--dir", "/etc", "--dir", "/etc/ssl"}
		for _, d := range []string{"/usr", "/lib", "/lib64", "/bin", "/etc/alternatives", "/etc/ssl/certs", "/etc/java"} {
			if st, e := os.Stat(d); e == nil && st.IsDir() {
				args = append(args, "--ro-bind", d, d)
			}
		}
		args = append(args, "--ro-bind", jar, "/app/component.jar", "--chdir", "/work", "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/tmp", "--setenv", "LAUNCHER_DEVTOOLS_TEST_MODE", "1", "--", java)
		args = append(args, javaCommandArgs("/app/component.jar", "/tmp", opt.HeapMB, opt.Args)...)
		cmd = exec.CommandContext(ctx, bwrap, args...)
	} else {
		cmd = exec.CommandContext(ctx, java, javaCommandArgs(jar, work, opt.HeapMB, opt.Args)...)
		cmd.Dir = work
	}
	prepareComponentGroup(cmd)
	// Never inherit operator tokens, cloud credentials, or arbitrary Java tool flags,
	// including when the child process happens to be the bubblewrap launcher.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + work, "TMPDIR=" + work, "LANG=C", "LAUNCHER_DEVTOOLS_TEST_MODE=1", "LAUNCHER_AUTH_TEST_ONLY=1"}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	cmd.Stdin = bytes.NewReader(nil)
	out := &cappedBuffer{max: 64 << 10}
	stderr := &cappedBuffer{max: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = stderr
	start := time.Now()
	if e = cmd.Start(); e != nil {
		return res, e
	} // The child runs in a private process group on POSIX; group termination prevents orphaned test grandchildren.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			killComponentTree(cmd)
		case <-done:
		}
	}()
	e = cmd.Wait()
	close(done)
	res.DurationMS = time.Since(start).Milliseconds()
	res.Stdout = strings.ToValidUTF8(out.String(), "")
	res.Stderr = strings.ToValidUTF8(stderr.String(), "")
	res.Truncated = out.truncated || stderr.truncated
	res.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if res.TimedOut {
		return res, errors.New("component timed out and was terminated")
	}
	if e != nil {
		return res, fmt.Errorf("component exited: %w", e)
	}
	return res, nil
}

var _ io.Writer = (*cappedBuffer)(nil)
