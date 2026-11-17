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
		return errors.New("Необходимо указать исполняемый файл Java")
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
		return res, errors.New("Параметр --isolation допускает только process или sandbox")
	}
	if opt.Timeout <= 0 || opt.Timeout > 2*time.Minute {
		return res, errors.New("timeout: требуется «1s..2m»")
	}
	if opt.HeapMB < 32 || opt.HeapMB > 2048 {
		return res, errors.New("Размер кучи должен составлять от 32 до 2048 МиБ")
	}
	if e := validJavaPath(opt.Java); e != nil {
		return res, e
	}
	if _, e := AnalyzeJar(opt.Jar); e != nil {
		return res, fmt.Errorf("Ошибка предварительной проверки JAR: %w", e)
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
	work, e := os.MkdirTemp("", "devtools-component-")
	if e != nil {
		return res, e
	}
	defer os.RemoveAll(work)
	ctx, cancel := context.WithTimeout(parent, opt.Timeout)
	defer cancel()
	var cmd *exec.Cmd
	if opt.Isolation == "sandbox" {
		if runtime.GOOS != "linux" {
			return res, errors.New("Для песочницы bubblewrap необходим Linux")
		}
		bwrap, e := exec.LookPath("bwrap")
		if e != nil {
			return res, errors.New("Песочница недоступна: установите bubblewrap. Изоляция процесса НЕ является песочницей безопасности")
		}
		// Prefer a private network namespace. Some hosted Linux kernels allow
		// user namespaces but reject bringing up loopback inside them (RTM_NEWADDR).
		// Only that precise failure allows a fallback; never use the host network
		// without a kernel-enforced seccomp filter blocking socket/connect.
		probe := exec.CommandContext(ctx, bwrap, "--die-with-parent", "--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true")
		probe.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		probeOutput, probeErr := probe.CombinedOutput()
		fallback := false
		if probeErr != nil {
			if strings.Contains(string(probeOutput), "loopback: Failed RTM_NEWADDR: Operation not permitted") {
				fallback = true
			} else {
				return res, fmt.Errorf("Песочница bubblewrap не может изолировать систему: %s: %w", strings.TrimSpace(string(probeOutput)), probeErr)
			}
		}
		args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/work", "--dir", "/app", "--dir", "/etc", "--dir", "/etc/ssl"}
		var filter *os.File
		if fallback {
			var filterErr error
			filter, filterErr = sandboxNoNetworkFilter()
			if filterErr != nil {
				return res, fmt.Errorf("Песочница не может безопасно заблокировать сетевые вызовы: %w", filterErr)
			}
			defer filter.Close()
			// bubblewrap receives the BPF program as descriptor 3; the filter
			// is installed in the jailed process before exec of the untrusted JVM.
			args = append(args, "--share-net", "--seccomp", "3")
			defer func() { _ = os.Remove(filter.Name()) }()
		}
		for _, d := range []string{"/usr", "/lib", "/lib64", "/bin", "/etc/alternatives", "/etc/ssl/certs", "/etc/java"} {
			if st, e := os.Stat(d); e == nil && st.IsDir() {
				args = append(args, "--ro-bind", d, d)
			}
		}
		// GitHub-hosted JDKs live outside /usr, e.g. /opt/hostedtoolcache/Java_.../x64.
		// Bind only the selected JDK, read-only, never the whole host /opt tree.
		// Resolve symlinks before binding to avoid executing through an unmounted alias.
		javaResolved, resolveErr := filepath.EvalSymlinks(java)
		if resolveErr != nil {
			return res, fmt.Errorf("Не удалось проверить выбранную JVM: %w", resolveErr)
		}
		javaInfo, statErr := os.Stat(javaResolved)
		if statErr != nil || !javaInfo.Mode().IsRegular() {
			return res, errors.New("Выбранный исполняемый файл JVM недоступен")
		}
		if !strings.HasPrefix(javaResolved, "/usr/") && !strings.HasPrefix(javaResolved, "/bin/") {
			jdkRoot := filepath.Dir(filepath.Dir(javaResolved)) // .../<JDK>/bin/java -> .../<JDK>
			if filepath.Base(filepath.Dir(javaResolved)) != "bin" || jdkRoot == "/" {
				return res, errors.New("Невозможно безопасно смонтировать каталог выбранной JVM")
			}
			args = append(args, "--ro-bind", jdkRoot, jdkRoot)
		}
		java = javaResolved
		args = append(args, "--ro-bind", jar, "/app/component.jar", "--chdir", "/work", "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/tmp", "--setenv", "LAUNCHER_DEVTOOLS_TEST_MODE", "1", "--", java)
		args = append(args, javaCommandArgs("/app/component.jar", "/tmp", opt.HeapMB, opt.Args)...)
		cmd = exec.CommandContext(ctx, bwrap, args...)
		if filter != nil {
			cmd.ExtraFiles = []*os.File{filter}
		}
	} else {
		cmd = exec.CommandContext(ctx, java, javaCommandArgs(jar, work, opt.HeapMB, opt.Args)...)
		cmd.Dir = work
	}
	prepareComponentGroup(cmd)
	// Никогда не наследуйте токены оператора, облачные учётные данные и произвольные флаги
	// Java, даже если дочерний процесс — запускатель bubblewrap.
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
	} // В POSIX дочерний процесс работает в отдельной группе; завершение группы предотвращает появление осиротевших процессов следующих уровней.
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
		return res, errors.New("Время ожидания компонента истекло; его работа завершена")
	}
	if e != nil {
		return res, fmt.Errorf("Компонент завершился: %w", e)
	}
	return res, nil
}

var _ io.Writer = (*cappedBuffer)(nil)
