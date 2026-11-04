package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func limitWorkerResources0273(seconds int) error {
	// Жёсткие лимиты применяются только к одноразовому рабочему процессу и его дочерним
	// Java. Лимит виртуального адресного пространства не задаётся: современные JVM
	// резервируют большие диапазоны даже при ограниченной куче. Время CPU, размер файлов и
	// число дескрипторов ограничивает ядро; куча дочернего процесса ограничена -Xmx.
	for _, limit := range []struct {
		resource int
		value    uint64
	}{
		{syscall.RLIMIT_CPU, uint64(seconds + 3)},
		{syscall.RLIMIT_FSIZE, 2 << 30},
		{syscall.RLIMIT_NOFILE, 1024},
		{syscall.RLIMIT_CORE, 0},
	} {
		if err := syscall.Setrlimit(limit.resource, &syscall.Rlimit{Cur: limit.value, Max: limit.value}); err != nil {
			return err
		}
	}
	return nil
}
func prepareWorkerProcess0273(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
func prepareJavaChild0273(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
func terminateWorkerTree0273(p *os.Process) {
	if p == nil {
		return
	}
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}

// Строгий режим версии 0.27.3 включается только явно: требуются пространства имён
// пользователей и bubblewrap. Создаётся частное пространство монтирования, где запись
// разрешена только в корень сборки, без домашнего каталога хоста, учётных данных и сетевого
// пространства имён. Если bwrap отсутствует, нельзя откатываться к неизолированному процессу.
func strictSandboxJavaCommand0273(ctx context.Context, req processorWorkerRequest0273, javaArgs []string) (*exec.Cmd, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bubblewrap executable missing (required for strict processor sandbox): %w", err)
	}
	mounts := []string{"--die-with-parent", "--unshare-net", "--unshare-pid", "--new-session", "--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--dir", "/tmp"}
	for _, host := range []string{"/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc/ssl", "/etc/alternatives", "/etc/ld.so.cache"} {
		if _, err := os.Stat(host); err == nil {
			mounts = append(mounts, "--ro-bind", host, host)
		}
	}
	resolved, err := filepath.EvalSymlinks(req.Java)
	if err != nil {
		return nil, err
	}
	javaHome := filepath.Dir(filepath.Dir(resolved))
	if javaHome != req.Directory && !isInsidePath0273(req.Directory, javaHome) && !isInsidePath0273("/usr", javaHome) && !isInsidePath0273("/bin", javaHome) {
		mounts = append(mounts, "--ro-bind", javaHome, javaHome)
	}
	mounts = append(mounts, "--bind", req.Directory, req.Directory, "--chdir", req.Directory, "--setenv", "HOME", req.TempDirectory, "--", req.Java)
	mounts = append(mounts, javaArgs...)
	return exec.CommandContext(ctx, bwrap, mounts...), nil
}
func isInsidePath0273(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && (rel == "." || len(rel) < 3 || rel[:3] != "../")
}
