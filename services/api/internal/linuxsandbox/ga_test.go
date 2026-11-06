//go:build linux && (amd64 || arm64)

package linuxsandbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Релиз не должен утверждать контроль жизненного цикла дерева процессов на ядрах
// без cgroup.kill: дочерний процесс мог выйти из исходной группы.
func TestGACgroupKillMandatory0320(t *testing.T) {
	dir := t.TempDir()
	if err := requireCgroupKill03120(dir); err == nil || !strings.Contains(err.Error(), "cgroup-kill-required") {
		t.Fatalf("Ошибочно принято отсутствие cgroup.kill: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "cgroup.kill"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := requireCgroupKill03120(dir); err == nil {
		t.Fatal("Ошибочно принят каталог, выдающий себя за cgroup.kill")
	}
	if err := os.Remove(filepath.Join(dir, "cgroup.kill")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireCgroupKill03120(dir); err != nil {
		t.Fatal(err)
	}
}

// Параллельное завершение не должно вызывать панику из-за повторного закрытия
// канала и приводить к падению хоста по вине отключившегося расширения.
func TestGAConcurrentIPCListenerShutdown0320(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	listener := &oneConnListener{conn: left, done: make(chan struct{})}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = listener.Close() }()
	}
	wg.Wait()
	select {
	case <-listener.done:
	default:
		t.Fatal("Слушающий сокет не закрыт")
	}
}
