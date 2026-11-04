//go:build darwin

package macossandbox

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Этот тест намеренно запускается по явному запросу. Нужны настоящий вспомогательный
// бинарник с подписью Developer ID, ядровая App Sandbox и нативное исполнение macOS.
// Кросс-компиляция или локальный mock codesign не подходят.
func TestSignedSandboxNativeLive04311(t *testing.T) {
	if os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE") != "1" {
		t.Skip("live signing and native macOS runner required")
	}
	image := os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE_FIXTURE")
	if image == "" {
		t.Fatal("native Mach-O fixture required")
	}
	if err := Available(); err != nil {
		t.Fatalf("signed helper not usable: %v", err)
	}
	for _, scenario := range []struct {
		name    string
		allowed bool
	}{{"sandbox", true}, {"fork", false}, {"detach", false}} {
		t.Run(scenario.name, func(t *testing.T) {
			options := Options{
				PayloadRoot: os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE_ROOT"), Entrypoint: image,
				Args: []string{scenario.name}, HostURL: "http://127.0.0.1:19090",
				HostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }),
				Policy:      Policy{MaxMemoryBytes: 512 << 20, MaxProcesses: 1, MaxCPUPercent: 100, TimeoutSeconds: 7},
			}
			h, err := Prepare(options)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			defer h.Close()
			if err = h.Cmd.Start(); err != nil {
				t.Fatalf("exec signed helper: %v", err)
			}
			startedErr := h.Started()
			if startedErr != nil {
				_ = h.Cmd.Wait()
				// Fork может быть запрещён границей ядра и сразу завершиться.
				if !scenario.allowed {
					return
				}
				t.Fatal(startedErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.Cmd.Wait() }()
			select {
			case err := <-done:
				if scenario.allowed && err != nil {
					t.Fatalf("allowed isolated process failed: %v", err)
				}
				if !scenario.allowed && err == nil {
					t.Fatal("extra descendant or detached process was accepted")
				}
			case <-ctx.Done():
				h.Close()
				t.Fatal("signed helper or its child hung after deadline")
			}
		})
	}
	// Переносить политику ресурсов нескольких процессов на эту
	// непривилегированную платформу небезопасно: отклоняйте её, а не утверждайте
	// наличие контроля.
	_, err := Prepare(Options{Policy: Policy{MaxProcesses: 2, MaxCPUPercent: 100, MaxMemoryBytes: 512 << 20, TimeoutSeconds: 5}, HostURL: "http://127.0.0.1:19090", HostHandler: http.NotFoundHandler()})
	if err == nil || !strings.Contains(err.Error(), "resource-policy") {
		t.Fatalf("multi-process mode must fail closed: %v", err)
	}
}

// Проверяйте путь закрытия канала живости Backend на реально работающем
// вспомогательном процессе.
func TestSignedSandboxLiveShutdown04311(t *testing.T) {
	if os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE") != "1" {
		t.Skip("native macOS only")
	}
	h, err := Prepare(Options{PayloadRoot: os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE_ROOT"), Entrypoint: os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE_FIXTURE"), Args: []string{"stay"}, HostURL: "http://127.0.0.1:19090", HostHandler: http.NotFoundHandler(), Policy: Policy{MaxProcesses: 1, MaxMemoryBytes: 512 << 20, MaxCPUPercent: 100, TimeoutSeconds: 20}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := h.Started(); err != nil {
		_ = h.Cmd.Wait()
		t.Fatal(err)
	}
	// Имитируйте резкое завершение Backend: процесс-писатель канала живости
	// Supervisor исчезает без явной команды завершить группу процессов.
	if err := h.liveWrite.Close(); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- h.Cmd.Wait() }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("helper exited successfully after supervisor loss")
		}
	case <-time.After(3 * time.Second):
		h.Close()
		t.Fatal("child not terminated after supervisor liveness FD closed")
	}
	// Для другого запуска нужен отдельный независимо подписанный вспомогательный
	// процесс; закрытый нельзя оживить повторным открытием того же IPC.
	_ = exec.ErrNotFound
}
