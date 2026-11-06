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
		t.Skip("Требуются реальная подпись и нативный исполнитель macOS")
	}
	image := os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE_FIXTURE")
	if image == "" {
		t.Fatal("Требуется нативный тестовый файл Mach-O")
	}
	if err := Available(); err != nil {
		t.Fatalf("Подписанный вспомогательный процесс недоступен: %v", err)
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
				t.Fatalf("Подготовка: %v", err)
			}
			defer h.Close()
			if err = h.Cmd.Start(); err != nil {
				t.Fatalf("запуск подписанного вспомогательного процесса: %v", err)
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
					t.Fatalf("Разрешённый изолированный процесс завершился с ошибкой: %v", err)
				}
				if !scenario.allowed && err == nil {
					t.Fatal("Ошибочно принят лишний дочерний или отделённый процесс")
				}
			case <-ctx.Done():
				h.Close()
				t.Fatal("Подписанный вспомогательный процесс или его потомок завис после истечения срока")
			}
		})
	}
	// Переносить политику ресурсов нескольких процессов на эту
	// непривилегированную платформу небезопасно: отклоняйте её, а не утверждайте
	// наличие контроля.
	_, err := Prepare(Options{Policy: Policy{MaxProcesses: 2, MaxCPUPercent: 100, MaxMemoryBytes: 512 << 20, TimeoutSeconds: 5}, HostURL: "http://127.0.0.1:19090", HostHandler: http.NotFoundHandler()})
	if err == nil || !strings.Contains(err.Error(), "resource-policy") {
		t.Fatalf("Многопроцессный режим должен блокировать операцию при ошибке: %v", err)
	}
}

// Проверяйте путь закрытия канала живости Backend на реально работающем
// вспомогательном процессе.
func TestSignedSandboxLiveShutdown04311(t *testing.T) {
	if os.Getenv("LAUNCHER_MACOS_SANDBOX_LIVE") != "1" {
		t.Skip("Только для нативной macOS")
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
			t.Fatal("Вспомогательный процесс успешно завершился после потери супервизора")
		}
	case <-time.After(3 * time.Second):
		h.Close()
		t.Fatal("Дочерний процесс не завершён после закрытия дескриптора контроля супервизора")
	}
	// Для другого запуска нужен отдельный независимо подписанный вспомогательный
	// процесс; закрытый нельзя оживить повторным открытием того же IPC.
	_ = exec.ErrNotFound
}
