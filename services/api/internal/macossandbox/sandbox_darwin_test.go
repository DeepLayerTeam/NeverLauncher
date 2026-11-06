//go:build darwin

package macossandbox

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnsignedHelperAlwaysRejected(t *testing.T) {
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", "")
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "")
	if Available() == nil {
		t.Fatal("Ошибочно принят отсутствующий неподписанный вспомогательный процесс")
	}
}
func TestWrongTeamIDRejected(t *testing.T) {
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "NOT-A-TEAM")
	if _, err := teamID(); err == nil {
		t.Fatal("Ошибочно принят некорректный идентификатор команды")
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "ABCDEFG123")
	if _, err := teamID(); err != nil {
		t.Fatal(err)
	}
}
func TestUntrustedHelperFileRejectedBeforeCodesign(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "helper")
	if err := os.WriteFile(p, []byte("not-code"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", p)
	if _, err := helperPath(); err == nil {
		t.Fatal("Ошибочно принят вспомогательный файл с разрешённой записью для группы и всех пользователей")
	}
	if err := os.Chmod(p, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_TEAM_ID", "ABCDEFG123")
	if Available() == nil {
		t.Fatal("unsigned executable accepted")
	}
}

func TestUnsupportedMacOSResourcePolicyRefusedBeforeExecution04311(t *testing.T) {
	// Действительная подпись не превращает политику нескольких процессов в
	// изоляцию уровня cgroup, обеспеченную ОС. Неподдерживаемые модели ресурсов
	// всегда отклоняются.
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", "")
	_, err := Prepare(Options{Policy: Policy{MaxMemoryBytes: 256 << 20, MaxProcesses: 4, MaxCPUPercent: 50, TimeoutSeconds: 60}, HostHandler: http.NotFoundHandler(), HostURL: "http://127.0.0.1:3000"})
	if err == nil {
		t.Fatal("Неподдерживаемая многопроцессная песочница macOS ошибочно принята")
	}
	if !strings.Contains(err.Error(), "helper") { // Отсутствие вспомогательного процесса само по себе приводит к отказу по умолчанию.
		t.Fatalf("Неожиданная ошибка в неподписанном изолированном режиме: %v", err)
	}
}

func TestWritableDirectoryCannotHostTrustedHelper04311(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "NeverExtensionSandbox")
	if err := os.WriteFile(file, []byte("not signed"), 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAUNCHER_MACOS_SANDBOX_HELPER", file)
	if _, err := helperPath(); err == nil {
		t.Fatal("writable ancestor accepted")
	}
}
