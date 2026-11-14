package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func hostFixture0282(t *testing.T, body string) (string, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("интеграционные тесты идентичности Runtime узла сейчас требуют Linux")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "paper.jar"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	java := writeFakeJava01910(t, root, body)
	return root, java
}

func TestHost0282GracefulConsoleStopAndScopedRequest(t *testing.T) {
	root, java := hostFixture0282(t, `echo READY
while IFS= read -r line; do
 if [ "$line" = stop ]; then echo 'WORLD-SAVED'; exit 0; fi
done`)
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--restart-policy", "always", "--stop-timeout-seconds", "2"}); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- runServerBridgeHost01910(root, false) }()
	paths := hostPaths01910(root)
	var state serverBridgeHostRuntime01910
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		state, _ = readServerBridgeHostRuntime01910(paths["runtime"])
		log, _ := os.ReadFile(paths["stdout"])
		if state.Status == "running" && strings.Contains(string(log), "READY") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if state.Status != "running" {
		t.Fatalf("Процесс не выполняется: %+v", state)
	}
	// Отложенный запрос устаревшего сеанса не должен остановить эту JVM.
	forged := hostStopRequest0282{SessionID: "previous-session", ProcessPID: state.ProcessPID}
	if err := atomicWriteJSON01910(paths["stop"], forged, 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	if !hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
		t.Fatal("Устаревший запрос неожиданно остановил JVM")
	}
	started := time.Now()
	if err := stopServerBridgeHost01910([]string{"--server-root", root}); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 1500*time.Millisecond {
		t.Fatal("Команда остановки через консоль не завершила процесс до отправки системного сигнала")
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Выполнение не завершилось")
	}
	state, _ = readServerBridgeHostRuntime01910(paths["runtime"])
	if state.Status != "stopped" || state.StopMethod != "console-stop" || state.ProcessIdentity != "" {
		t.Fatalf("Остановленный Runtime: %+v", state)
	}
	log, _ := os.ReadFile(paths["stdout"])
	if !strings.Contains(string(log), "WORLD-SAVED") {
		t.Fatalf("Отсутствует подтверждение сохранения: %q", log)
	}
}

func TestHost0282EnvironmentAllowlistAndWorkingDirectory(t *testing.T) {
	root, java := hostFixture0282(t, `printf 'pwd=%s\n' "$PWD"
printf 'allowed=%s\n' "${TEST_GAME_ENV:-MISSING}"
printf 'denied=%s\n' "${UNSAFE_LEAK_VALUE:-MISSING}"
sleep 1
exit 0`)
	work := filepath.Join(root, "instance")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UNSAFE_LEAK_VALUE", "should-not-be-in-child")
	err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--working-directory", "instance", "--env-allow", "TEST_GAME_ENV", "--env", "TEST_GAME_ENV=token-fixture", "--restart-policy", "never"})
	if err != nil {
		t.Fatal(err)
	}
	config, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
	if err != nil {
		t.Fatal(err)
	}
	masked, _ := json.Marshal(hostRedactedConfig0282(config))
	if strings.Contains(string(masked), "token-fixture") {
		t.Fatal("Конфигурация статуса раскрывает секреты окружения")
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		t.Fatal(err)
	}
	output, _ := os.ReadFile(hostPaths01910(root)["stdout"])
	if !strings.Contains(string(output), "pwd="+work) || !strings.Contains(string(output), "allowed=token-fixture") || !strings.Contains(string(output), "denied=MISSING") {
		t.Fatalf("Неожиданное окружение дочернего процесса: %q", output)
	}
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--env", "SECRET=oops"}); err == nil {
		t.Fatal("Принята переменная вне списка разрешённых")
	}
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--working-directory", ".."}); err == nil {
		t.Fatal("Принят обход рабочего каталога")
	}
}

func TestHost0282IdentityRecoveryAndStalePID(t *testing.T) {
	root, java := hostFixture0282(t, `exit 0`)
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--restart-policy", "never"}); err != nil {
		t.Fatal(err)
	}
	paths := hostPaths01910(root)
	// PID, повторно использованный ОС, нельзя считать прежней JVM.
	fake := serverBridgeHostRuntime01910{Status: "running", SessionID: "previous-session", ProcessPID: os.Getpid(), ProcessIdentity: "old-boot:0", SupervisorPID: 123}
	if err := atomicWriteJSON01910(paths["runtime"], fake, 0600); err != nil {
		t.Fatal(err)
	}
	if hostIdentityMatches0282(fake.ProcessPID, fake.ProcessIdentity) {
		t.Fatal("Принят повторно использованный PID")
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		t.Fatal(err)
	}
	recovered, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if recovered.RecoveredFrom != "previous-session" || recovered.Status != "exited" {
		t.Fatalf("Не удалось восстановить устаревший Runtime: %+v", recovered)
	}
	// Новый супервизор не должен принимать под управление всё ещё работающий процесс с подтверждённой идентичностью.
	fake.ProcessIdentity = hostOwnIdentity0282()
	if err := atomicWriteJSON01910(paths["runtime"], fake, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runServerBridgeHost01910(root, false); err == nil {
		t.Fatal("Принят осиротевший работающий процесс")
	}
	// Устаревшие незаблокированные запросы не должны случайно адресоваться другому супервизору.
	if hostTakeStopRequest0282(paths["stop"], "new-session", os.Getpid()) {
		t.Fatal("Принята команда остановки несуществующего процесса")
	}
}

func TestHost0282CrashLoopWindowAndLogRotation(t *testing.T) {
	root, java := hostFixture0282(t, `echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
sleep 0.2
exit 8`)
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--restart-policy", "on-failure", "--max-restarts", "2", "--restart-backoff-ms", "10", "--crash-window-seconds", "120", "--log-max-bytes", "1024", "--log-backups", "2"}); err != nil {
		t.Fatal(err)
	}
	err := runServerBridgeHost01910(root, false)
	if err == nil {
		t.Fatal("Сбой должен возвращать ошибку")
	}
	paths := hostPaths01910(root)
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if state.CrashCount != 3 || state.RestartCount != 2 || !strings.Contains(state.LastError, "Достигнут лимит перезапусков после сбоев") {
		t.Fatalf("Неожиданное состояние после сбоя: %+v", state)
	}
	if delay := hostRestartDelay0282(2000, 4); delay != 16*time.Second {
		t.Fatalf("Неожиданная задержка повторного запуска: %v", delay)
	}
	writer, err := newHostRollingWriter0282(filepath.Join(root, "rolling.log"), 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := writer.Write([]byte(strings.Repeat("x", 400))); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "rolling.log.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "rolling.log.2")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "rolling.log.3")); !os.IsNotExist(err) {
		t.Fatal("Ротация превысила допустимый срок хранения")
	}
}
