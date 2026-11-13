//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Этот дочерний процесс — реальный системный супервизор, а не имитация. Он запускает
// настоящий исполняемый OpenJDK через производственный механизм Host.
func TestHostSupervisorProcessHelper0414(t *testing.T) {
	root := os.Getenv("LAUNCHER_0414_HOST_HELPER")
	if root == "" {
		return
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка супервизора хоста:", err)
		os.Exit(77)
	}
	os.Exit(0)
}

func hostRealJavaFixture0414(t *testing.T, mode string, restarts int) string {
	t.Helper()
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("исполняемый файл Java недоступен")
	}
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("компилятор Java недоступен")
	}
	jar, err := exec.LookPath("jar")
	if err != nil {
		t.Skip("инструмент jar недоступен")
	}
	root := t.TempDir()
	source := filepath.Join(root, "JvmLifecycleFixture.java")
	// Коды завершения и файлы состояния записывает настоящий процесс Java.
	code := `import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
public class JvmLifecycleFixture {
 static void append(String value) throws Exception {
  Files.writeString(Path.of("jvm-events.txt"), value + "\n", StandardCharsets.UTF_8,
    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
 }
 public static void main(String[] args) throws Exception {
  String mode = args[0];
  append("BOOT:" + ProcessHandle.current().pid());
  System.out.println("JAVA_PROCESS_STARTED=" + ProcessHandle.current().pid());
  if (mode.equals("crash-always")) { append("CRASH"); System.exit(23); }
  if (mode.equals("crash-once") && !Files.exists(Path.of("first-crash.marker"))) {
    Files.writeString(Path.of("first-crash.marker"), "1");
    append("CRASH"); System.exit(23);
  }
  BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
  for (String command; (command = input.readLine()) != null;) {
    if (command.equals("stop")) {
      append("WORLD-SAVED"); System.out.println("WORLD-SAVED"); return;
    }
  }
 }
}`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	classes := filepath.Join(root, "classes")
	if err := os.Mkdir(classes, 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(javac, "-d", classes, source).CombinedOutput(); err != nil {
		t.Fatalf("ошибка компилятора javac: %v: %s", err, out)
	}
	if out, err := exec.Command(jar, "--create", "--file", filepath.Join(root, "paper.jar"), "--main-class", "JvmLifecycleFixture", "-C", classes, ".").CombinedOutput(); err != nil {
		t.Fatalf("ошибка упаковки JAR: %v: %s", err, out)
	}
	args := []string{"--server-root", root, "--platform", "paper", "--java", java, "--server-jar", "paper.jar", "--restart-policy", "on-failure", "--max-restarts", fmt.Sprint(restarts), "--restart-backoff-ms", "50", "--stop-timeout-seconds", "2", "--server-arg", mode}
	if err := configureServerBridgeHost01910(args); err != nil {
		t.Fatal(err)
	}
	return root
}

func hostLaunchSupervisor0414(t *testing.T, root string) (*exec.Cmd, <-chan error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostSupervisorProcessHelper0414$")
	cmd.Env = append(os.Environ(), "LAUNCHER_0414_HOST_HELPER="+root)
	stderr := filepath.Join(root, fmt.Sprintf("test-supervisor-%d.log", time.Now().UnixNano()))
	log, err := os.Create(stderr)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	log.Close()
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	t.Cleanup(func() {
		// Не допускайте утечки работающего Java-процесса из тестового окружения.
		state, err := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
		if err == nil && state.SupervisorPID == cmd.Process.Pid && hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
			_ = stopServerBridgeHost01910([]string{"--server-root", root})
			if hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
				_ = hostKillProcess01910(state.ProcessPID)
			}
		}
	})
	return cmd, finished
}

func hostWaitRealJava0414(t *testing.T, root string, supervisorPID int, minimumRestarts int) serverBridgeHostRuntime01910 {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		state, err := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
		if err == nil && (supervisorPID == 0 || state.SupervisorPID == supervisorPID) && state.Status == "running" && state.RestartCount >= minimumRestarts && hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
			exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", state.ProcessPID))
			if err != nil || !strings.Contains(exe, "java") {
				t.Fatalf("Ожидалась реальная JVM, получен исполняемый файл %q: %v", exe, err)
			}
			if data, _ := os.ReadFile(filepath.Join(root, "jvm-events.txt")); strings.Contains(string(data), fmt.Sprintf("BOOT:%d", state.ProcessPID)) {
				return state
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	state, _ := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
	log, _ := os.ReadFile(hostPaths01910(root)["supervisor"])
	t.Fatalf("Реальная JVM не прошла проверку: состояние=%+v, журнал=%s", state, log)
	return serverBridgeHostRuntime01910{}
}

func hostCheckFinished0414(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Ошибка завершения диспетчера: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("Диспетчер не завершился")
	}
}

func TestHostLifecycle0414RealJVMStartStopRestartAndSIGTERM(t *testing.T) {
	root := hostRealJavaFixture0414(t, "run", 0)
	first, done := hostLaunchSupervisor0414(t, root)
	old := hostWaitRealJava0414(t, root, first.Process.Pid, 0)
	if err := stopServerBridgeHost01910([]string{"--server-root", root}); err != nil {
		t.Fatal(err)
	}
	hostCheckFinished0414(t, done)
	state, _ := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
	if state.Status != "stopped" || state.StopMethod != "console-stop" || hostIdentityMatches0282(old.ProcessPID, old.ProcessIdentity) {
		t.Fatalf("Остановка не подтверждена: %+v", state)
	}
	second, done2 := hostLaunchSupervisor0414(t, root)
	newState := hostWaitRealJava0414(t, root, second.Process.Pid, 0)
	if newState.SessionID == old.SessionID || newState.ProcessIdentity == old.ProcessIdentity {
		t.Fatalf("Перезапуск не заменил процесс и сеанс диспетчера: прежний=%+v, новый=%+v", old, newState)
	}
	if err := syscall.Kill(second.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	hostCheckFinished0414(t, done2)
	stopped, _ := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
	if stopped.Status != "stopped" || stopped.StopMethod != "signal-console-stop" || stopped.ProcessPID != 0 {
		t.Fatalf("Сигнал SIGTERM оставил JVM без управления: %+v", stopped)
	}
	data, err := os.ReadFile(filepath.Join(root, "jvm-events.txt"))
	if err != nil || strings.Count(string(data), "WORLD-SAVED") != 2 || strings.Count(string(data), "BOOT:") != 2 {
		t.Fatalf("Отсутствуют маркеры жизненного цикла процесса Java: %s (%v)", data, err)
	}
}

func TestHostLifecycle0414RealJVMAutoRecoveryAfterCrash(t *testing.T) {
	root := hostRealJavaFixture0414(t, "crash-once", 2)
	cmd, done := hostLaunchSupervisor0414(t, root)
	running := hostWaitRealJava0414(t, root, cmd.Process.Pid, 1)
	if running.CrashCount != 1 || running.RestartCount != 1 || running.Crashed {
		t.Fatalf("Неверное восстановление после сбоя: %+v", running)
	}
	if err := stopServerBridgeHost01910([]string{"--server-root", root}); err != nil {
		t.Fatal(err)
	}
	hostCheckFinished0414(t, done)
	data, _ := os.ReadFile(filepath.Join(root, "jvm-events.txt"))
	if strings.Count(string(data), "CRASH") != 1 || strings.Count(string(data), "BOOT:") != 2 || strings.Count(string(data), "WORLD-SAVED") != 1 {
		t.Fatalf("Реальный сбой Java не устранён: %s", data)
	}
}

func TestHostLifecycle0414RealJVMCrashLoopIsBounded(t *testing.T) {
	root := hostRealJavaFixture0414(t, "crash-always", 2)
	err := runServerBridgeHost01910(root, false)
	if err == nil {
		t.Fatal("Ошибочно разрешён циклический сбой реальной JVM")
	}
	state, readErr := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
	if readErr != nil {
		t.Fatal(readErr)
	}
	if state.Status != "crashed" || state.ProcessPID != 0 || state.CrashCount != 3 || state.RestartCount != 2 || !strings.Contains(state.LastError, "Достигнут лимит перезапусков после сбоев") {
		t.Fatalf("Неожиданный предел аварий Java: %+v (%v)", state, err)
	}
	data, _ := os.ReadFile(filepath.Join(root, "jvm-events.txt"))
	if strings.Count(string(data), "BOOT:") != 3 || strings.Count(string(data), "CRASH") != 3 {
		t.Fatalf("Неожиданные реальные запуски Java: %s", data)
	}
}

// Проверяет реальный скомпилированный производственный CLI: start создаёт собственный дочерний
// процесс, stop ждёт завершения JVM, а restart подтверждает другой процесс ОС.
func TestHostLifecycle0414ActualCLIAndRemoteEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("собирается настоящий CLI")
	}
	root := hostRealJavaFixture0414(t, "run", 0)
	cli := filepath.Join(t.TempDir(), "nl")
	build := exec.Command("go", "build", "-o", cli, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Ошибка сборки промышленного CLI: %v: %s", err, output)
	}
	run := func(action string) error {
		command := exec.Command(cli, "server-bridge", "host", action, "--server-root", root)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("вызов реального CLI %s: %w: %s", action, err, output)
		}
		return nil
	}
	if err := run("start"); err != nil {
		t.Fatal(err)
	}
	first := hostWaitRealJava0414(t, root, 0, 0)
	// CLI не является супервизором: отсоединённая фоновая JVM всё ещё работает.
	if !hostIdentityMatches0282(first.ProcessPID, first.ProcessIdentity) {
		t.Fatal("Команда запуска CLI завершилась без работающей JVM")
	}
	if err := run("restart"); err != nil {
		t.Fatal(err)
	}
	second := hostWaitRealJava0414(t, root, 0, 0)
	if first.SessionID == second.SessionID || first.ProcessIdentity == second.ProcessIdentity {
		t.Fatalf("Перезапуск через CLI не запустил новую JVM: прежняя=%+v, новая=%+v", first, second)
	}
	if err := run("stop"); err != nil {
		t.Fatal(err)
	}
	final, err := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
	if err != nil || final.Status != "stopped" || hostIdentityMatches0282(second.ProcessPID, second.ProcessIdentity) {
		t.Fatalf("Остановка через CLI не подтвердила завершение процесса: %+v %v", final, err)
	}
	events, _ := os.ReadFile(filepath.Join(root, "jvm-events.txt"))
	if strings.Count(string(events), "BOOT:") != 2 || strings.Count(string(events), "WORLD-SAVED") != 2 {
		t.Fatalf("Несоответствие реального жизненного цикла CLI: %s", events)
	}
}

func TestHostLifecycle0414StopWhileJavaCrashIsInBackoff(t *testing.T) {
	root := hostRealJavaFixture0414(t, "crash-always", 3)
	paths := hostPaths01910(root)
	config, err := readServerBridgeHostConfig01910(paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	config.RestartBackoffMillis = 3000
	if err = atomicWriteJSON01910(paths["config"], config, 0600); err != nil {
		t.Fatal(err)
	}
	proc, done := hostLaunchSupervisor0414(t, root)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		state, _ := readServerBridgeHostRuntime01910(paths["runtime"])
		if state.SupervisorPID == proc.Process.Pid && state.Status == "restarting" && state.ProcessPID == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	state, _ := readServerBridgeHostRuntime01910(paths["runtime"])
	if state.Status != "restarting" {
		t.Fatalf("После реального сбоя Java не наступила задержка повторного запуска: %+v", state)
	}
	if err := stopServerBridgeHost01910([]string{"--server-root", root}); err != nil {
		t.Fatal(err)
	}
	hostCheckFinished0414(t, done)
	state, _ = readServerBridgeHostRuntime01910(paths["runtime"])
	if state.Status != "stopped" || state.RestartCount != 1 || state.ProcessPID != 0 {
		t.Fatalf("Остановка во время задержки перезапуска запустила другую JVM: %+v", state)
	}
	data, _ := os.ReadFile(filepath.Join(root, "jvm-events.txt"))
	if strings.Count(string(data), "BOOT:") != 1 {
		t.Fatalf("JVM перезапустилась после остановки во время задержки: %s", data)
	}
}

func TestHostLifecycle0414StopSessionBoundAcrossProcessStartup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "stop.request")
	req := hostStopRequest0282{SessionID: "fresh-session", ProcessPID: 0, RequestedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := atomicWriteJSON01910(path, req, 0600); err != nil {
		t.Fatal(err)
	}
	if hostTakeStopRequest0282(path, "old-session", 1234) {
		t.Fatal("Устаревший сеанс обработал остановку без процесса")
	}
	if !hostTakeStopRequest0282(path, "fresh-session", 1234) {
		t.Fatal("Остановка без процесса не затронула параллельно запущенную JVM")
	}
	if hostTakeStopRequest0282(path, "fresh-session", 1234) {
		t.Fatal("Запрос остановки выполнен дважды")
	}
}
