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
		t.Skip("host runtime identity integration fixtures currently require Linux")
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
		t.Fatalf("not running: %+v", state)
	}
	// A delayed request issued by an obsolete session must not stop this JVM.
	forged := hostStopRequest0282{SessionID: "previous-session", ProcessPID: state.ProcessPID}
	if err := atomicWriteJSON01910(paths["stop"], forged, 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	if !hostIdentityMatches0282(state.ProcessPID, state.ProcessIdentity) {
		t.Fatal("stale request unexpectedly stopped JVM")
	}
	started := time.Now()
	if err := stopServerBridgeHost01910([]string{"--server-root", root}); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 1500*time.Millisecond {
		t.Fatal("console stop did not shut down before OS signal fallback")
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not finish")
	}
	state, _ = readServerBridgeHostRuntime01910(paths["runtime"])
	if state.Status != "stopped" || state.StopMethod != "console-stop" || state.ProcessIdentity != "" {
		t.Fatalf("stopped runtime: %+v", state)
	}
	log, _ := os.ReadFile(paths["stdout"])
	if !strings.Contains(string(log), "WORLD-SAVED") {
		t.Fatalf("missing save proof: %q", log)
	}
}

func TestHost0282EnvironmentAllowlistAndWorkingDirectory(t *testing.T) {
	root, java := hostFixture0282(t, `printf 'pwd=%s\n' "$PWD"
printf 'allowed=%s\n' "${TEST_GAME_ENV:-MISSING}"
printf 'denied=%s\n' "${UNSAFE_LEAK_VALUE:-MISSING}"
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
		t.Fatal("status config leaks environment secrets")
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		t.Fatal(err)
	}
	output, _ := os.ReadFile(hostPaths01910(root)["stdout"])
	if !strings.Contains(string(output), "pwd="+work) || !strings.Contains(string(output), "allowed=token-fixture") || !strings.Contains(string(output), "denied=MISSING") {
		t.Fatalf("unexpected subprocess environment: %q", output)
	}
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--env", "SECRET=oops"}); err == nil {
		t.Fatal("variable outside allowlist was accepted")
	}
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--working-directory", ".."}); err == nil {
		t.Fatal("working directory traversal was accepted")
	}
}

func TestHost0282IdentityRecoveryAndStalePID(t *testing.T) {
	root, java := hostFixture0282(t, `exit 0`)
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--restart-policy", "never"}); err != nil {
		t.Fatal(err)
	}
	paths := hostPaths01910(root)
	// A PID reused by the OS must not be treated as the old JVM.
	fake := serverBridgeHostRuntime01910{Status: "running", SessionID: "previous-session", ProcessPID: os.Getpid(), ProcessIdentity: "old-boot:0", SupervisorPID: 123}
	if err := atomicWriteJSON01910(paths["runtime"], fake, 0600); err != nil {
		t.Fatal(err)
	}
	if hostIdentityMatches0282(fake.ProcessPID, fake.ProcessIdentity) {
		t.Fatal("reused PID accepted")
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		t.Fatal(err)
	}
	recovered, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if recovered.RecoveredFrom != "previous-session" || recovered.Status != "exited" {
		t.Fatalf("stale runtime recovery failed: %+v", recovered)
	}
	// A still-live, identity-proven process must not be adopted by a new supervisor.
	fake.ProcessIdentity = hostOwnIdentity0282()
	if err := atomicWriteJSON01910(paths["runtime"], fake, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runServerBridgeHost01910(root, false); err == nil {
		t.Fatal("live orphan was accepted")
	}
	// Stale unlocked requests cannot accidentally target another supervisor.
	if hostTakeStopRequest0282(paths["stop"], "new-session", os.Getpid()) {
		t.Fatal("nonexistent stop request accepted")
	}
}

func TestHost0282CrashLoopWindowAndLogRotation(t *testing.T) {
	root, java := hostFixture0282(t, `echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
exit 8`)
	if err := configureServerBridgeHost01910([]string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", java, "--restart-policy", "on-failure", "--max-restarts", "2", "--restart-backoff-ms", "10", "--crash-window-seconds", "120", "--log-max-bytes", "1024", "--log-backups", "2"}); err != nil {
		t.Fatal(err)
	}
	err := runServerBridgeHost01910(root, false)
	if err == nil {
		t.Fatal("crash should return error")
	}
	paths := hostPaths01910(root)
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if state.CrashCount != 3 || state.RestartCount != 2 || !strings.Contains(state.LastError, "crash-loop") {
		t.Fatalf("unexpected crash state: %+v", state)
	}
	if delay := hostRestartDelay0282(2000, 4); delay != 16*time.Second {
		t.Fatalf("unexpected backoff %v", delay)
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
		t.Fatal("rotation exceeded retention")
	}
}
