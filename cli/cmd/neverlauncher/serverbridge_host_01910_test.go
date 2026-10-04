package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestServerBridgeHostConfigureJavaJar01910(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture uses a POSIX fake java executable")
	}
	root := t.TempDir()
	jar := filepath.Join(root, "paper-1.21.1.jar")
	if err := os.WriteFile(jar, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	java := writeFakeJava01910(t, root, `echo "server stdout"
echo "server stderr" >&2
exit 0`)
	if err := configureServerBridgeHost01910([]string{
		"--server-root", root, "--platform", "paper", "--server-jar", jar, "--java", java,
		"--jvm-arg", "-Xms128M", "--jvm-arg=-Xmx256M", "--server-arg", "nogui", "--restart-policy", "never",
	}); err != nil {
		t.Fatal(err)
	}
	config, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
	if err != nil {
		t.Fatal(err)
	}
	if config.Platform != "paper" || config.LaunchMode != "java-jar" || config.JavaMajor != 21 {
		t.Fatalf("unexpected config: %+v", config)
	}
	if got := strings.Join(config.JVMArgs, " "); got != "-Xms128M -Xmx256M" {
		t.Fatalf("JVM args=%q", got)
	}
	command, err := serverBridgeHostCommand01910(config)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	if !strings.Contains(joined, "-Xms128M -Xmx256M -jar "+jar+" nogui") {
		t.Fatalf("command=%q", joined)
	}
}

func TestServerBridgeHostCrashRestartAndLogs01910(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture uses a POSIX fake java executable")
	}
	root := t.TempDir()
	jar := filepath.Join(root, "paper.jar")
	if err := os.WriteFile(jar, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	java := writeFakeJava01910(t, root, `COUNT_FILE="$PWD/.fake-java-count"
COUNT=0
if [ -f "$COUNT_FILE" ]; then COUNT=$(cat "$COUNT_FILE"); fi
COUNT=$((COUNT+1))
printf '%s' "$COUNT" > "$COUNT_FILE"
echo "stdout-run-$COUNT"
echo "stderr-run-$COUNT" >&2
if [ "$COUNT" -eq 1 ]; then exit 7; fi
exit 0`)
	if err := configureServerBridgeHost01910([]string{
		"--server-root", root, "--platform", "paper", "--server-jar", jar, "--java", java,
		"--restart-policy", "on-failure", "--max-restarts", "1", "--restart-backoff-ms", "0",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		t.Fatalf("supervisor run: %v", err)
	}
	paths := hostPaths01910(root)
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "exited" || state.RestartCount != 1 || state.CrashCount != 1 || state.ExitCode == nil || *state.ExitCode != 0 {
		t.Fatalf("unexpected runtime: %+v", state)
	}
	stdout, _ := os.ReadFile(paths["stdout"])
	stderr, _ := os.ReadFile(paths["stderr"])
	combined, _ := os.ReadFile(paths["combined"])
	if !strings.Contains(string(stdout), "stdout-run-1") || !strings.Contains(string(stdout), "stdout-run-2") {
		t.Fatalf("stdout log=%q", stdout)
	}
	if !strings.Contains(string(stderr), "stderr-run-1") || !strings.Contains(string(stderr), "stderr-run-2") {
		t.Fatalf("stderr log=%q", stderr)
	}
	if !strings.Contains(string(combined), "[STDOUT]") || !strings.Contains(string(combined), "[STDERR]") {
		t.Fatalf("combined log=%q", combined)
	}
}

func TestServerBridgeHostStopSupervisedProcess01910(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture uses POSIX signals")
	}
	root := t.TempDir()
	jar := filepath.Join(root, "paper.jar")
	if err := os.WriteFile(jar, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	java := writeFakeJava01910(t, root, `trap 'echo graceful-stop; exit 0' TERM INT
echo ready
while :; do sleep 1; done`)
	if err := configureServerBridgeHost01910([]string{
		"--server-root", root, "--platform", "paper", "--server-jar", jar, "--java", java,
		"--restart-policy", "never", "--stop-timeout-seconds", "3",
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runServerBridgeHost01910(root, false) }()
	paths := hostPaths01910(root)
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := readServerBridgeHostRuntime01910(paths["runtime"])
		if err == nil && state.Status == "running" && state.ProcessPID > 0 {
			pid = state.ProcessPID
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("Minecraft process did not enter running state")
	}
	if err := stopServerBridgeHost01910([]string{"--server-root", root}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned after stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not finish after stop")
	}
	state, err := readServerBridgeHostRuntime01910(paths["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "stopped" || state.ProcessPID != 0 || state.Crashed {
		t.Fatalf("unexpected stopped runtime: %+v", state)
	}
	stdout, _ := os.ReadFile(paths["stdout"])
	if !strings.Contains(string(stdout), "graceful-stop") {
		t.Fatalf("graceful stop missing from stdout: %q", stdout)
	}
}

func TestServerBridgeHostForgeArgsMode01910(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture uses a POSIX fake java executable")
	}
	root := t.TempDir()
	argsFile := filepath.Join(root, "libraries", "net", "minecraftforge", "forge", "1.20.1-47.3.0", "unix_args.txt")
	if err := os.MkdirAll(filepath.Dir(argsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(argsFile, []byte("-Dforge.fixture=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	java := writeFakeJava01910(t, root, `exit 0`)
	config := serverBridgeHostConfig01910{
		SchemaVersion: "1.0", ProductVersion: version, ServerRoot: root, Platform: "forge", LaunchMode: "java-args-file",
		JavaPath: java, JavaMajor: 21, JavaArgsFile: argsFile, RestartPolicy: "never", MaxRestarts: 0,
		RestartBackoffMillis: 0, StopTimeoutSeconds: 5,
	}
	command, err := serverBridgeHostCommand01910(config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(command, " "), "@"+argsFile) {
		t.Fatalf("forge args command=%v", command)
	}
}

func writeFakeJava01910(t *testing.T, root, body string) string {
	t.Helper()
	path := filepath.Join(root, "fake-java")
	script := `#!/bin/sh
if [ "${1:-}" = "-version" ]; then
  echo 'openjdk version "21.0.1"' >&2
  exit 0
fi
` + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
