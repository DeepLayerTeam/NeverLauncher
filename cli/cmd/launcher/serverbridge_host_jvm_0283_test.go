package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func hostJavaFixture0283(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX Java fixture")
	}
	root := t.TempDir()
	java := writeFakeJava01910(t, root, `printf '%s\n' "$@" > "${PWD}/actual-launch-argv.txt"
echo 'Java fixture started'
exit 0`)
	return root, java
}

func hostTestArgs0283(root, java string) []string {
	return []string{"--server-root", root, "--platform", "paper", "--java", java, "--restart-policy", "never"}
}

func TestJVM0283MainClassRunsApprovedLaunch(t *testing.T) {
	root, java := hostJavaFixture0283(t)
	if err := os.Mkdir(filepath.Join(root, "libs"), 0755); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(root, "libs", "server.jar")
	if err := os.WriteFile(jar, []byte("test jar"), 0600); err != nil {
		t.Fatal(err)
	}
	args := append(hostTestArgs0283(root, java), "--launch-mode", "java-main-class", "--main-class", "org.example.Server", "--classpath-entry", "libs/server.jar", "--classpath-entry", "libs", "--jvm-arg", "-Xmx512M", "--server-arg", "nogui")
	if err := configureServerBridgeHost01910(args); err != nil {
		t.Fatal(err)
	}
	config, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Classpath, []string{jar, filepath.Join(root, "libs")}) {
		t.Fatalf("canonical classpath: %v", config.Classpath)
	}
	expected := []string{"-Xmx512M", "-cp", strings.Join(config.Classpath, string(os.PathListSeparator)), "org.example.Server", "nogui"}
	cmd, err := serverBridgeHostCommand01910(config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cmd[1:], expected) {
		t.Fatalf("cmd: %v vs %v", cmd, expected)
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(root, "actual-launch-argv.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(actual)) != strings.Join(expected, "\n") {
		t.Fatalf("actual argv: %s", actual)
	}
}

func TestJVM0283ModuleLaunchAndValidation(t *testing.T) {
	root, java := hostJavaFixture0283(t)
	if err := os.Mkdir(filepath.Join(root, "modules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "modules", "server.jar"), []byte("module"), 0600); err != nil {
		t.Fatal(err)
	}
	args := append(hostTestArgs0283(root, java), "--module", "org.example.server", "--modulepath-entry", "modules/server.jar", "--main-class", "org.example.Main")
	if err := configureServerBridgeHost01910(args); err != nil {
		t.Fatal(err)
	}
	config, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
	if err != nil {
		t.Fatal(err)
	}
	if config.LaunchMode != "java-module" {
		t.Fatalf("unexpected mode: %s", config.LaunchMode)
	}
	command, err := serverBridgeHostCommand01910(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(command, " "); !strings.Contains(got, "--module-path "+filepath.Join(root, "modules", "server.jar")+" --module org.example.server/org.example.Main") {
		t.Fatalf("command: %v", command)
	}
	if err := runServerBridgeHost01910(root, false); err != nil {
		t.Fatal(err)
	}
}

func TestJVM0283HostRejectsExecutionAndInjection(t *testing.T) {
	root, java := hostJavaFixture0283(t)
	if err := os.WriteFile(filepath.Join(root, "paper.jar"), []byte("jar"), 0600); err != nil {
		t.Fatal(err)
	}
	base := append(hostTestArgs0283(root, java), "--server-jar", "paper.jar")
	for _, injected := range []string{"-javaagent:evil.jar", "@evil.opts", "-cp", "-Djava.system.class.loader=evil.Loader", "-Xbootclasspath/a:evil.jar", "-XX:OnOutOfMemoryError=touch /tmp/owned"} {
		t.Run(injected, func(t *testing.T) {
			args := append(append([]string{}, base...), "--jvm-arg", injected)
			if err := configureServerBridgeHost01910(args); err == nil {
				t.Fatalf("accepted %q", injected)
			}
		})
	}
	if err := configureServerBridgeHost01910(append(append([]string{}, base...), "--server-arg", "@untrusted.txt")); err == nil {
		t.Fatal("accepted game argfile")
	}
	custom := filepath.Join(root, "arbitrary-executable")
	if err := os.WriteFile(custom, []byte("#!/bin/sh\necho 'openjdk version \"21\"' >&2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	other := []string{"--server-root", root, "--platform", "paper", "--server-jar", "paper.jar", "--java", custom}
	if err := configureServerBridgeHost01910(other); err == nil {
		t.Fatal("unapproved executable accepted")
	}
	if err := configureServerBridgeHost01910(append(other, "--allow-custom-java-executable")); err != nil {
		t.Fatalf("explicit host opt-in: %v", err)
	}
}

func TestJVM0283RejectsEscapingAndChangedArtifacts(t *testing.T) {
	root, java := hostJavaFixture0283(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "escape.jar"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "escape.jar"), filepath.Join(root, "escape.jar")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	base := append(hostTestArgs0283(root, java), "--launch-mode", "java-main-class", "--main-class", "org.example.Main")
	if err := configureServerBridgeHost01910(append(append([]string{}, base...), "--classpath-entry", "escape.jar")); err == nil {
		t.Fatal("outside symlink accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "good.jar"), []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := configureServerBridgeHost01910(append(append([]string{}, base...), "--classpath-entry", "good.jar")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "good.jar")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "escape.jar"), filepath.Join(root, "good.jar")); err != nil {
		t.Fatal(err)
	}
	config, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverBridgeHostCommand01910(config); err == nil {
		t.Fatal("artifact changed after configure but launch accepted")
	}
}

func TestJVM0283ClasspathWildcardAndPathRejections(t *testing.T) {
	root, java := hostJavaFixture0283(t)
	if err := os.Mkdir(filepath.Join(root, "libs"), 0755); err != nil {
		t.Fatal(err)
	}
	base := append(hostTestArgs0283(root, java), "--launch-mode", "java-main-class", "--main-class", "a.Main")
	if err := configureServerBridgeHost01910(append(append([]string{}, base...), "--classpath-entry", filepath.Join("libs", "*"))); err != nil {
		t.Fatal(err)
	}
	config, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Classpath) != 1 || config.Classpath[0] != filepath.Join(root, "libs", "*") {
		t.Fatalf("wildcard: %v", config.Classpath)
	}
	for _, bad := range []string{"libs/*.jar", "../libs/*", "libs/*/nested", ""} {
		if err := configureServerBridgeHost01910(append(append([]string{}, base...), "--classpath-entry", bad)); err == nil {
			t.Errorf("accepted invalid classpath %q", bad)
		}
	}
}

// Exercises the real JVM, rather than only testing an exec argv fixture.
func TestJVM0283RealJavaClasspathAndModule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses Unix filesystem layout")
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("Java runtime unavailable")
	}
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac unavailable")
	}
	version, err := javaMajorVersion(java)
	if err != nil || version < 9 {
		t.Skip("Java 9+ required for module test")
	}
	for _, module := range []bool{false, true} {
		name := "classpath"
		if module {
			name = "module"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "src", "org", "example", "Server.java")
			if err := os.MkdirAll(filepath.Dir(source), 0755); err != nil {
				t.Fatal(err)
			}
			code := `package org.example; public final class Server { public static void main(String[] args) { System.out.println("ACTUAL_JAVA_" + args[0]); } }`
			if err := os.WriteFile(source, []byte(code), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "classes")
			if err := os.Mkdir(output, 0755); err != nil {
				t.Fatal(err)
			}
			argv := []string{"-d", output, source}
			if module {
				descriptor := filepath.Join(root, "src", "module-info.java")
				if err := os.WriteFile(descriptor, []byte(`module org.example.server { }`), 0600); err != nil {
					t.Fatal(err)
				}
				argv = append(argv, descriptor)
			}
			if out, err := exec.Command(javac, argv...).CombinedOutput(); err != nil {
				t.Fatalf("compile Java fixture: %v: %s", err, out)
			}
			args := []string{"--server-root", root, "--platform", "paper", "--java", java, "--restart-policy", "never", "--server-arg", "E2E"}
			if module {
				args = append(args, "--launch-mode", "java-module", "--module", "org.example.server", "--main-class", "org.example.Server", "--modulepath-entry", output)
			} else {
				args = append(args, "--launch-mode", "java-main-class", "--main-class", "org.example.Server", "--classpath-entry", output)
			}
			if err := configureServerBridgeHost01910(args); err != nil {
				t.Fatal(err)
			}
			if err := runServerBridgeHost01910(root, false); err != nil {
				t.Fatal(err)
			}
			stdout, err := os.ReadFile(hostPaths01910(root)["stdout"])
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(stdout), "ACTUAL_JAVA_E2E") {
				t.Fatalf("real Java main not executed, stdout=%s", stdout)
			}
		})
	}
}

func TestJVM0283UserJVMArgfileCannotInjectAgent(t *testing.T) {
	root, java := hostJavaFixture0283(t)
	argsFile := filepath.Join(root, "unix_args.txt")
	if err := os.WriteFile(argsFile, []byte("-Dforge.fixture=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := configureServerBridgeHost01910(append(hostTestArgs0283(root, java), "--launch-mode", "java-args-file", "--java-args-file", argsFile)); err != nil {
		t.Fatal(err)
	}
	userArgs := filepath.Join(root, "user_jvm_args.txt")
	if err := os.WriteFile(userArgs, []byte("# safe JVM flags\n-Xmx2G\n-XX:+UseG1GC\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := readServerBridgeHostConfig01910(hostPaths01910(root)["config"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverBridgeHostCommand01910(config); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userArgs, []byte("-javaagent:unauthorized.jar\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := serverBridgeHostCommand01910(config); err == nil {
		t.Fatal("malicious user_jvm_args.txt accepted")
	}
}

func TestJVM0283RestartRechecksArtifacts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture replaces symlink from POSIX shell")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "malicious.jar")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(root, "server.jar")
	if err := os.WriteFile(jar, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	body := "rm -f \"" + jar + "\"\nln -s \"" + outside + "\" \"" + jar + "\"\nexit 7"
	java := writeFakeJava01910(t, root, body)
	args := []string{"--server-root", root, "--platform", "paper", "--java", java, "--server-jar", "server.jar", "--restart-policy", "on-failure", "--max-restarts", "1", "--restart-backoff-ms", "0"}
	if err := configureServerBridgeHost01910(args); err != nil {
		t.Fatal(err)
	}
	if err := runServerBridgeHost01910(root, false); err == nil {
		t.Fatal("restarted after unsafe artifact swap")
	}
	state, err := readServerBridgeHostRuntime01910(hostPaths01910(root)["runtime"])
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "failed" || !strings.Contains(state.LastError, "JAR") {
		t.Fatalf("expected preflight failure before relaunch: %+v", state)
	}
}
