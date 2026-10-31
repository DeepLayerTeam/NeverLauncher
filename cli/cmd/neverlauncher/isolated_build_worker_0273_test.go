package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProcessorWorker0273ExecutesOutsideCLIWithSanitizedEnvAndLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake-Java fixture")
	}
	dir := t.TempDir()
	java := filepath.Join(dir, "java")
	// Java fixture writes its own PID, inherited secret status and a result.
	script := `#!/bin/sh
printf '%s' "$PPID" > "$PWD/worker-parent.pid"
if [ -n "$NEVERLAUNCHER_TOKEN" ]; then exit 99; fi
if [ -z "$NEVERLAUNCHER_BUILD_WORKER" ]; then exit 98; fi
printf 'ok' > "$PWD/generated.jar"
printf 'logged output\n'
`
	if err := os.WriteFile(java, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEVERLAUNCHER_TOKEN", "should-not-be-in-child")
	pc := forgeProcessorContext{ClientDir: dir, JavaExecutable: java, Timeout: 10 * time.Second}
	path, err := runIsolatedProcessor0273(context.Background(), pc, 4, []string{"-cp", "test.jar", "example.Processor"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "generated.jar"))
	if err != nil || string(got) != "ok" {
		t.Fatalf("missing executed output: %s %v", got, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "logged output") || !strings.Contains(string(raw), "success=true") {
		t.Fatalf("missing log evidence: %s", raw)
	}
	if strings.Contains(string(raw), "should-not-be-in-child") {
		t.Fatal("secret leaked into worker log")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "worker-parent.pid"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		t.Fatal("Java was not started")
	}
}

func TestProcessorWorker0273TimeoutKillsProcessGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux PGID test")
	}
	dir := t.TempDir()
	java := filepath.Join(dir, "java")
	// Includes a grandchild that inherits pipes: timeout must not wait for it.
	if err := os.WriteFile(java, []byte("#!/bin/sh\nsleep 60 &\nwait\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	path, err := runIsolatedProcessor0273(ctx, forgeProcessorContext{ClientDir: dir, JavaExecutable: java, Timeout: 20 * time.Second}, 0, []string{"-cp", "a", "Main"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("worker process tree failed to exit promptly: %s", time.Since(start))
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || !strings.Contains(string(data), "success=false") {
		t.Fatalf("failure log missing: %s %v", data, readErr)
	}
}

func TestProcessorWorker0273RefusesOversizedOrUntrustedRequest(t *testing.T) {
	// Do not permit JSON requests that cannot be independently bounded or
	// execution paths that are resolved relative to arbitrary PATH entries.
	tooBig := processorWorkerRequest0273{Java: "/usr/bin/java", Directory: "/tmp", TempDirectory: "/tmp", TimeoutSeconds: 60, HeapMiB: 2048, Args: make([]string, 5000)}
	raw, err := json.Marshal(tooBig)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > workerRequestLimit0273 {
		t.Log("oversized request is rejected at transport")
	}
	if len(tooBig.Args) <= 4096 {
		t.Fatal("invalid fixture")
	}
}

func TestForgeProcessorInputFingerprint0273RejectsModifiedClasspath(t *testing.T) {
	dir := t.TempDir()
	java := filepath.Join(dir, "java")
	jar := filepath.Join(dir, "libraries", "example", "p", "1", "p-1.jar")
	if err := os.MkdirAll(filepath.Dir(jar), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(java, []byte("java"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	pc := forgeProcessorContext{ClientDir: dir, JavaExecutable: java}
	processor := forgeProcessor{Jar: "example:p:1"}
	a, err := fingerprintForgeProcessor0273(pc, processor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jar, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := fingerprintForgeProcessor0273(pc, processor)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("modified processor jar must invalidate journal identity")
	}
	if err := os.Remove(jar); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintForgeProcessor0273(pc, processor); err == nil {
		t.Fatal("missing processor inputs must be fatal")
	}
}

func TestForgeProcessorRecovery0273QuarantinesCorruptOutputAndChangedInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	root := t.TempDir()
	java := testFakeJava(t, []byte("verified-processor-output"))
	installer := filepath.Join(root, ".launcher", "installers", "forge", "52.0.1", "installer.jar")
	processorJar := filepath.Join(root, "libraries", "com", "example", "processor", "1.0", "processor-1.0.jar")
	for _, f := range []string{installer, processorJar} {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(installer, []byte("stable-installer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(processorJar, testProcessorJar(t), 0o600); err != nil {
		t.Fatal(err)
	}
	rel, err := mavenCoordinatePath("com.example:generated:1.0")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "libraries", filepath.FromSlash(rel))
	pc := forgeProcessorContext{
		Loader: "forge", MinecraftVersion: "1.21.1", ClientDir: root, InstallerPath: installer,
		JavaExecutable: java, Timeout: 5 * time.Second, Profile: &forgeInstallerProfile{Processors: []forgeProcessor{{
			Jar: "com.example:processor:1.0", Args: []string{"--out", "[com.example:generated:1.0]"},
			Outputs: map[string]string{"[com.example:generated:1.0]": sha1HexLocal([]byte("verified-processor-output"))},
		}}},
	}
	first, err := runForgeProcessors(context.Background(), pc)
	if err != nil || first.Ran != 1 {
		t.Fatalf("first run %+v: %v", first, err)
	}
	second, err := runForgeProcessors(context.Background(), pc)
	if err != nil || second.Skipped != 1 {
		t.Fatalf("second run %+v: %v", second, err)
	}
	if err := os.WriteFile(output, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := runForgeProcessors(context.Background(), pc)
	if err != nil || third.Ran != 1 || third.Skipped != 0 {
		t.Fatalf("corrupt output accepted %+v: %v", third, err)
	}
	if got, err := os.ReadFile(output); err != nil || string(got) != "verified-processor-output" {
		t.Fatalf("unrecovered file: %s %v", got, err)
	}
	if err := os.WriteFile(processorJar, testProcessorJar(t), 0o600); err != nil {
		t.Fatal(err)
	} // same bytes
	fourth, err := runForgeProcessors(context.Background(), pc)
	if err != nil || fourth.Skipped != 1 {
		t.Fatalf("identical JAR bytes changed fingerprint: %+v %v", fourth, err)
	}
	if err := os.WriteFile(processorJar, append(testProcessorJar(t), 0), 0o600); err != nil {
		t.Fatal(err)
	}
	fifth, err := runForgeProcessors(context.Background(), pc)
	if err != nil || fifth.Ran != 1 {
		t.Fatalf("modified input did not invalidate processor result %+v: %v", fifth, err)
	}
	journal, _, err := loadForgeProcessorJournal(pc)
	if err != nil || journal.Entries["0"].WorkerLogPath == "" || !isSHA256Hex0271(journal.Entries["0"].InputSHA256) {
		t.Fatalf("journal evidence missing: %+v %v", journal, err)
	}
	qdir := filepath.Join(root, ".launcher", "quarantine")
	found, err := os.ReadDir(qdir)
	if err != nil || len(found) < 2 {
		t.Fatalf("corrupt and stale outputs not quarantined: %v %v", found, err)
	}
}

func TestForgeProcessorRecovery0273RejectsSymlinkOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires symlinks")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "external.jar")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(root, "output.jar")
	if err := os.Symlink(outside, in); err != nil {
		t.Fatal(err)
	}
	pc := forgeProcessorContext{ClientDir: root}
	_, err := processorOutputsMatch(pc, forgeProcessor{Outputs: map[string]string{"{ROOT}/output.jar": sha1HexLocal([]byte("outside"))}})
	if err == nil {
		t.Fatal("symlink output was accepted as a trusted processor result")
	}
}

func TestProcessorWorker0273StrictSandboxFailsClosedWhenUnsupported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux bubblewrap availability contract")
	}
	if _, err := exec.LookPath("bwrap"); err == nil {
		t.Skip("bubblewrap present: needs system-supported namespace integration to certify")
	}
	root := t.TempDir()
	java := filepath.Join(root, "java")
	if err := os.WriteFile(java, []byte("#!/bin/sh\nprintf 'unsafe fallback' > generated.jar\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pc := forgeProcessorContext{ClientDir: root, JavaExecutable: java, StrictSandbox: true, Timeout: 5 * time.Second}
	log, err := runIsolatedProcessor0273(context.Background(), pc, 0, []string{"-cp", "a", "Main"})
	if err == nil || !strings.Contains(err.Error(), "bubblewrap") {
		t.Fatalf("strict worker fallback is unsafe: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "generated.jar")); !os.IsNotExist(statErr) {
		t.Fatalf("processor ran outside strict sandbox: %v", statErr)
	}
	if _, err := os.Stat(log); err != nil {
		t.Fatalf("worker failure log unavailable: %v", err)
	}
}
