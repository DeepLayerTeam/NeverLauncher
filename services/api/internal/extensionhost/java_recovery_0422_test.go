package extensionhost

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// These tests run a real, packed Java 17+ extension JAR, not a mocked host.
// The Java host fixture has a bounded startup/stop timeout and closes itself on cleanup.
func persistJavaInstall0422(t *testing.T, host *Supervisor, install model.ExtensionInstall) model.ExtensionInstall {
	t.Helper()
	ctx := context.Background()
	saved, err := host.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID,
		DesiredVersion: install.CurrentVersion, CurrentVersion: install.CurrentVersion,
		DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled,
		PackageIdentity: "sha256:" + strings.Repeat("a", 64), CurrentPackageIdentity: "sha256:" + strings.Repeat("a", 64),
		Enabled: true, Source: "java-recovery-test", Operation: "enable", ExpectedGeneration: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestJavaJvmCrashRestartsRealProcess0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	ctx, cancel := context.WithTimeout(context.Background(), 23*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	before, err := host.Get(key)
	if err != nil || !before.Healthy {
		t.Fatalf("JVM failed to start: %+v %v", before, err)
	}
	if err := killProcessTree(host.processes[key.String()].cmd.Process); err != nil {
		t.Fatal(err)
	}
	until := time.NewTimer(17 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		after, err := host.Get(key)
		if err == nil && after.Healthy && after.InstanceID != before.InstanceID && after.PID != before.PID && after.Restarts >= 1 {
			result, err := host.CallJavaRPC0304(ctx, key, "health", nil)
			if err != nil || !strings.Contains(string(result), `"responsive":true`) {
				t.Fatalf("restarted JVM does not accept authenticated RPC: %s: %v", result, err)
			}
			return
		}
		select {
		case <-tick.C:
		case <-until.C:
			t.Fatalf("real JVM did not recover: before=%+v after=%+v error=%v", before, after, err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestJavaMissingRuntimeRetryAfterRepair0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	missing := filepath.Join(t.TempDir(), "java-repaired")
	host.cfg.JavaExecutable = missing
	if err := host.StartInstallation(ctx, install); err == nil {
		t.Fatal("unavailable JVM unexpectedly launched")
	}
	failed, err := host.Get(key)
	if err != nil || failed.State != "failed" || failed.LastError == "" {
		t.Fatalf("failed launch left stale starting slot: %+v %v", failed, err)
	}
	if len(host.tokens) != 0 {
		t.Fatal("failed JVM retained an active authentication token")
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("Java unavailable")
	}
	if err := os.WriteFile(missing, []byte("#!/bin/sh\nexec "+java+" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatalf("repaired JVM could not start: %v", err)
	}
	running, err := host.Get(key)
	if err != nil || !running.Healthy || running.InstanceID == failed.InstanceID {
		t.Fatalf("retry not running: %+v %v", running, err)
	}
	if err := host.Stop(ctx, key); err != nil {
		t.Fatal(err)
	}
}

func TestJavaReconcileRunningAndDisable0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	ctx, cancel := context.WithTimeout(context.Background(), 17*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	original, err := host.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if errs := host.Reconcile(ctx); len(errs) != 0 {
			t.Fatalf("idempotent reconcile %d failed: %v", i, errs)
		}
		current, _ := host.Get(key)
		if current.InstanceID != original.InstanceID || current.PID != original.PID {
			t.Fatalf("reconcile relaunched healthy JVM: %+v", current)
		}
	}
	_, err = host.repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: key.ExtensionID, Scope: key.Scope, ScopeID: key.ScopeID,
		DesiredVersion: install.CurrentVersion, CurrentVersion: install.CurrentVersion,
		DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled,
		PackageIdentity: install.PackageIdentity, CurrentPackageIdentity: install.CurrentPackageIdentity,
		Enabled: false, Source: "java-recovery-test", Operation: "disable", ExpectedGeneration: install.Generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if errs := host.Reconcile(ctx); len(errs) != 0 {
		t.Fatalf("disable reconcile failed: %v", errs)
	}
	stopped, err := host.Get(key)
	if err != nil || stopped.State != "stopped" {
		t.Fatalf("disabled extension still running: %+v %v", stopped, err)
	}
}

func TestJavaStopCancelsScheduledRestart0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	before, _ := host.Get(key)
	if err := killProcessTree(host.processes[key.String()].cmd.Process); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := host.Get(key)
		if st.State == "crashed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := host.Stop(ctx, key); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // greater than the one-second retry backoff
	after, _ := host.Get(key)
	if after.InstanceID != before.InstanceID || after.State == "running" {
		t.Fatalf("operator Stop did not cancel restart: %+v", after)
	}
}

// A missing Java executable after a crash must not permanently strand an
// enabled extension. The supervisor retries failed OS launches and eventually
// starts the actual JAR when the Java executable becomes available again.
func TestJavaAutoRecoveryAfterRuntimeRestored0422(t *testing.T) {
	host, install, key := javaHostFixture0304(t)
	install = persistJavaInstall0422(t, host, install)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skip("Java runtime unavailable")
	}
	wrapper := filepath.Join(t.TempDir(), "java-runtime")
	writeWrapper := func() error { return os.WriteFile(wrapper, []byte("#!/bin/sh\nexec "+java+" \"$@\"\n"), 0700) }
	if err := writeWrapper(); err != nil {
		t.Fatal(err)
	}
	host.cfg.JavaExecutable = wrapper
	ctx, cancel := context.WithTimeout(context.Background(), 28*time.Second)
	defer cancel()
	if err := host.StartInstallation(ctx, install); err != nil {
		t.Fatal(err)
	}
	first, _ := host.Get(key)
	if err := os.Remove(wrapper); err != nil {
		t.Fatal(err)
	}
	if err := killProcessTree(host.processes[key.String()].cmd.Process); err != nil {
		t.Fatal(err)
	}
	failDeadline := time.NewTimer(10 * time.Second)
	defer failDeadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	failed := false
	for !failed {
		status, _ := host.Get(key)
		if status.State == "failed" && status.InstanceID != first.InstanceID {
			failed = true
			break
		}
		select {
		case <-ticker.C:
		case <-failDeadline.C:
			t.Fatalf("missing Java runtime did not reach failed state: %+v", status)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := writeWrapper(); err != nil {
		t.Fatal(err)
	}
	for {
		status, _ := host.Get(key)
		if status.Healthy && status.InstanceID != first.InstanceID && status.Restarts >= 2 {
			if _, err := host.CallJavaRPC0304(ctx, key, "health", nil); err != nil {
				t.Fatalf("recovered JVM RPC: %v", err)
			}
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("JVM did not recover after Java was restored: %+v: %v", status, ctx.Err())
		}
	}
}
