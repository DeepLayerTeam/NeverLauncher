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

// This test is deliberately opt-in. It requires a real Developer-ID-signed
// helper, both kernel App Sandbox and native macOS execution. Cross-compilation
// or a locally mocked codesign binary cannot satisfy it.
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
				// Fork can be denied at the kernel boundary and immediately exit.
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
	// It is unsafe to translate a multi-process resource policy to this
	// unprivileged platform: reject it rather than claiming enforcement.
	_, err := Prepare(Options{Policy: Policy{MaxProcesses: 2, MaxCPUPercent: 100, MaxMemoryBytes: 512 << 20, TimeoutSeconds: 5}, HostURL: "http://127.0.0.1:19090", HostHandler: http.NotFoundHandler()})
	if err == nil || !strings.Contains(err.Error(), "resource-policy") {
		t.Fatalf("multi-process mode must fail closed: %v", err)
	}
}

// Test the backend-liveness close path against an actual running helper.
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
	// Simulate abrupt backend death: the supervisor liveness writer disappears
	// without explicitly sending a process-group kill.
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
	// A subsequent independent signed helper is required for another launch;
	// the closed helper can never be revived by reopening the same IPC.
	_ = exec.ErrNotFound
}
