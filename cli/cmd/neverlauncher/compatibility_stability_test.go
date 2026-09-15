package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompatibilityGETRetriesTransientStatus(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	resp, err := compatibilityGET(context.Background(), server.Client(), server.URL, "NeverLauncher/test")
	if err != nil {
		t.Fatalf("compatibilityGET: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "ok" || calls.Load() != 3 {
		t.Fatalf("unexpected response/calls: %q / %d", data, calls.Load())
	}
}

func TestMaterializationLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireCompatibilityMaterializationLock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer first.Close()

	lockPath := filepath.Join(dir, ".neverlauncher", "materialize.lock")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file: %v", err)
	}

	// Do not wait for the production timeout in a unit test: prove O_EXCL semantics directly.
	if _, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
		t.Fatal("second materialization lock unexpectedly succeeded")
	}

	first.Close()
	second, err := acquireCompatibilityMaterializationLock(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	second.Close()
}

func TestSecureClientDestinationRejectsSymlinkComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows runners")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "libraries")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := secureClientDestination(root, "libraries/example.jar"); err == nil {
		t.Fatal("symlink component was accepted")
	}
}

func TestValidateAssetLogicalPath(t *testing.T) {
	for _, good := range []string{"minecraft/sounds/test.ogg", "icons/icon_16x16.png", "a"} {
		if err := validateAssetLogicalPath(good); err != nil {
			t.Fatalf("valid path %q rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"../escape", "a/../escape", "/absolute", "a//b", "a\\..\\b", ""} {
		if err := validateAssetLogicalPath(bad); err == nil {
			t.Fatalf("unsafe path %q accepted", bad)
		}
	}
}

func TestReplaceFileAtomicPortableReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "artifact.jar")
	tmp := filepath.Join(dir, "artifact.jar.nlpart")
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFileAtomicPortable(tmp, dst); err != nil {
		t.Fatalf("replace: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "new" {
		t.Fatalf("replacement mismatch: %q / %v", data, err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("temporary file still exists: %v", err)
	}
}

func TestClientPackageRejectsSymlinkArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows runners")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.jar")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "client.jar")); err != nil {
		t.Fatal(err)
	}
	if _, err := buildClientPackage(root, "p", "vanilla", "stable", "1", ""); err == nil {
		t.Fatal("client package accepted symlink artifact")
	}
}

func TestCompatibilityRetryDelayIsBounded(t *testing.T) {
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("Retry-After", "999")
	if got := compatibilityRetryDelay(response, 0); got != 10*time.Second {
		t.Fatalf("Retry-After bound: %v", got)
	}
}
