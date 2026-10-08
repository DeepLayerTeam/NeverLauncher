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

	// Делать не wait для рабочий тайм-аут в модульный тест: prove O_EXCL семантика напрямую.
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

func TestValidateRemoteURLRejectsCredentialsAndPrivateLiteral(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_ALLOW_PRIVATE_UPSTREAM", "")
	for _, raw := range []string{
		"https://user:secret@example.com/file.jar",
		"https://example.com/file.jar#fragment",
		"https://127.0.0.1/file.jar",
		"https://10.0.0.1/file.jar",
		"http://example.com/file.jar",
	} {
		if err := validateRemoteURL(raw); err == nil {
			t.Fatalf("unsafe upstream URL accepted: %s", raw)
		}
	}
	if err := validateRemoteURL("https://example.com/file.jar"); err != nil {
		t.Fatalf("public HTTPS URL rejected: %v", err)
	}
	if err := validateRemoteURL("http://127.0.0.1:8080/file.jar"); err != nil {
		t.Fatalf("loopback HTTP test upstream rejected: %v", err)
	}
	t.Setenv("NEVERLAUNCHER_ALLOW_PRIVATE_UPSTREAM", "1")
	if err := validateRemoteURL("https://10.0.0.1/file.jar"); err != nil {
		t.Fatalf("explicit private upstream opt-in rejected: %v", err)
	}
}

func TestReplaceDirectoryAtomicPortablePreservesNewTree(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "natives")
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "old.bin"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "new.bin"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceDirectoryAtomicPortable(staging, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "old.bin")); !os.IsNotExist(err) {
		t.Fatalf("old tree survived atomic publish: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dst, "new.bin")); err != nil || string(raw) != "new" {
		t.Fatalf("new tree not published: %q / %v", raw, err)
	}
}
