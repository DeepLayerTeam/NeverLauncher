//go:build linux

package extensionbroker

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The shared filesystem broker operates on directory FDs. Concurrent renames,
// symlinks and hardlinks must never turn an approved relative path into an
// operation on a private inode outside its configured root.
func TestAdversarialBrokerPathBoundary03114(t *testing.T) {
	root := t.TempDir()
	private := t.TempDir()
	secret := filepath.Join(private, "backend-secret")
	if err := os.WriteFile(secret, []byte("immutable-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "allowed"), 0700); err != nil {
		t.Fatal(err)
	}
	payload := base64.StdEncoding.EncodeToString([]byte("attack"))
	for _, path := range []string{
		"../../backend-secret", "allowed/../../backend-secret", "allowed/../backend-secret",
		"allowed//backend-secret", "./backend-secret", "allowed/./x", "allowed/..",
		"\\..\\backend-secret", "/etc/shadow", "allowed/\x00shadow",
	} {

		if _, err := Read(root, path); err == nil {
			t.Errorf("read escaped: %q", path)
		}
		if err := Write(root, path, payload); err == nil {
			t.Errorf("write escaped: %q", path)
		}
	}
	if err := os.Symlink(private, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, "escape/backend-secret", payload); err == nil {
		t.Fatal("symlink parent escaped")
	}
	if _, err := Read(root, "escape/backend-secret"); err == nil {
		t.Fatal("symlink parent read private inode")
	}
	if err := os.Link(secret, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, "hardlink"); err == nil {
		t.Fatal("private hardlink disclosed")
	}
	if err := Write(root, "hardlink", payload); err != nil {
		t.Fatal(err)
	} // Replacement, not inode mutation.
	got, err := os.ReadFile(secret)
	if err != nil || !bytes.Equal(got, []byte("immutable-secret")) {
		t.Fatalf("outside inode changed: %q %v", got, err)
	}
}

func TestAdversarialBrokerAtomicConcurrentWriters03114(t *testing.T) {
	root := t.TempDir()
	const workers = 12
	a := bytes.Repeat([]byte("A"), 32<<10)
	b := bytes.Repeat([]byte("B"), 32<<10)
	if err := Write(root, "shared", base64.StdEncoding.EncodeToString(a)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, workers*25)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 25; n++ {
				if i%2 == 0 {
					if err := Write(root, "shared", base64.StdEncoding.EncodeToString(a)); err != nil {
						failures <- err
					}
				} else {
					if err := Write(root, "shared", base64.StdEncoding.EncodeToString(b)); err != nil {
						failures <- err
					}
				}
				raw, err := Read(root, "shared")
				if err != nil {
					// The file can be atomically replaced between openat and fstat;
					// treating a now-unlinked descriptor as denied is secure.
					if !errors.Is(err, ErrDenied) {
						failures <- err
					}
					continue
				}
				data, err := base64.StdEncoding.DecodeString(raw)
				if err != nil || !(bytes.Equal(data, a) || bytes.Equal(data, b)) {
					failures <- ErrDenied
				}
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("atomic broker failure: %v", err)
	}
}

func TestAdversarialBrokerSymlinkSwap03114(t *testing.T) {
	root := t.TempDir()
	private := t.TempDir()
	secret := filepath.Join(private, "backend-secret")
	if err := os.WriteFile(secret, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(root, "active")
	if err := os.Mkdir(live, 0700); err != nil {
		t.Fatal(err)
	}
	value := base64.StdEncoding.EncodeToString([]byte("attack"))
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			tmp := filepath.Join(root, "old")
			_ = os.Rename(live, tmp)
			_ = os.Symlink(private, live)
			_ = os.Remove(live)
			_ = os.Rename(tmp, live)
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		select {
		case <-done:
		default:
		}
		_ = Write(root, "active/backend-secret", value)
		_, _ = Read(root, "active/backend-secret")
	}
	wg.Wait()
	got, err := os.ReadFile(secret)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("root-swapping leaked outside inode: %q %v", got, err)
	}
}
