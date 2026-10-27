//go:build linux

package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func testPlan(t *testing.T) Plan {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	return Plan{Mode: Standard, SingleInstance: true, LockPath: filepath.Join(dir, "api.owner.lock")}
}

func TestExclusiveLockAndRelease(t *testing.T) {
	plan := testPlan(t)
	first, err := Acquire(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Acquire(plan); err == nil {
		t.Fatal("second handle must be rejected")
	}
	info, err := os.Stat(plan.LockPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("lock file %v err=%v", info, err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(plan)
	if err != nil {
		t.Fatalf("reacquire after clean shutdown: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLockInDifferentProcess(t *testing.T) {
	plan := testPlan(t)
	lock, err := Acquire(plan)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockChildProcess$")
	cmd.Env = append(os.Environ(), "NEVERLAUNCHER_DEPLOYMENT_LOCK_TEST_PATH="+plan.LockPath)
	data, childErr := cmd.CombinedOutput()
	if childErr != nil {
		t.Fatalf("child failed %v: %s", childErr, data)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(os.Args[0], "-test.run=^TestLockChildProcess$")
	cmd.Env = append(os.Environ(), "NEVERLAUNCHER_DEPLOYMENT_LOCK_TEST_PATH="+plan.LockPath, "NEVERLAUNCHER_DEPLOYMENT_LOCK_TEST_EXPECT_SUCCESS=1")
	data, childErr = cmd.CombinedOutput()
	if childErr != nil {
		t.Fatalf("child reacquisition failed %v: %s", childErr, data)
	}
}
func TestLockChildProcess(t *testing.T) {
	path := os.Getenv("NEVERLAUNCHER_DEPLOYMENT_LOCK_TEST_PATH")
	if path == "" {
		return
	}
	lock, err := Acquire(Plan{SingleInstance: true, LockPath: path})
	success := os.Getenv("NEVERLAUNCHER_DEPLOYMENT_LOCK_TEST_EXPECT_SUCCESS") == "1"
	if (err == nil) != success {
		t.Fatalf("got acquire err=%v, expected success=%v", err, success)
	}
	if err == nil {
		_ = lock.Close()
	}
}
func TestSymlinkAndUnsafePermissionsRejected(t *testing.T) {
	p := testPlan(t)
	if err := os.MkdirAll(filepath.Dir(p.LockPath), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.lock")
	if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p.LockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(p); err == nil {
		t.Fatal("symlink lock accepted")
	}
	if err := os.Remove(p.LockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.LockPath, nil, 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.LockPath, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(p); err == nil {
		t.Fatal("weak lock permissions accepted")
	}
	if err := os.Remove(p.LockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(p.LockPath), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(p); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("unsafe parent accepted: %v", err)
	}
}
func TestLockParentSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(Plan{SingleInstance: true, LockPath: filepath.Join(dir, "alias", "api.lock")}); err == nil {
		t.Fatal("symlinked parent accepted")
	}
}

func TestProductionLockRequiresVerifiedLocalFS(t *testing.T) {
	p := testPlan(t)
	p.requireLocalFS = true
	if err := os.MkdirAll(filepath.Dir(p.LockPath), 0700); err != nil {
		t.Fatal(err)
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(p.LockPath), &fs); err != nil {
		t.Fatal(err)
	}
	l, err := Acquire(p)
	switch fs.Type {
	case 0xef53, 0x58465342, 0x9123683e:
		if err != nil {
			t.Fatalf("supported local filesystem rejected: %v", err)
		}
		_ = l.Close()
	default:
		if err == nil {
			_ = l.Close()
			t.Fatalf("unsafe filesystem 0x%x accepted", fs.Type)
		}
	}
}
