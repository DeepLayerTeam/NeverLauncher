package sqlitedurable

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	base := os.Getenv("LAUNCHER_SQLITE_TEST_ROOT")
	if base == "" {
		base = t.TempDir()
	} else {
		var err error
		base, err = os.MkdirTemp(base, "dep00-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(base) })
	}
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	opt := Options{Path: filepath.Join(base, "sqlite.db")}
	if err := verifyLocalPath(opt.Path); err != nil {
		if os.Getenv("LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS") == "1" {
			t.Fatalf("SQLite FS certification failed: %v", err)
		}
		t.Skipf("SQLite integration requires verified ext4/xfs/btrfs mount: %v", err)
	}
	return opt
}

func TestCommittedAndRollback(t *testing.T) {
	opt := testOptions(t)
	ctx := context.Background()
	store, err := Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Write(ctx, func(q Executor) error {
		_, e := q.ExecContext(ctx, "CREATE TABLE t (id TEXT PRIMARY KEY, n INTEGER NOT NULL)")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Write(ctx, func(q Executor) error {
		_, e := q.ExecContext(ctx, "INSERT INTO t (id,n) VALUES ('persisted', 42)")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("abort")
	err = store.Write(ctx, func(q Executor) error {
		if _, e := q.ExecContext(ctx, "INSERT INTO t (id,n) VALUES ('rolled_back', 99)"); e != nil {
			return e
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected rollback error: %v", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	err = store.Read(ctx, func(q Executor) error {
		var n int
		if e := q.QueryRowContext(ctx, "SELECT n FROM t WHERE id='persisted'").Scan(&n); e != nil {
			return e
		}
		if n != 42 {
			return fmt.Errorf("committed data lost: %d", n)
		}
		var count int
		if e := q.QueryRowContext(ctx, "SELECT count(*) FROM t WHERE id='rolled_back'").Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return errors.New("rollback data survived")
		}
		if _, e := q.ExecContext(ctx, "DELETE FROM t"); e == nil {
			return errors.New("reader has write access")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := store.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Busy != 0 {
		t.Fatalf("checkpoint busy: %+v", status)
	}
}

func TestConcurrentWritersAreSerialized(t *testing.T) {
	opt := testOptions(t)
	ctx := context.Background()
	s, err := Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Write(ctx, func(q Executor) error {
		if _, e := q.ExecContext(ctx, "CREATE TABLE counter(n INTEGER NOT NULL)"); e != nil {
			return e
		}
		_, e := q.ExecContext(ctx, "INSERT INTO counter VALUES(0)")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 60)
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Write(ctx, func(q Executor) error { _, e := q.ExecContext(ctx, "UPDATE counter SET n=n+1"); return e })
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	err = s.Read(ctx, func(q Executor) error {
		var n int
		if e := q.QueryRowContext(ctx, "SELECT n FROM counter").Scan(&n); e != nil {
			return e
		}
		if n != 60 {
			return fmt.Errorf("lost update, n=%d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveOwner(t *testing.T) {
	opt := testOptions(t)
	ctx := context.Background()
	s, err := Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	// Child tries exactly the same store, not only raw file locks.
	child := exec.Command(os.Args[0], "-test.run=^TestOwnerChild$")
	child.Env = append(os.Environ(), "SQLITE_CHILD_PATH="+opt.Path, "SQLITE_CHILD_MODE=expect-deny")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("second owner accepted or helper failed: %v\n%s", e, out)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	child = exec.Command(os.Args[0], "-test.run=^TestOwnerChild$")
	child.Env = append(os.Environ(), "SQLITE_CHILD_PATH="+opt.Path, "SQLITE_CHILD_MODE=expect-allow")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("owner lock not released: %v\n%s", e, out)
	}
}

func TestOwnerChild(t *testing.T) {
	path := os.Getenv("SQLITE_CHILD_PATH")
	if path == "" {
		return
	}
	s, err := Open(context.Background(), Options{Path: path})
	switch os.Getenv("SQLITE_CHILD_MODE") {
	case "expect-deny":
		if err == nil {
			_ = s.Close()
			t.Fatal("second writer acquired exclusive store")
		}
		if !strings.Contains(err.Error(), "owned by another") {
			t.Fatalf("unexpected cause: %v", err)
		}
	case "expect-allow":
		if err != nil {
			t.Fatalf("reopening after owner exit: %v", err)
		}
		_ = s.Close()
	case "crash":
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if e := s.Write(ctx, func(q Executor) error {
			_, e := q.ExecContext(ctx, "INSERT INTO crash_test VALUES('uncommitted')")
			return e
		}); e != nil {
			t.Fatal(e)
		}
		// The crash scenario below uses BEGIN IMMEDIATE without committing.
		// Avoid Store.Write: it correctly rolls back on callback error/panic.
		c, e := s.writer.Conn(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
			t.Fatal(e)
		}
		if _, e = c.ExecContext(ctx, "INSERT INTO crash_test VALUES('during_crash')"); e != nil {
			t.Fatal(e)
		}
		os.Exit(77)
	}
}

func TestAbruptExitRecovery(t *testing.T) {
	opt := testOptions(t)
	ctx := context.Background()
	s, err := Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Write(ctx, func(q Executor) error {
		_, e := q.ExecContext(ctx, "CREATE TABLE crash_test(id TEXT PRIMARY KEY)")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestOwnerChild$")
	child.Env = append(os.Environ(), "SQLITE_CHILD_PATH="+opt.Path, "SQLITE_CHILD_MODE=crash")
	if err = child.Run(); err == nil {
		t.Fatal("child must die before COMMIT")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 77 {
		t.Fatalf("unexpected exit code: %v", err)
	}
	s, err = Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Read(ctx, func(q Executor) error {
		var n int
		if e := q.QueryRowContext(ctx, "SELECT count(*) FROM crash_test WHERE id='uncommitted'").Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return fmt.Errorf("prior committed write lost: %d", n)
		}
		if e := q.QueryRowContext(ctx, "SELECT count(*) FROM crash_test WHERE id='during_crash'").Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return errors.New("crash-before-commit became durable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledTxnRollback(t *testing.T) {
	opt := testOptions(t)
	ctx := context.Background()
	s, err := Open(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Write(ctx, func(q Executor) error { _, e := q.ExecContext(ctx, "CREATE TABLE abandoned(x INT)"); return e }); err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithCancel(ctx)
	err = s.Write(c, func(q Executor) error {
		if _, e := q.ExecContext(c, "INSERT INTO abandoned VALUES(10)"); e != nil {
			return e
		}
		cancel()
		return c.Err()
	})
	if err == nil {
		t.Fatal("canceled transaction returned success")
	}
	// database/sql may discard a canceled connection rather than reuse it.
	checkCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	if err = s.Read(checkCtx, func(q Executor) error {
		var n int
		if e := q.QueryRowContext(checkCtx, "SELECT count(*) FROM abandoned").Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return fmt.Errorf("canceled write committed: %d", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectMemoryURIsAndBadPermissions(t *testing.T) {
	for _, path := range []string{":memory:", "file:/tmp/s.db", "file::memory:", "", "state.db?cache=shared"} {
		if s, e := Open(context.Background(), Options{Path: path}); e == nil {
			_ = s.Close()
			t.Fatalf("accepted path %q", path)
		}
	}
	root := t.TempDir()
	_ = os.Chmod(root, 0777)
	if e := verifyLocalPath(filepath.Join(root, "data.db")); e == nil {
		t.Fatal("unsafe directory permission accepted")
	}
	_ = os.Chmod(root, 0700)
	if err := os.Symlink("/tmp", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if e := verifyLocalPath(filepath.Join(root, "link", "data.db")); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestVersionAndProbe(t *testing.T) {
	opt := testOptions(t)
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	if _, err := ProbeDurability(ctx, opt); err != nil {
		t.Fatal(err)
	}
}

func TestLockPrimitive(t *testing.T) {
	base := t.TempDir()
	name := filepath.Join(base, "guard.lock")
	first, err := exclusiveLock(name)
	if err != nil {
		t.Fatal(err)
	}
	second, err := exclusiveLock(name)
	if err == nil {
		_ = second.Close()
		t.Fatal("flock allowed a second independent owner")
	}
	if err = releaseLock(first); err != nil {
		t.Fatal(err)
	}
	third, err := exclusiveLock(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = releaseLock(third); err != nil {
		t.Fatal(err)
	}
}

func TestRejectTmpfs(t *testing.T) {
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Skip("no tmpfs mount")
	}
	root, err := os.MkdirTemp("/dev/shm", "sqlite-negative-*")
	if err != nil {
		t.Skipf("cannot create tmpfs test directory: %v", err)
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err = verifyLocalPath(filepath.Join(root, "state.db")); err == nil {
		t.Fatal("tmpfs accepted for durable SQLite")
	}
}
