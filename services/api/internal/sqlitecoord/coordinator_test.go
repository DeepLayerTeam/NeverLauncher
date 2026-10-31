package sqlitecoord

import (
	"context"
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/serverbridgeha"
)

func coordTestPath(t *testing.T) string {
	t.Helper()
	root := os.Getenv("LAUNCHER_SQLITE_TEST_ROOT")
	if root == "" {
		root = t.TempDir()
	} else {
		var e error
		root, e = os.MkdirTemp(root, "coord-test-*")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = os.RemoveAll(root) })
	}
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	return filepath.Join(root, "coordinator.db")
}
func openTestCoordinator(t *testing.T, path string) *Coordinator {
	t.Helper()
	c, e := Open(context.Background(), path)
	if e != nil {
		// The product's SQLite store explicitly denies overlayfs and tmpfs. A
		// certified CI job sets the following flag and must never skip tests.
		if os.Getenv("LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS") != "1" && (errors.Is(e, os.ErrPermission) || isUnsupportedFS(e)) {
			t.Skipf("requires supported SQLite local FS: %v", e)
		}
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func isUnsupportedFS(e error) bool {
	return e != nil && strings.Contains(e.Error(), "unsupported SQLite filesystem")
}

func TestRateLimitAtomicAndRestart(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	const n = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, e := c.Allow(ctx, "auth|10.0.0.1", 7, time.Minute)
			if e != nil {
				t.Errorf("allow: %v", e)
				return
			}
			if result.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 7 {
		t.Fatalf("concurrent allowance %d, want 7", allowed)
	}
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	c2 := openTestCoordinator(t, path)
	res, e := c2.Allow(ctx, "auth|10.0.0.1", 7, time.Minute)
	if e != nil || res.Allowed || res.Remaining != 0 {
		t.Fatalf("rate limit reset after restart: %+v, %v", res, e)
	}
	res, e = c2.Allow(ctx, "auth|10.0.0.2", 7, time.Minute)
	if e != nil || !res.Allowed || res.Remaining != 6 {
		t.Fatalf("key isolation: %+v, %v", res, e)
	}
}
func TestLeaseFencingAndRestart(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	ok, e := c.AcquireCommandLease(ctx, "server", "command", "worker-a", "token-a", 5*time.Second)
	if e != nil || !ok {
		t.Fatalf("lease acquire: %t %v", ok, e)
	}
	ok, e = c.AcquireCommandLease(ctx, "server", "command", "worker-b", "token-b", 5*time.Second)
	if e != nil || ok {
		t.Fatalf("must not steal unexpired lease %t %v", ok, e)
	}
	valid, e := c.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if e != nil || !valid {
		t.Fatalf("lease disappeared %v", e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	c2 := openTestCoordinator(t, path)
	valid, e = c2.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if e != nil || !valid {
		t.Fatalf("lease lost over restart %v", e)
	}
	if e = c2.ReleaseCommandLease(ctx, "server", "command", "worker-b", "token-b"); e != nil {
		t.Fatal(e)
	}
	valid, _ = c2.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if !valid {
		t.Fatal("wrong owner released lease")
	}
	if e = c2.ReleaseCommandLease(ctx, "server", "command", "worker-a", "token-a"); e != nil {
		t.Fatal(e)
	}
	ok, e = c2.AcquireCommandLease(ctx, "server", "command", "worker-a", "token-a", 5*time.Second)
	if e != nil || ok {
		t.Fatalf("ABA replayed lease token %t %v", ok, e)
	}
	ok, e = c2.AcquireCommandLease(ctx, "server", "command", "worker-b", "token-b", 5*time.Second)
	if e != nil || !ok {
		t.Fatalf("fresh ownership %t %v", ok, e)
	}
	valid, _ = c2.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if valid {
		t.Fatal("stale token validates after fencing")
	}
}
func TestSingleOwnerAndChannel(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	if second, e := Open(ctx, path); e == nil {
		_ = second.Close()
		t.Fatal("second owner accepted")
	}
	p := serverbridgeha.ChannelPresence{ReplicaID: "api-1", ServerID: "server", RuntimeID: "runtime", ChannelID: "channel", ResumeAfter: 17, BackendAddress: "localhost:8080"}
	if e := c.TouchChannel(ctx, p, 10*time.Second); e != nil {
		t.Fatal(e)
	}
	p.ResumeAfter = 16
	if e := c.TouchChannel(ctx, p, 10*time.Second); e == nil {
		t.Fatal("stale cursor accepted")
	}
	old, found, e := c.Channel(ctx, p.ServerID, p.RuntimeID, p.ChannelID)
	if e != nil || !found || old.ResumeAfter != 17 {
		t.Fatalf("cursor rolled back %+v found=%v err=%v", old, found, e)
	}
}
func TestFailClosedParameters(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	if _, e := c.Allow(ctx, "a", 0, time.Minute); !errors.Is(e, ErrInvalid) {
		t.Fatalf("invalid limit: %v", e)
	}
	if _, e := c.AcquireCommandLease(ctx, "a", "b", "c", "", time.Second); !errors.Is(e, ErrInvalid) {
		t.Fatalf("empty token: %v", e)
	}
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Allow(ctx, "a", 2, time.Minute); e == nil {
		t.Fatal("fail-open after close")
	}
}

func TestLeaseExpiryFencingAndPrune(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	granted, e := c.AcquireCommandLease(ctx, "srv", "cmd", "one", "first", time.Minute)
	if e != nil || !granted {
		t.Fatalf("first acquisition: %v", e)
	}
	e = c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, "UPDATE coord_leases SET expires_at=1 WHERE server_id='srv' AND command_id='cmd'")
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	granted, e = c.AcquireCommandLease(ctx, "srv", "cmd", "two", "second", time.Minute)
	if e != nil || !granted {
		t.Fatalf("expired lease not reclaimed: %v", e)
	}
	valid, e := c.VerifyCommandLease(ctx, "srv", "cmd", "one", "first")
	if e != nil || valid {
		t.Fatalf("fenced old lease remains valid: %v", e)
	}
	var fence int64
	e = c.db.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, "SELECT fence FROM coord_leases WHERE server_id='srv' AND command_id='cmd'").Scan(&fence)
	})
	if e != nil || fence != 2 {
		t.Fatalf("fence high-water: %d %v", fence, e)
	}
	e = c.db.Write(ctx, func(q sqlitedurable.Executor) error {
		if _, e := q.ExecContext(ctx, "INSERT INTO coord_limits(key_hash,count,resets_at,last_updated) VALUES('expired',1,1,1)"); e != nil {
			return e
		}
		_, e := q.ExecContext(ctx, "INSERT INTO coord_channels(server_id,runtime_id,channel_id,replica_id,backend_address,resume_after,expires_at) VALUES('s','r','c','api','localhost',1,1)")
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	n, e := c.Prune(ctx)
	if e != nil || n != 2 {
		t.Fatalf("prune %d %v", n, e)
	}
	e = c.db.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, "SELECT fence FROM coord_leases WHERE server_id='srv' AND command_id='cmd'").Scan(&fence)
	})
	if e != nil || fence != 2 {
		t.Fatalf("prune erased tombstone/high-water mark: %v", e)
	}
}
