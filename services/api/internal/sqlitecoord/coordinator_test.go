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
		// Хранилище SQLite продукта явно запрещает overlayfs и tmpfs. Сертифицированное
		// задание CI устанавливает следующий флаг и должно пропускать тесты.
		if os.Getenv("LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS") != "1" && (errors.Is(e, os.ErrPermission) || isUnsupportedFS(e)) {
			t.Skipf("Требуется поддерживаемая локальная файловая система SQLite: %v", e)
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
				t.Errorf("Разрешение: %v", e)
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
		t.Fatalf("лимит параллельных запросов %d, ожидалось 7", allowed)
	}
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	c2 := openTestCoordinator(t, path)
	res, e := c2.Allow(ctx, "auth|10.0.0.1", 7, time.Minute)
	if e != nil || res.Allowed || res.Remaining != 0 {
		t.Fatalf("ограничение частоты сбросилось после перезапуска: %+v, %v", res, e)
	}
	res, e = c2.Allow(ctx, "auth|10.0.0.2", 7, time.Minute)
	if e != nil || !res.Allowed || res.Remaining != 6 {
		t.Fatalf("изоляция ключей: %+v, %v", res, e)
	}
}
func TestLeaseFencingAndRestart(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	ok, e := c.AcquireCommandLease(ctx, "server", "command", "worker-a", "token-a", 5*time.Second)
	if e != nil || !ok {
		t.Fatalf("захват аренды: %t %v", ok, e)
	}
	ok, e = c.AcquireCommandLease(ctx, "server", "command", "worker-b", "token-b", 5*time.Second)
	if e != nil || ok {
		t.Fatalf("нельзя захватывать ещё действующую аренду: %t %v", ok, e)
	}
	valid, e := c.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if e != nil || !valid {
		t.Fatalf("аренда исчезла: %v", e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
	c2 := openTestCoordinator(t, path)
	valid, e = c2.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if e != nil || !valid {
		t.Fatalf("аренда потеряна при перезапуске: %v", e)
	}
	if e = c2.ReleaseCommandLease(ctx, "server", "command", "worker-b", "token-b"); e != nil {
		t.Fatal(e)
	}
	valid, _ = c2.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if !valid {
		t.Fatal("аренду освободил посторонний владелец")
	}
	if e = c2.ReleaseCommandLease(ctx, "server", "command", "worker-a", "token-a"); e != nil {
		t.Fatal(e)
	}
	ok, e = c2.AcquireCommandLease(ctx, "server", "command", "worker-a", "token-a", 5*time.Second)
	if e != nil || ok {
		t.Fatalf("повторное использование токена аренды по схеме ABA: %t %v", ok, e)
	}
	ok, e = c2.AcquireCommandLease(ctx, "server", "command", "worker-b", "token-b", 5*time.Second)
	if e != nil || !ok {
		t.Fatalf("новое владение: %t %v", ok, e)
	}
	valid, _ = c2.VerifyCommandLease(ctx, "server", "command", "worker-a", "token-a")
	if valid {
		t.Fatal("устаревший токен проходит проверку после смены эпохи")
	}
}
func TestSingleOwnerAndChannel(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	if second, e := Open(ctx, path); e == nil {
		_ = second.Close()
		t.Fatal("Второй владелец ошибочно принят")
	}
	p := serverbridgeha.ChannelPresence{ReplicaID: "api-1", ServerID: "server", RuntimeID: "runtime", ChannelID: "channel", ResumeAfter: 17, BackendAddress: "localhost:8080"}
	if e := c.TouchChannel(ctx, p, 10*time.Second); e != nil {
		t.Fatal(e)
	}
	p.ResumeAfter = 16
	if e := c.TouchChannel(ctx, p, 10*time.Second); e == nil {
		t.Fatal("принят устаревший курсор")
	}
	old, found, e := c.Channel(ctx, p.ServerID, p.RuntimeID, p.ChannelID)
	if e != nil || !found || old.ResumeAfter != 17 {
		t.Fatalf("курсор откатился назад: %+v найден=%v ошибка=%v", old, found, e)
	}
}
func TestFailClosedParameters(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	if _, e := c.Allow(ctx, "a", 0, time.Minute); !errors.Is(e, ErrInvalid) {
		t.Fatalf("Недопустимое ограничение: %v", e)
	}
	if _, e := c.AcquireCommandLease(ctx, "a", "b", "c", "", time.Second); !errors.Is(e, ErrInvalid) {
		t.Fatalf("пустой токен: %v", e)
	}
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Allow(ctx, "a", 2, time.Minute); e == nil {
		t.Fatal("после закрытия система ошибочно разрешает доступ")
	}
}

func TestLeaseExpiryFencingAndPrune(t *testing.T) {
	path := coordTestPath(t)
	c := openTestCoordinator(t, path)
	ctx := context.Background()
	granted, e := c.AcquireCommandLease(ctx, "srv", "cmd", "one", "first", time.Minute)
	if e != nil || !granted {
		t.Fatalf("первый захват аренды: %v", e)
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
		t.Fatalf("истёкшая аренда не освобождена: %v", e)
	}
	valid, e := c.VerifyCommandLease(ctx, "srv", "cmd", "one", "first")
	if e != nil || valid {
		t.Fatalf("устаревшая аренда остаётся действительной после смены эпохи: %v", e)
	}
	var fence int64
	e = c.db.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, "SELECT fence FROM coord_leases WHERE server_id='srv' AND command_id='cmd'").Scan(&fence)
	})
	if e != nil || fence != 2 {
		t.Fatalf("максимальная эпоха защиты: %d %v", fence, e)
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
		t.Fatalf("Очистка %d: %v", n, e)
	}
	e = c.db.Read(ctx, func(q sqlitedurable.Executor) error {
		return q.QueryRowContext(ctx, "SELECT fence FROM coord_leases WHERE server_id='srv' AND command_id='cmd'").Scan(&fence)
	})
	if e != nil || fence != 2 {
		t.Fatalf("очистка удалила отметку об удалении или максимальную эпоху: %v", e)
	}
}
