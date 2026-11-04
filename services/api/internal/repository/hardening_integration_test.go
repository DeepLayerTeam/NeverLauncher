package repository

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// Two independently opened pgx connections emulate separate API replicas/tabs.
// This is a real PostgreSQL test; it must not silently downgrade to memory.
func TestHardening02112PostgresConcurrentRevisionCAS(t *testing.T) {
	dsn := os.Getenv("LAUNCHER_SERVERBRIDGE_HA_DSN")
	if dsn == "" {
		t.Skip("requires LAUNCHER_SERVERBRIDGE_HA_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	open := func() *SQLRepository {
		t.Helper()
		r, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
		if !ok {
			t.Fatal("expected SQLRepository")
		}
		return r
	}
	a, b := open(), open()
	defer a.db.Close()
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	initial, err := a.GetOperationalConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	left, right := initial.Settings, initial.Settings
	left.AuditLookbackDays = 40
	right.AuditLookbackDays = 41
	type result struct {
		rev OperationalConfigRevision
		err error
	}
	barrier := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, v := range []struct {
		repo     *SQLRepository
		settings OperationalConfig
	}{{a, left}, {b, right}} {
		wg.Add(1)
		go func(repo *SQLRepository, settings OperationalConfig) {
			defer wg.Done()
			<-barrier
			rev, e := repo.SaveOperationalConfig(ctx, initial.Revision, settings, "e2e-admin", "concurrent tab CAS", nil)
			results <- result{rev, e}
		}(v.repo, v.settings)
	}
	close(barrier)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for item := range results {
		switch {
		case item.err == nil:
			success++
			if item.rev.Revision != initial.Revision+1 {
				t.Errorf("unexpected revision: %+v", item.rev)
			}
		case errors.Is(item.err, ErrConflict):
			conflict++
		default:
			t.Errorf("unexpected postgres save error: %v", item.err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("two replicas must yield one successful CAS: success=%d conflict=%d", success, conflict)
	}
	after, err := b.GetOperationalConfig(ctx)
	if err != nil || after.Revision != initial.Revision+1 {
		t.Fatalf("lost committed config revision: %+v %v", after, err)
	}
	if after.Settings.AuditLookbackDays != 40 && after.Settings.AuditLookbackDays != 41 {
		t.Fatalf("unexpected persisted settings: %+v", after.Settings)
	}
	// Restore uses a NEW revision and does not destroy the previous history.
	restored, err := a.SaveOperationalConfig(ctx, after.Revision, OperationalConfig{}, "e2e-admin", "restore after CAS", &initial.Revision)
	if err != nil || restored.Revision != after.Revision+1 || restored.Settings != initial.Settings {
		t.Fatalf("restore: %+v %v", restored, err)
	}
}
