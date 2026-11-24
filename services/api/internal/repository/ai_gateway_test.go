package repository

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/aigateway"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

// Concurrent callers must not be admitted above the shared budget, even if all
// providers have yet to return. All reservations in this test cost 100 microUSD.
func exerciseAILedger121(t *testing.T, a, b *aigateway.Ledger, month string, started int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := aigateway.Config{GlobalBudget: 500, UserBudget: 300, UserRPM: 120}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var admitted []aigateway.Reservation
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := aigateway.Reservation{ID: fmt.Sprintf("%s-%d-%d", month, started, i), User: fmt.Sprintf("ai-user-%d", i%2), Month: month, Started: started, Amount: 100, Model: "test"}
			l := a
			if i%2 == 1 {
				l = b
			}
			err := l.Reserve(ctx, r, c)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				admitted = append(admitted, r)
			} else if !errors.Is(err, aigateway.ErrBudget) {
				t.Errorf("reservation: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if len(admitted) != 5 {
		t.Fatalf("admitted %d, want exactly 5", len(admitted))
	}
	u, err := b.Usage(ctx, month, "")
	if err != nil || u.Requests != 5 || u.ChargedMicroUSD != 500 || u.UncertainRequests != 5 {
		t.Fatalf("%+v %v", u, err)
	}
	personal, err := a.Usage(ctx, month, admitted[0].User)
	if err != nil || personal.Requests < 2 || personal.Requests > 3 || personal.ChargedMicroUSD != personal.Requests*100 {
		t.Fatalf("personal %+v %v", personal, err)
	}
	if err := b.Finish(ctx, admitted[0], "completed", 10, 5, 20); err != nil {
		t.Fatal(err)
	}
	if err := a.Finish(ctx, admitted[0], "completed", 0, 0, 0); err == nil {
		t.Fatal("double settlement accepted")
	}
	u, err = a.Usage(ctx, month, "")
	if err != nil || u.ChargedMicroUSD != 420 || u.UncertainRequests != 4 || u.InputTokens != 10 || u.OutputTokens != 5 {
		t.Fatalf("%+v %v", u, err)
	}
	c.UserRPM = 1
	r := aigateway.Reservation{ID: admitted[0].ID + "-rate", User: admitted[0].User, Month: month, Started: started + 1, Amount: 1, Model: "test"}
	if err := a.Reserve(ctx, r, c); !errors.Is(err, aigateway.ErrRate) {
		t.Fatalf("rate limit: %v", err)
	}
}
func TestAIGatewaySQLiteDurability121(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SQLite durable repository certified on Linux")
	}
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "ai-repository.db")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	l, err := r.AILedger(ctx)
	if err != nil {
		r.Close()
		t.Fatal(err)
	}
	now := time.Now().UTC()
	month := now.Format("2006-01")
	exerciseAILedger121(t, l, l, month, now.Unix())
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenSQLiteHTTPRepository0372(ctx, path, "https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	l, err = r.AILedger(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, err := l.Usage(ctx, month, "")
	if err != nil || u.ChargedMicroUSD != 420 || u.UncertainRequests != 4 {
		t.Fatalf("ledger lost after restart: %+v %v", u, err)
	}
}

// The ledger must survive restart, but a missing ledger object must fail closed.
func TestAIGatewaySQLiteRejectsPartialSchema(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SQLite durable repository certified on Linux")
	}
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "ai-partial.db")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.AILedger(ctx); err != nil {
		r.Close()
		t.Fatal(err)
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		_, e := q.ExecContext(ctx, "DROP INDEX ai_requests_month_user")
		return e
	})
	closeErr := r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if reopened, err := OpenSQLiteHTTPRepository0372(ctx, path, "https://example.test"); err == nil {
		reopened.Close()
		t.Fatal("incomplete AI ledger unexpectedly accepted")
	}
}
