package sqlitecoord

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Production RC stress of the REAL WAL-backed rate limiter. It measures a
// specific bounded contention workload; no platform-wide RPS claim is made.
func TestProductionRCConcurrentRateLimitStress(t *testing.T) {
	path := coordTestPath(t)
	coordinator := openTestCoordinator(t, path)
	const workers, attempts, budget = 16, 12, 67
	var allowed atomic.Int64
	var denied atomic.Int64
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < attempts; j++ {
				result, err := coordinator.Allow(ctx, "rc-load-client", budget, time.Minute)
				if err != nil {
					t.Errorf("SQLite under concurrent load: %v", err)
					return
				}
				if result.Allowed {
					allowed.Add(1)
				} else {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != budget || denied.Load() != workers*attempts-budget {
		t.Fatalf("concurrency bypassed persisted rate limit: allowed=%d denied=%d",
			allowed.Load(), denied.Load())
	}
	if err := coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestCoordinator(t, path)
	result, err := reopened.Allow(ctx, "rc-load-client", budget, time.Minute)
	if err != nil || result.Allowed {
		t.Fatalf("restart bypassed exhausted budget: %+v %v", result, err)
	}
	t.Logf("observed sqlite-limiter test throughput=%.2f ops/s, measured on this runner only",
		float64(workers*attempts)/time.Since(start).Seconds())
}
