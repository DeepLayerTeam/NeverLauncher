package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Result describes one rate-limit decision.
type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	ResetAfter time.Duration
}

// Limiter is a process-safe or distributed fixed-window limiter.
type Limiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error)
	Health(ctx context.Context) error
	Backend() string
}

type memoryBucket struct {
	count int
	reset time.Time
}

// MemoryLimiter is used for development/tests. Production should use Redis.
type MemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]memoryBucket
}

func NewMemory() *MemoryLimiter {
	return &MemoryLimiter{buckets: make(map[string]memoryBucket)}
}

func (m *MemoryLimiter) Backend() string              { return "memory" }
func (m *MemoryLimiter) Health(context.Context) error { return nil }

func (m *MemoryLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (Result, error) {
	if limit <= 0 || window <= 0 {
		return Result{Allowed: true, Limit: limit, Remaining: limit}, nil
	}
	now := time.Now()
	m.mu.Lock()
	bucket := m.buckets[key]
	if bucket.reset.IsZero() || !now.Before(bucket.reset) {
		bucket = memoryBucket{reset: now.Add(window)}
	}
	bucket.count++
	m.buckets[key] = bucket
	remaining := limit - bucket.count
	if remaining < 0 {
		remaining = 0
	}
	resetAfter := time.Until(bucket.reset)
	m.mu.Unlock()
	return Result{Allowed: bucket.count <= limit, Limit: limit, Remaining: remaining, ResetAfter: resetAfter}, nil
}
