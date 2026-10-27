// Package capacity records bounded, low-cardinality live measurements and
// derives operational warnings from measured quantities. Guardrails are not
// benchmarked maximum throughput claims.
package capacity

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var bounds = [...]float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

type window struct {
	second                        int64
	requests, failures, throttled uint64
	buckets                       [len(bounds) + 1]uint64
	sum                           float64
}
type HTTPMetrics struct {
	mu      sync.Mutex
	windows [60]window
	active  int64
}
type Traffic struct {
	Requests          uint64                  `json:"requests"`
	Failures          uint64                  `json:"failures"`
	Throttled         uint64                  `json:"throttled"`
	InFlight          int64                   `json:"inFlight"`
	P95Seconds        float64                 `json:"p95Seconds"`
	AvgSeconds        float64                 `json:"avgSeconds"`
	RequestsPerSecond float64                 `json:"requestsPerSecond"`
	ErrorRatio        float64                 `json:"errorRatio"`
	ThrottleRatio     float64                 `json:"throttleRatio"`
	Buckets           [len(bounds) + 1]uint64 `json:"-"`
}

func (m *HTTPMetrics) observe(now time.Time, status int, elapsed time.Duration) {
	second := now.Unix()
	seconds := elapsed.Seconds()
	m.mu.Lock()
	defer m.mu.Unlock()
	b := &m.windows[second%int64(len(m.windows))]
	if b.second != second {
		*b = window{second: second}
	}
	b.requests++
	b.sum += seconds
	if status >= 500 {
		b.failures++
	}
	if status == 429 {
		b.throttled++
	}
	idx := len(bounds)
	for i, x := range bounds {
		if seconds <= x {
			idx = i
			break
		}
	}
	b.buckets[idx]++
}
func (m *HTTPMetrics) Snapshot(now time.Time) Traffic {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Traffic{InFlight: m.active}
	for _, b := range m.windows {
		if b.second > now.Unix() || now.Unix()-b.second >= 60 {
			continue
		}
		s.Requests += b.requests
		s.Failures += b.failures
		s.Throttled += b.throttled
		s.AvgSeconds += b.sum
		for i, n := range b.buckets {
			s.Buckets[i] += n
		}
	}
	if s.Requests > 0 {
		s.AvgSeconds /= float64(s.Requests)
		s.ErrorRatio = float64(s.Failures) / float64(s.Requests)
		s.ThrottleRatio = float64(s.Throttled) / float64(s.Requests)
		target := (s.Requests*95 + 99) / 100
		var cumulative uint64
		for i, v := range s.Buckets {
			cumulative += v
			if cumulative >= target {
				if i == len(bounds) {
					s.P95Seconds = bounds[len(bounds)-1]
				} else {
					s.P95Seconds = bounds[i]
				}
				break
			}
		}
	}
	s.RequestsPerSecond = float64(s.Requests) / 60
	return s
}
func (m *HTTPMetrics) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" || r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		m.mu.Lock()
		m.active++
		m.mu.Unlock()
		start := time.Now()
		rw := &responseStatus{ResponseWriter: w, status: 200}
		defer func() { m.mu.Lock(); m.active--; m.mu.Unlock(); m.observe(time.Now(), rw.status, time.Since(start)) }()
		next.ServeHTTP(rw, r)
	})
}

type responseStatus struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *responseStatus) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
		r.ResponseWriter.WriteHeader(code)
	}
}
func (r *responseStatus) Write(p []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(200)
	}
	return r.ResponseWriter.Write(p)
}
func (r *responseStatus) Unwrap() http.ResponseWriter { return r.ResponseWriter }
func (r *responseStatus) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (r *responseStatus) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Prometheus is a stable, aggregate-only metric set without URLs, users or IDs.
func (m *HTTPMetrics) Prometheus(w io.Writer) {
	s := m.Snapshot(time.Now())
	fmt.Fprintln(w, "# HELP neverlauncher_http_requests_60s Requests observed in the last 60 seconds\n# TYPE neverlauncher_http_requests_60s gauge")
	fmt.Fprintf(w, "neverlauncher_http_requests_60s %d\n", s.Requests)
	fmt.Fprintln(w, "# TYPE neverlauncher_http_5xx_60s gauge")
	fmt.Fprintf(w, "neverlauncher_http_5xx_60s %d\n", s.Failures)
	fmt.Fprintln(w, "# TYPE neverlauncher_http_429_60s gauge")
	fmt.Fprintf(w, "neverlauncher_http_429_60s %d\n", s.Throttled)
	fmt.Fprintln(w, "# TYPE neverlauncher_http_inflight gauge")
	fmt.Fprintf(w, "neverlauncher_http_inflight %d\n", s.InFlight)
	fmt.Fprintln(w, "# TYPE neverlauncher_http_latency_p95_seconds_60s gauge")
	fmt.Fprintf(w, "neverlauncher_http_latency_p95_seconds_60s %s\n", strconv.FormatFloat(s.P95Seconds, 'f', 3, 64))
}
