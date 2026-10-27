// neverlauncher-capacity-bench is an opt-in, bounded, read-only HTTP load probe.
// It measures only the SELECTED endpoint and is not a claim of global capacity.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type Result struct {
	Concurrency     int     `json:"concurrency"`
	DurationSeconds float64 `json:"durationSeconds"`
	Requests        int     `json:"requests"`
	Successful      int     `json:"successful"`
	Status429       int     `json:"status429"`
	Status5xx       int     `json:"status5xx"`
	UnexpectedHTTP  int     `json:"unexpectedHttp"`
	TransportErrors int     `json:"transportErrors"`
	RPS             float64 `json:"requestsPerSecond"`
	P95Milliseconds float64 `json:"p95Milliseconds"`
	P99Milliseconds float64 `json:"p99Milliseconds"`
	Passed          bool    `json:"passed"`
}
type Response struct {
	Endpoint          string   `json:"endpoint"`
	Warning           string   `json:"warning"`
	Results           []Result `json:"results"`
	HighestPassingRPS float64  `json:"highestPassingRps"`
}

func safeURL(s string, remote bool) (string, error) {
	u, e := url.Parse(s)
	if e != nil || u == nil || u.Host == "" || u.Fragment != "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("absolute http(s) URL without credentials/fragment required")
	}
	if u.RawQuery != "" {
		return "", errors.New("query parameters are forbidden (avoid replaying tokens)")
	}
	if u.Path == "" {
		u.Path = "/api/v1/status"
	}
	if u.Path != "/api/v1/status" && u.Path != "/ready" && u.Path != "/health" {
		return "", errors.New("only read-only allowlisted endpoints can be benchmarked")
	}
	if !remote {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("remote target requires --allow-remote")
		}
	}
	return u.String(), nil
}

// Fixed histogram avoids unbounded memory usage at high request rates.
var latencyBounds = [...]time.Duration{time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}

func bucketLatency(d time.Duration) int {
	for i, b := range latencyBounds {
		if d <= b {
			return i
		}
	}
	return len(latencyBounds)
}
func histogramQuantile(hist [len(latencyBounds) + 1]uint64, total int, percentage int) float64 {
	if total == 0 {
		return 0
	}
	target := (total*percentage + 99) / 100
	count := 0
	for i, v := range hist {
		count += int(v)
		if count >= target {
			if i == len(latencyBounds) {
				return float64(latencyBounds[len(latencyBounds)-1]) / float64(time.Millisecond)
			}
			return float64(latencyBounds[i]) / float64(time.Millisecond)
		}
	}
	return 0
}

func run(ctx context.Context, client *http.Client, endpoint string, concurrency int, duration time.Duration) Result {
	r := Result{Concurrency: concurrency}
	started := time.Now()
	scoped, stop := context.WithTimeout(ctx, duration)
	defer stop()
	type observation struct {
		status  int
		elapsed time.Duration
		err     bool
	}
	samples := make(chan observation, concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if scoped.Err() != nil {
					return
				}
				req, e := http.NewRequestWithContext(scoped, http.MethodGet, endpoint, nil)
				if e != nil {
					return
				}
				t := time.Now()
				resp, e := client.Do(req)
				if scoped.Err() != nil {
					return
				}
				obs := observation{err: e != nil}
				if e == nil {
					obs.status = resp.StatusCode
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
					_ = resp.Body.Close()
				}
				obs.elapsed = time.Since(t)
				select {
				case samples <- obs:
				case <-scoped.Done():
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(samples) }()
	var hist [len(latencyBounds) + 1]uint64
	for v := range samples {
		r.Requests++
		if v.err {
			r.TransportErrors++
		} else if v.status == 429 {
			r.Status429++
		} else if v.status >= 500 {
			r.Status5xx++
		} else if v.status >= 200 && v.status < 300 {
			r.Successful++
		} else {
			r.UnexpectedHTTP++
		}
		hist[bucketLatency(v.elapsed)]++
	}
	r.DurationSeconds = time.Since(started).Seconds()
	if r.DurationSeconds > 0 {
		r.RPS = float64(r.Requests) / r.DurationSeconds
	}
	r.P95Milliseconds = histogramQuantile(hist, r.Requests, 95)
	r.P99Milliseconds = histogramQuantile(hist, r.Requests, 99)
	// Operation-oriented SLO. Passed only after at least 10 observations.
	// A 401/403/302 or any other non-2xx must never count as healthy capacity.
	// A partial 2xx success rate is equally unacceptable for this read-only probe.
	r.Passed = r.Requests >= 10 && r.Successful == r.Requests && r.P95Milliseconds <= 1000
	return r
}
func main() {
	address := flag.String("url", "http://127.0.0.1:8080/api/v1/status", "read-only HTTP target")
	maxWorkers := flag.Int("max-workers", 16, "maximum parallel requests, 1..64")
	stepTime := flag.Duration("step", 8*time.Second, "measurement time per ramp step, 2..120s")
	remote := flag.Bool("allow-remote", false, "explicitly authorize load against remote server YOU OWN")
	confirm := flag.Bool("confirm", false, "explicitly approve generating HTTP load")
	flag.Parse()
	if !*confirm || *maxWorkers < 1 || *maxWorkers > 64 || *stepTime < 2*time.Second || *stepTime > 120*time.Second {
		fmt.Fprintln(os.Stderr, "--confirm required; --max-workers 1..64; --step 2s..120s")
		os.Exit(2)
	}
	target, e := safeURL(*address, *remote)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	tr := &http.Transport{MaxIdleConnsPerHost: *maxWorkers, MaxConnsPerHost: *maxWorkers, IdleConnTimeout: 5 * time.Second, DisableKeepAlives: false}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	out := Response{Endpoint: target, Warning: "Measurements are endpoint-specific, hardware-specific and time-specific. Not a certified whole-product throughput limit."}
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64} {
		if n > *maxWorkers {
			break
		}
		result := run(context.Background(), client, target, n, *stepTime)
		out.Results = append(out.Results, result)
		if result.Passed && result.RPS > out.HighestPassingRPS {
			out.HighestPassingRPS = result.RPS
		}
		if !result.Passed {
			break
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if len(out.Results) == 0 || !out.Results[len(out.Results)-1].Passed {
		os.Exit(2)
	}
}
