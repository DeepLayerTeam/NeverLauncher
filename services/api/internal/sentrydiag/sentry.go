// Package sentrydiag provides optional, bounded Sentry error reporting.
// It deliberately never serializes HTTP requests, tokens, request bodies, or users.
package sentrydiag

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type destination struct {
	ingest string
	key    string
	dsn    string
}

func parseDSN(raw string) (destination, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return destination{}, errors.New("invalid Sentry DSN")
	}
	if u.User == nil || u.User.Username() == "" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return destination{}, errors.New("Sentry DSN lacks public key or host")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return destination{}, errors.New("Sentry DSN secret key is unsupported")
	}
	if u.Scheme != "https" { // HTTP accepted only on loopback, useful for local/self-hosted deployments.
		if u.Scheme != "http" || (u.Hostname() != "localhost" && net.ParseIP(u.Hostname()) == nil || (net.ParseIP(u.Hostname()) != nil && !net.ParseIP(u.Hostname()).IsLoopback())) {
			return destination{}, errors.New("Sentry DSN requires HTTPS")
		}
	}
	segments := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	project := segments[len(segments)-1]
	if len(project) == 0 || len(project) > 20 {
		return destination{}, errors.New("invalid Sentry project id")
	}
	for _, r := range project {
		if r < '0' || r > '9' {
			return destination{}, errors.New("invalid Sentry project id")
		}
	}
	base := "/" + strings.Join(segments[:len(segments)-1], "/")
	if len(segments) == 1 {
		base = ""
	}
	return destination{ingest: u.Scheme + "://" + u.Host + base + "/api/" + project + "/envelope/", key: u.User.Username(), dsn: raw}, nil
}

var (
	credentialPattern = regexp.MustCompile(`(?i)(bearer\s+|password\s*[:=]\s*|token\s*[:=]\s*|secret\s*[:=]\s*|api[_-]?key\s*[:=]\s*)[^\s,;]+`)
	emailPattern      = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	homePattern       = regexp.MustCompile(`(?i)(?:/home/|/Users/|C:\\Users\\)[^\\/\s]+`)
	ipPattern         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

func Redact(s string) string {
	if len(s) > 8192 {
		s = s[:8192]
	}
	s = credentialPattern.ReplaceAllString(s, "[REDACTED]")
	s = emailPattern.ReplaceAllString(s, "[EMAIL]")
	s = homePattern.ReplaceAllString(s, "[HOME]")
	s = ipPattern.ReplaceAllString(s, "[IP]")
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

type event struct {
	Category  string
	Component string
	Message   string
}
type Reporter struct {
	mu                   sync.RWMutex
	closed               bool
	dest                 destination
	release, environment string
	events               chan event
	client               *http.Client
	done                 chan struct{}
	stop                 chan struct{}
	once                 sync.Once
}

// New returns nil for an unset DSN. Invalid nonempty DSNs fail startup rather than silently disabling reporting.
func New(dsn, release, environment string) (*Reporter, error) {
	if dsn == "" {
		return nil, nil
	}
	d, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	r := &Reporter{dest: d, release: release, environment: environment, events: make(chan event, 64), done: make(chan struct{}), stop: make(chan struct{}), client: &http.Client{Timeout: 3 * time.Second}}
	go r.loop()
	return r, nil
}
func (r *Reporter) Capture(category, component, message string) {
	if r == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(category) || !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(component) {
		return
	}
	select {
	case r.events <- event{category, component, Redact(message)}:
	default:
	}
}

// loop flushes events accepted before shutdown, with a strict upper bound.
// The caller cannot wait indefinitely when the remote ingest is unavailable.
func (r *Reporter) loop() {
	defer close(r.done)
	for {
		select {
		case <-r.stop:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for ctx.Err() == nil {
				select {
				case e := <-r.events:
					_ = r.send(ctx, e)
				default:
					return
				}
			}
			return
		case e := <-r.events:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = r.send(ctx, e)
			cancel()
		}
	}
}

func (r *Reporter) send(ctx context.Context, e event) error {
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(idBytes[:])
	payload := map[string]any{"event_id": id, "timestamp": time.Now().UTC().Format(time.RFC3339Nano), "platform": "go", "level": "error", "release": r.release, "environment": r.environment, "logger": "launcher." + e.Component, "message": e.Category + ": " + e.Message, "sdk": map[string]any{"name": "launcher.go", "version": "0.30.9"}}
	head, _ := json.Marshal(map[string]any{"event_id": id, "dsn": r.dest.dsn, "sent_at": time.Now().UTC().Format(time.RFC3339)})
	item, _ := json.Marshal(map[string]any{"type": "event"})
	body, _ := json.Marshal(payload)
	data := bytes.NewBuffer(nil)
	data.Write(head)
	data.WriteByte('\n')
	data.Write(item)
	data.WriteByte('\n')
	data.Write(body)
	data.WriteByte('\n')
	// Retry only transient ingest failures. The event_id remains stable so
	// Sentry can deduplicate a request whose acknowledgement was lost.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", r.dest.ingest, bytes.NewReader(data.Bytes()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-sentry-envelope")
		req.Header.Set("X-Sentry-Auth", fmt.Sprintf("Sentry sentry_version=7,sentry_client=launcher.go/0.30.9,sentry_key=%s", r.dest.key))
		resp, err := r.client.Do(req)
		wait := 200 * time.Millisecond
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("Sentry ingest HTTP %d", resp.StatusCode)
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusGatewayTimeout {
				return lastErr
			}
			if seconds, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && seconds > 0 {
				wait = time.Duration(seconds) * time.Second
			}
		} else {
			lastErr = err
		}
		if attempt == 2 {
			break
		}
		if wait > time.Second {
			wait = time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

// Wrap captures HTTP panics and 5xx status codes without request metadata and re-panics
// so the standard net/http recovery behavior remains intact.
func (r *Reporter) Wrap(next http.Handler) http.Handler {
	if r == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				r.Capture("http.panic", "backend", "handler panic")
				panic(v)
			}
		}()
		tracking := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(tracking, req)
		if tracking.status >= 500 {
			r.Capture("http.5xx", "backend", fmt.Sprintf("status=%d", tracking.status))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(n int) {
	if w.status == 0 {
		w.status = n
	}
	w.ResponseWriter.WriteHeader(n)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(p)
}
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (r *Reporter) Close() {
	if r != nil {
		r.once.Do(func() {
			r.mu.Lock()
			r.closed = true
			close(r.stop)
			r.mu.Unlock()
			<-r.done
		})
	}
}

// EnabledFromEnvironment deliberately does not turn on reporting merely because a DSN exists.
func EnabledFromEnvironment() bool {
	return strings.EqualFold(os.Getenv("LAUNCHER_SENTRY_BACKEND_ENABLED"), "true")
}
