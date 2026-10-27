package capacity

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPWindowRollingAndStatus(t *testing.T) {
	m := new(HTTPMetrics)
	now := time.Unix(1_000_000, 0)
	m.observe(now.Add(-60*time.Second), 500, 5*time.Second)
	for i := 0; i < 20; i++ {
		m.observe(now, 200, 25*time.Millisecond)
	}
	m.observe(now, 503, 2500*time.Millisecond)
	m.observe(now, 429, 120*time.Millisecond)
	got := m.Snapshot(now)
	if got.Requests != 22 || got.Failures != 1 || got.Throttled != 1 || got.P95Seconds != .25 {
		t.Fatalf("unexpected window: %+v", got)
	}
	if m.Snapshot(now.Add(61*time.Second)).Requests != 0 {
		t.Fatal("expired window included")
	}
}
func TestHTTPMiddleware(t *testing.T) {
	m := new(HTTPMetrics)
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503); _, _ = w.Write([]byte("failure")) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/a", nil))
	if rec.Code != 503 || m.Snapshot(time.Now()).Failures != 1 {
		t.Fatalf("status lost: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if m.Snapshot(time.Now()).Requests != 1 {
		t.Fatal("metrics scraped itself")
	}
	var out bytes.Buffer
	m.Prometheus(&out)
	if !strings.Contains(out.String(), "neverlauncher_http_5xx_60s 1") {
		t.Fatal(out.String())
	}
}
func TestOperationalThresholds(t *testing.T) {
	r := Report{Issues: []Issue{}}
	r.evaluatePostgres(PostgreSQL{ActiveConnections: 83, MaxConnections: 100, PendingJobs: 510, ExpiredJobLeases: 1, PendingOutbox: 700, OldestPendingJobSeconds: 120})
	if len(r.Issues) != 5 {
		t.Fatalf("expected five measurable warnings: %+v", r.Issues)
	}
	for _, i := range r.Issues {
		if i.Severity != "warning" || i.Recommendation == "" {
			t.Fatalf("bad recommendation %+v", i)
		}
	}
}
func TestProbeFailsClosedWhenDatabaseUnavailable(t *testing.T) {
	r := Probe(context.Background(), Options{Driver: "postgres"})
	if r.Verified || len(r.Errors) == 0 || r.PostgreSQL != nil {
		t.Fatalf("false green capacity probe: %+v", r)
	}
}
func TestCollectorStaleReport(t *testing.T) {
	c := NewCollector(Options{Mode: "standard"})
	if c.Latest().Verified {
		t.Fatal("uncollected capacity reported verified")
	}
	c.mu.Lock()
	c.last = Report{Verified: true, At: time.Now().Add(-120 * time.Second)}
	c.sampled = true
	c.mu.Unlock()
	if c.Latest().Verified {
		t.Fatal("stale capacity reported verified")
	}
}
func TestMeasureDiskFailsForMissingVolume(t *testing.T) {
	_, err := measureDisk("backup", "/some/missing/unlikely/capacity-check-03215")
	if err == nil {
		t.Fatal("missing volume accepted")
	}
}

type fakeDriver struct{}
type fakeConn struct{ fail bool }
type fakeRows struct {
	cols []string
	vals [][]driver.Value
	idx  int
}

func (fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{}, nil }
func (fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not implemented")
}
func (fakeConn) Close() error              { return nil }
func (fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions not implemented") }
func (fakeConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	var v []driver.Value
	switch {
	case strings.Contains(q, "max_connections"):
		v = []driver.Value{"100"}
	case strings.Contains(q, "pg_stat_activity"):
		v = []driver.Value{int64(89)}
	case strings.Contains(q, "pg_database_size"):
		v = []driver.Value{int64(123456)}
	case strings.Contains(q, "FROM durable_jobs"):
		v = []driver.Value{int64(900), int64(3), float64(120)}
	case strings.Contains(q, "SELECT (SELECT count(*) FROM projects)"):
		v = []driver.Value{int64(1), int64(2), int64(3), int64(4), int64(5), int64(6)}
	case strings.Contains(q, "FROM event_outbox"):
		v = []driver.Value{int64(510)}
	default:
		return nil, errors.New("unexpected query: " + q)
	}
	cols := make([]string, len(v))
	for i := range cols {
		cols[i] = "col"
	}
	return &fakeRows{cols: cols, vals: [][]driver.Value{v}}, nil
}
func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.idx == len(r.vals) {
		return io.EOF
	}
	copy(dest, r.vals[r.idx])
	r.idx++
	return nil
}
func TestPostgresReadingFromQueries(t *testing.T) {
	sql.Register("capacity_test_driver_03215", fakeDriver{})
	db, e := sql.Open("capacity_test_driver_03215", "")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	p, e := probePostgres(context.Background(), db)
	if e != nil {
		t.Fatal(e)
	}
	if p.ActiveConnections != 89 || p.MaxConnections != 100 || p.PendingJobs != 900 || p.ExpiredJobLeases != 3 || p.PendingOutbox != 510 || p.DatabaseBytes != 123456 || p.Users != 2 || p.CrashReports != 6 {
		t.Fatalf("bad actual query data: %+v", p)
	}
}
