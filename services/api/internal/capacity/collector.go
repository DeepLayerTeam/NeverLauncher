package capacity

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// Collector samples at bounded frequency; /metrics never executes SQL or a
// potentially blocking network probe in a request handler.
type Collector struct {
	Opt     Options
	HTTP    *HTTPMetrics
	mu      sync.RWMutex
	last    Report
	sampled bool
}

func NewCollector(opt Options) *Collector {
	c := &Collector{HTTP: &HTTPMetrics{}}
	opt.Traffic = c.HTTP
	c.Opt = opt
	return c
}
func (c *Collector) Sample(ctx context.Context) Report {
	report := Probe(ctx, c.Opt)
	c.mu.Lock()
	c.last = report
	c.sampled = true
	c.mu.Unlock()
	return report
}
func (c *Collector) Latest() Report {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.sampled {
		return Report{Mode: c.Opt.Mode, Verified: false, Errors: []string{"sampling not yet completed"}}
	}
	out := c.last
	out.Disks = append([]Disk(nil), out.Disks...)
	out.Issues = append([]Issue(nil), out.Issues...)
	out.Errors = append([]string(nil), out.Errors...)
	out.Limitations = append([]string(nil), out.Limitations...)
	if out.At.Add(90 * time.Second).Before(time.Now()) {
		out.Verified = false
		out.Errors = append(out.Errors, "capacity sample is stale (>90s)")
	}
	return out
}
func (c *Collector) Run(ctx context.Context) {
	sample := func() { each, cancel := context.WithTimeout(ctx, 8*time.Second); defer cancel(); c.Sample(each) }
	sample()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample()
		}
	}
}
func (c *Collector) Prometheus(w io.Writer) {
	c.HTTP.Prometheus(w)
	r := c.Latest()
	verified := 0
	if r.Verified {
		verified = 1
	}
	fmt.Fprintln(w, "# HELP launcher_capacity_sample_verified 1 if last operational probe succeeded and is fresh\n# TYPE launcher_capacity_sample_verified gauge")
	fmt.Fprintf(w, "launcher_capacity_sample_verified %d\n", verified)
	fmt.Fprintf(w, "# TYPE launcher_capacity_go_heap_bytes gauge\nlauncher_capacity_go_heap_bytes %d\n", r.GoHeapBytes)
	fmt.Fprintf(w, "# TYPE launcher_capacity_goroutines gauge\nlauncher_capacity_goroutines %d\n", r.Goroutines)
	if r.PostgreSQL != nil {
		// Backwards-compatible legacy inventory counters, now from the cached
		// SQL aggregate instead of materializing entire repository tables.
		fmt.Fprintf(w, "# TYPE launcher_projects_total gauge\nlauncher_projects_total %d\n", r.PostgreSQL.Projects)
		fmt.Fprintf(w, "# TYPE launcher_users_total gauge\nlauncher_users_total %d\n", r.PostgreSQL.Users)
		fmt.Fprintf(w, "# TYPE launcher_roles_total gauge\nlauncher_roles_total %d\n", r.PostgreSQL.Roles)
		fmt.Fprintf(w, "# TYPE launcher_audit_events_total gauge\nlauncher_audit_events_total %d\n", r.PostgreSQL.AuditEvents)
		fmt.Fprintf(w, "# TYPE launcher_telemetry_events_total gauge\nlauncher_telemetry_events_total %d\n", r.PostgreSQL.TelemetryEvents)
		fmt.Fprintf(w, "# TYPE launcher_crash_reports_total gauge\nlauncher_crash_reports_total %d\n", r.PostgreSQL.CrashReports)
		fmt.Fprintf(w, "# TYPE launcher_capacity_pg_connections gauge\nlauncher_capacity_pg_connections %d\n", r.PostgreSQL.ActiveConnections)
		fmt.Fprintf(w, "# TYPE launcher_capacity_pg_max_connections gauge\nlauncher_capacity_pg_max_connections %d\n", r.PostgreSQL.MaxConnections)
		fmt.Fprintf(w, "# TYPE launcher_capacity_pg_database_bytes gauge\nlauncher_capacity_pg_database_bytes %d\n", r.PostgreSQL.DatabaseBytes)
		fmt.Fprintf(w, "# TYPE launcher_capacity_jobs_pending gauge\nlauncher_capacity_jobs_pending %d\n", r.PostgreSQL.PendingJobs)
		fmt.Fprintf(w, "# TYPE launcher_capacity_jobs_expired_leases gauge\nlauncher_capacity_jobs_expired_leases %d\n", r.PostgreSQL.ExpiredJobLeases)
		fmt.Fprintf(w, "# TYPE launcher_capacity_outbox_pending gauge\nlauncher_capacity_outbox_pending %d\n", r.PostgreSQL.PendingOutbox)
	}
	for _, d := range r.Disks {
		// All names come from a closed set, never from request paths.
		fmt.Fprintf(w, "launcher_capacity_disk_available_bytes{volume=%q} %d\n", d.Name, d.AvailableBytes)
		fmt.Fprintf(w, "launcher_capacity_disk_available_ratio{volume=%q} %.6f\n", d.Name, d.AvailableFraction)
	}
	var warnings, critical int
	for _, i := range r.Issues {
		if i.Severity == "critical" {
			critical++
		} else if i.Severity == "warning" {
			warnings++
		}
	}
	fmt.Fprintf(w, "# TYPE launcher_capacity_warnings gauge\nlauncher_capacity_warnings %d\n", warnings)
	fmt.Fprintf(w, "# TYPE launcher_capacity_critical gauge\nlauncher_capacity_critical %d\n", critical)
}
