package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/dbmigrate"
)

func (s Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.State != nil && s.State.BackendLifecycle0289 != nil && s.State.BackendLifecycle0289.IsDraining() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining", "version": s.Version})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	checks := map[string]string{"storage": "ok", "repository": "not_applicable"}

	if err := s.Storage.Health(ctx); err != nil {
		checks["storage"] = err.Error()
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "message": err.Error()})
		return
	}

	if checker, ok := s.Repo.(interface{ Health(context.Context) error }); ok {
		if err := checker.Health(ctx); err != nil {
			checks["repository"] = err.Error()
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "message": err.Error()})
			return
		}
		checks["repository"] = "ok"
	}

	if s.State != nil && s.State.RateLimitEnabled && s.State.RateLimiter != nil {
		rlCtx, rlCancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		err := s.State.RateLimiter.Health(rlCtx)
		rlCancel()
		if err != nil {
			checks["rateLimiter"] = err.Error()
			if s.State.RateLimitFailClosed {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "message": "rate limiter unavailable"})
				return
			}
		} else {
			checks["rateLimiter"] = s.State.RateLimiter.Backend()
		}
	}

	if s.State != nil && s.State.ServerBridgeHARequired {
		if s.State.ServerBridgeCoordinator == nil {
			checks["serverBridgeCoordinator"] = "not configured"
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "message": "Координатор высокой доступности ServerBridge недоступен"})
			return
		}
		haCtx, haCancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		err := s.State.ServerBridgeCoordinator.Health(haCtx)
		haCancel()
		if err != nil {
			checks["serverBridgeCoordinator"] = err.Error()
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "message": "Координатор высокой доступности ServerBridge недоступен"})
			return
		}
		checks["serverBridgeCoordinator"] = s.State.ServerBridgeCoordinator.Backend()
	}

	if s.State != nil && s.State.ServerBridge != nil && s.State.ServerBridge.backendV2() != nil {
		ha, err := s.State.ServerBridge.haStatus0149()
		if err != nil {
			checks["serverBridgeHA"] = err.Error()
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "message": "serverbridge PostgreSQL HA status unavailable"})
			return
		}
		checks["serverBridgeHA"] = fmt.Sprintf("fresh_nodes=%d/%d fresh_topology=%d active_handoffs=%d nonce_backlog=%d", ha.NodesFresh, ha.NodesActive, ha.TopologyFresh, ha.ActiveHandoffs, ha.ExpiredNonceBacklog)
	}

	if s.Federation != nil {
		health := s.Federation.Health(ctx)
		healthy := 0
		for _, item := range health {
			if item.Healthy {
				healthy++
			}
		}
		checks["federation"] = fmt.Sprintf("%d/%d providers healthy", healthy, len(health))
		if len(health) == 0 || healthy == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "message": "no healthy authentication provider"})
			return
		}
	}

	if migrator, ok := s.Repo.(interface {
		MigrationStatus(context.Context) (dbmigrate.Status, error)
	}); ok {
		status, err := migrator.MigrationStatus(ctx)
		if err != nil || !status.Compatible || len(status.Pending) > 0 {
			message := "database schema is not current"
			if err != nil {
				message = err.Error()
			}
			checks["migrations"] = message
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks, "migrationCurrent": status.Current, "migrationPending": status.Pending, "message": message})
			return
		}
		checks["migrations"] = status.Current
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "version": s.Version, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver, "checks": checks})
}

var metricsStart0459 = time.Now()

func (s Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.Config.MetricsEnabled {
		writeError(w, http.StatusNotFound, "метрики отключены")
		return
	}
	// Сборщик ёмкости опрашивает SQL отдельно; сбор метрик никогда не должен
	// разветвляться в чтения полных таблиц через ORM на пути запроса.
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# HELP launcher_info Backend identity\n# TYPE launcher_info gauge\nlauncher_info{version=%q,storage=%q,repository=%q} 1\n", s.Version, s.Storage.Driver(), s.Config.RepositoryDriver)
	if s.Capacity != nil {
		s.Capacity.Prometheus(w)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	_, _ = fmt.Fprintf(w, "# HELP launcher_process_uptime_seconds Seconds since backend process started\n# TYPE launcher_process_uptime_seconds gauge\nlauncher_process_uptime_seconds %.3f\n", time.Since(metricsStart0459).Seconds())
	_, _ = fmt.Fprintf(w, "# HELP launcher_process_goroutines Goroutines in backend\n# TYPE launcher_process_goroutines gauge\nlauncher_process_goroutines %d\n", runtime.NumGoroutine())
	_, _ = fmt.Fprintf(w, "# HELP launcher_process_heap_alloc_bytes Allocated Go heap bytes\n# TYPE launcher_process_heap_alloc_bytes gauge\nlauncher_process_heap_alloc_bytes %d\n", memory.HeapAlloc)

	if s.State != nil && s.State.ServerBridge != nil && s.State.ServerBridge.backendV2() != nil {
		if ha, err := s.State.ServerBridge.haStatus0149(); err == nil {
			_, _ = fmt.Fprintf(w, "# HELP launcher_serverbridge_nodes_active Active ServerBridge nodes\n# TYPE launcher_serverbridge_nodes_active gauge\nlauncher_serverbridge_nodes_active %d\n", ha.NodesActive)
			_, _ = fmt.Fprintf(w, "# HELP launcher_serverbridge_nodes_fresh Fresh ServerBridge nodes\n# TYPE launcher_serverbridge_nodes_fresh gauge\nlauncher_serverbridge_nodes_fresh %d\n", ha.NodesFresh)
			_, _ = fmt.Fprintf(w, "# HELP launcher_serverbridge_topology_fresh Fresh runtime-learned topology edges\n# TYPE launcher_serverbridge_topology_fresh gauge\nlauncher_serverbridge_topology_fresh %d\n", ha.TopologyFresh)
			_, _ = fmt.Fprintf(w, "# HELP launcher_serverbridge_handoffs_active Active one-time handoffs\n# TYPE launcher_serverbridge_handoffs_active gauge\nlauncher_serverbridge_handoffs_active %d\n", ha.ActiveHandoffs)
			_, _ = fmt.Fprintf(w, "# HELP launcher_serverbridge_expired_nonce_backlog Expired replay nonces waiting for HA maintenance\n# TYPE launcher_serverbridge_expired_nonce_backlog gauge\nlauncher_serverbridge_expired_nonce_backlog %d\n", ha.ExpiredNonceBacklog)
		}
	}
}

func (s Server) adminObservability(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         s.Version,
		"environment":     s.Config.Environment,
		"repository":      s.Config.RepositoryDriver,
		"storage":         s.Storage.Driver(),
		"metricsEnabled":  s.Config.MetricsEnabled,
		"projects":        len(s.Repo.ListProjects()),
		"users":           len(s.Repo.ListUsers()),
		"roles":           len(s.Repo.ListRoles()),
		"auditEvents":     len(s.Repo.ListAuditEvents()),
		"telemetryEvents": len(s.Repo.ListTelemetryEvents()),
		"crashReports":    len(s.Repo.ListCrashReports()),
		"backups":         backupsCount880(s),
	})
}
