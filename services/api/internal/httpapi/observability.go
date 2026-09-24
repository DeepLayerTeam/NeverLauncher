package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/dbmigrate"
)

func (s Server) ready(w http.ResponseWriter, r *http.Request) {
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

func (s Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.Config.MetricsEnabled {
		writeError(w, http.StatusNotFound, "метрики отключены")
		return
	}
	projects := len(s.Repo.ListProjects())
	users := len(s.Repo.ListUsers())
	roles := len(s.Repo.ListRoles())
	auditEvents := len(s.Repo.ListAuditEvents())
	telemetryEvents := len(s.Repo.ListTelemetryEvents())
	crashReports := len(s.Repo.ListCrashReports())
	backups := 0
	if items, err := s.listOperationsBackups880(); err == nil {
		backups = len(items)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_info Информация о Backend API\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_info gauge\n")
	_, _ = fmt.Fprintf(w, "neverlauncher_info{version=%q,storage=%q,repository=%q} 1\n", s.Version, s.Storage.Driver(), s.Config.RepositoryDriver)
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_projects_total Количество проектов\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_projects_total gauge\nneverlauncher_projects_total %d\n", projects)
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_users_total Количество пользователей\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_users_total gauge\nneverlauncher_users_total %d\n", users)
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_roles_total Количество ролей\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_roles_total gauge\nneverlauncher_roles_total %d\n", roles)
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_audit_events_total Количество audit events\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_audit_events_total gauge\nneverlauncher_audit_events_total %d\n", auditEvents)
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_telemetry_events_total Количество telemetry events\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_telemetry_events_total gauge\nneverlauncher_telemetry_events_total %d\n", telemetryEvents)
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_crash_reports_total Количество crash reports\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_crash_reports_total gauge\nneverlauncher_crash_reports_total %d\n", crashReports)
	_, _ = fmt.Fprintf(w, "# HELP neverlauncher_backups_total Количество созданных backup archives\n")
	_, _ = fmt.Fprintf(w, "# TYPE neverlauncher_backups_total gauge\nneverlauncher_backups_total %d\n", backups)
	if s.State != nil && s.State.ServerBridge != nil && s.State.ServerBridge.backendV2() != nil {
		if ha, err := s.State.ServerBridge.haStatus0149(); err == nil {
			_, _ = fmt.Fprintf(w, "# HELP neverlauncher_serverbridge_nodes_active Active ServerBridge nodes\n# TYPE neverlauncher_serverbridge_nodes_active gauge\nneverlauncher_serverbridge_nodes_active %d\n", ha.NodesActive)
			_, _ = fmt.Fprintf(w, "# HELP neverlauncher_serverbridge_nodes_fresh Fresh ServerBridge nodes\n# TYPE neverlauncher_serverbridge_nodes_fresh gauge\nneverlauncher_serverbridge_nodes_fresh %d\n", ha.NodesFresh)
			_, _ = fmt.Fprintf(w, "# HELP neverlauncher_serverbridge_topology_fresh Fresh runtime-learned topology edges\n# TYPE neverlauncher_serverbridge_topology_fresh gauge\nneverlauncher_serverbridge_topology_fresh %d\n", ha.TopologyFresh)
			_, _ = fmt.Fprintf(w, "# HELP neverlauncher_serverbridge_handoffs_active Active one-time handoffs\n# TYPE neverlauncher_serverbridge_handoffs_active gauge\nneverlauncher_serverbridge_handoffs_active %d\n", ha.ActiveHandoffs)
			_, _ = fmt.Fprintf(w, "# HELP neverlauncher_serverbridge_expired_nonce_backlog Expired replay nonces waiting for HA maintenance\n# TYPE neverlauncher_serverbridge_expired_nonce_backlog gauge\nneverlauncher_serverbridge_expired_nonce_backlog %d\n", ha.ExpiredNonceBacklog)
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
