package httpapi

import (
	"net/http"
	"time"
)

func (s Server) registerOperationsRoutesV1(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/operations/diagnostics", s.requirePermission("diagnostics:read", s.adminOpsDiagnostics))
	mux.Handle("GET /api/v1/operations/backup", s.requirePermission("project:read", s.adminOpsBackup))
	mux.Handle("GET /api/v1/operations/audit/export", s.requirePermission("audit:read", s.operationsAuditExport))
	mux.Handle("GET /api/v1/operations/backup/status", s.requirePermission("project:read", s.operationsBackupStatus))
	mux.Handle("POST /api/v1/operations/backups", s.requirePermission("project:read", s.operationsBackupCreate))
	mux.Handle("GET /api/v1/operations/backups/{backupId}", s.requirePermission("project:read", s.operationsBackupGet))
	mux.Handle("POST /api/v1/operations/backups/{backupId}/restore-dry-run", s.requirePermission("project:read", s.operationsBackupRestoreDryRun))
	mux.Handle("POST /api/v1/operations/backups/{backupId}/restore", s.requireFreshAuth117("settings:manage", "phishing-resistant", 5*time.Minute, s.operationsBackupRestore))
	mux.Handle("GET /api/v1/operations/diagnostics-bundle", s.requirePermission("diagnostics:read", s.operationsDiagnosticsBundle))
	mux.Handle("GET /api/v1/operations/storage/audit", s.requirePermission("storage:manage", s.operationsStorageAudit))
	mux.Handle("GET /api/v1/operations/storage/consistency", s.requirePermission("storage:manage", s.operationsStorageConsistency))
	mux.Handle("GET /api/v1/operations/migrations/status", s.requirePermission("settings:manage", s.operationsMigrationsStatus))
	mux.Handle("POST /api/v1/operations/migrations/apply", s.requireFreshAuth117("settings:manage", "mfa", 5*time.Minute, s.operationsMigrationsApply))
	mux.Handle("GET /api/v1/operations/compliance", s.requirePermission("audit:read", s.adminCompliance))
}
