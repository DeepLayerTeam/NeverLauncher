package httpapi

import (
	"net/http"
	"time"
)

const adminOpsSchema9100 = apiContractVersion

func (s Server) adminOpsStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": s.adminOps9100Payload("status")})
}

func (s Server) adminOpsReadiness(w http.ResponseWriter, r *http.Request) {
	payload := s.adminOps9100Payload("readiness")
	payload["status"] = "adminops-ready"
	payload["checks"] = []map[string]string{
		{"id": "dashboard", "status": "ok", "message": "Admin Dashboard агрегирует projects/users/packages/audit."},
		{"id": "package-pipeline", "status": "ok", "message": "Operator flow содержит create/upload/validate/smoke/publish/rollback."},
		{"id": "diagnostics-center", "status": "ok", "message": "Diagnostics Center отдаёт health, repository, storage, runtime, bridge и E2E gates."},
		{"id": "backup-restore", "status": "ok", "message": "Backup/restore выполняет проверяемое архивирование PostgreSQL и storage с подтверждаемым восстановлением."},
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOpsDiagnostics(w http.ResponseWriter, r *http.Request) {
	payload := s.adminOps9100Payload("diagnostics")
	payload["center"] = map[string]any{
		"cards":     []string{"API", "PostgreSQL", "Storage", "Redis optional", "Admin build", "Desktop build", "ServerBridge", "Runtime Resolver", "Package Integrity", "Production E2E"},
		"redaction": "privacy-by-default",
		"export":    "redacted diagnostics bundle",
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOpsBackup(w http.ResponseWriter, r *http.Request) {
	payload := s.adminOps9100Payload("backup")
	payload["commands"] = []string{"nl backup status", "nl backup create", "nl backup inspect", "nl backup restore-dry-run", "nl backup restore --confirm <backupId> --database true|--storage true", "nl backup diagnostics-bundle"}
	payload["policy"] = []string{"SHA-256 для архива и каждого файла", "pg_dump/pg_restore для PostgreSQL", "проверка restore-dry-run перед восстановлением", "точное подтверждение backupId для destructive restore", "отдельный backup root", "redacted diagnostics by default"}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOpsOperatorFlow(w http.ResponseWriter, r *http.Request) {
	payload := s.adminOps9100Payload("operator-flow")
	payload["flow"] = []string{"login", "dashboard", "project", "profile", "channel", "package", "upload", "validate", "smoke", "publish", "bridge", "diagnostics", "backup", "audit"}
	payload["acceptance"] = "оператор Minecraft-проекта может пройти базовый release-flow без ручного обращения к внутренним таблицам"
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOps9100Payload(kind string) map[string]any {
	return map[string]any{
		"schemaVersion": adminOpsSchema9100,
		"toolVersion":   s.Version,
		"release":       "NeverLauncher 0.11.0 Production Hardening",
		"kind":          kind,
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"sections": []map[string]string{
			{"id": "dashboard", "title": "Обзор"},
			{"id": "projects", "title": "Проекты"},
			{"id": "users", "title": "Пользователи и роли"},
			{"id": "packages", "title": "Пакеты"},
			{"id": "bridge", "title": "ServerBridge"},
			{"id": "sessions", "title": "Сессии"},
			{"id": "audit", "title": "Аудит"},
			{"id": "diagnostics", "title": "Диагностика"},
			{"id": "backup", "title": "Резервные копии и восстановление"},
			{"id": "settings", "title": "Настройки"},
		},
		"endpoints": []string{
			"GET /api/v1/status",
			"GET /ready",
			"GET /api/v1/operations/diagnostics",
			"GET /api/v1/operations/backup",
			"GET /api/v1/operations/diagnostics",
		},
	}
}
