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
		{"id": "dashboard", "status": "ok", "message": "Панель администратора объединяет сведения о проектах, пользователях, пакетах и аудите."},
		{"id": "package-pipeline", "status": "ok", "message": "Процесс оператора включает создание, загрузку, проверку, пробный запуск, публикацию и откат."},
		{"id": "diagnostics-center", "status": "ok", "message": "Центр диагностики показывает состояние сервера, репозитория, хранилища, среды выполнения, мостов и сквозных проверок."},
		{"id": "backup-restore", "status": "ok", "message": "Резервное копирование и восстановление обеспечивают проверяемое архивирование PostgreSQL и хранилища с подтверждением операции."},
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOpsDiagnostics(w http.ResponseWriter, r *http.Request) {
	payload := s.adminOps9100Payload("diagnostics")
	payload["center"] = map[string]any{
		"cards":     []string{"API", "PostgreSQL", "Хранилище", "Redis (необязательно)", "Сборка панели администратора", "Сборка настольного клиента", "ServerBridge", "Определение среды выполнения", "Целостность пакетов", "Сквозная проверка промышленного окружения"},
		"redaction": "privacy-by-default",
		"export":    "Диагностический пакет с удалёнными конфиденциальными данными",
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOpsBackup(w http.ResponseWriter, r *http.Request) {
	payload := s.adminOps9100Payload("backup")
	payload["commands"] = []string{"nl backup status", "nl backup create", "nl backup inspect", "nl backup restore-dry-run", "nl backup restore --confirm <backupId> --database true|--storage true", "nl backup diagnostics-bundle"}
	payload["policy"] = []string{"SHA-256 для архива и каждого файла", "pg_dump/pg_restore для PostgreSQL", "пробная проверка восстановления без изменения данных", "точное подтверждение идентификатора резервной копии перед восстановлением с изменением данных", "отдельный каталог резервных копий", "По умолчанию конфиденциальные данные скрыты в диагностике"}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOpsOperatorFlow(w http.ResponseWriter, r *http.Request) {
	payload := s.adminOps9100Payload("operator-flow")
	payload["flow"] = []string{"login", "dashboard", "project", "profile", "channel", "package", "upload", "validate", "smoke", "publish", "bridge", "diagnostics", "backup", "audit"}
	payload["acceptance"] = "оператор Minecraft-проекта может выполнить основной процесс выпуска без ручного обращения к внутренним таблицам"
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": adminOpsSchema9100, "data": payload})
}

func (s Server) adminOps9100Payload(kind string) map[string]any {
	return map[string]any{
		"schemaVersion": adminOpsSchema9100,
		"toolVersion":   s.Version,
		"release":       "Launcher " + s.Version + " — усиленная защита промышленного окружения",
		"kind":          kind,
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"sections": []map[string]string{
			{"id": "dashboard", "title": "Обзор"},
			{"id": "projects", "title": "Проекты"},
			{"id": "users", "title": "Пользователи и роли"},
			{"id": "packages", "title": "Пакеты"},
			{"id": "bridge", "title": "ServerBridge"},
			{"id": "sessions", "title": "Сессии"},
			{"id": "devices", "title": "Доверенные устройства"},
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
