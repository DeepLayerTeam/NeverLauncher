package httpapi

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
)

type diagnosticPolicyResponse struct {
	Enabled        bool     `json:"enabled"`
	Version        string   `json:"version"`
	PrivacyMode    string   `json:"privacyMode"`
	AllowedFields  []string `json:"allowedFields"`
	RedactedFields []string `json:"redactedFields"`
}

type diagnosticReportRequest struct {
	SchemaVersion   string            `json:"schemaVersion"`
	GeneratedAt     string            `json:"generatedAt"`
	LauncherVersion string            `json:"launcherVersion"`
	OS              string            `json:"os"`
	Arch            string            `json:"arch"`
	BackendURL      string            `json:"backendUrl"`
	Status          string            `json:"status"`
	Checks          map[string]string `json:"checks"`
}

func (s Server) diagnosticsPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, diagnosticPolicyResponse{
		Enabled:     true,
		Version:     s.Version,
		PrivacyMode: "privacy-by-default",
		AllowedFields: []string{
			"schemaVersion",
			"generatedAt",
			"launcherVersion",
			"os",
			"arch",
			"backendUrl",
			"profileId",
			"profileVersion",
			"status",
			"checks",
			"logs",
		},
		RedactedFields: []string{"token", "password", "secret", "authorization", "accessKey", "secretKey"},
	})
}

func (s Server) diagnosticsValidate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var report diagnosticReportRequest
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "не удалось прочитать диагностический отчёт")
		return
	}
	if strings.TrimSpace(report.SchemaVersion) == "" || strings.TrimSpace(report.GeneratedAt) == "" || strings.TrimSpace(report.LauncherVersion) == "" {
		writeError(w, http.StatusBadRequest, "диагностический отчёт не содержит обязательные поля")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "message": "диагностический отчёт валиден"})
}

func (s Server) adminSupportSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         s.Version,
		"environment":     s.Config.Environment,
		"repository":      s.Config.RepositoryDriver,
		"storage":         s.Storage.Driver(),
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"projects":        len(s.Repo.ListProjects()),
		"users":           len(s.Repo.ListUsers()),
		"auditEvents":     len(s.Repo.ListAuditEvents()),
		"telemetryEvents": len(s.Repo.ListTelemetryEvents()),
		"crashReports":    len(s.Repo.ListCrashReports()),
	})
}
