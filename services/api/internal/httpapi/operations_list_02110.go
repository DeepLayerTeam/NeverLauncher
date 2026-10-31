package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// List stored operations without exposing payloads, idempotency keys or worker leases.
// Project membership is required independently of ownership of individual jobs.
func (s Server) operationList02110(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("projectId"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "projectId is required")
		return
	}
	if !s.authorizeClaims(r, claims, "project:read", projectID, "project", projectID).Allowed {
		writeError(w, http.StatusForbidden, "project access denied")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	switch status {
	case "", "pending", "running", "succeeded", "failed", "revoked", "dead":
	default:
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}
	settings, settingsErr := s.operationalSettings02111(r)
	if settingsErr != nil {
		writeError(w, http.StatusServiceUnavailable, "настройки списка заданий недоступны")
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = settings.JobsDefaultPageSize
	}
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil {
		offset = 0
	}
	if limit < 1 {
		limit = settings.JobsDefaultPageSize
	}
	if limit > settings.JobsMaxPageSize {
		limit = settings.JobsMaxPageSize
	}
	if offset < 0 || offset > 10000 {
		writeError(w, http.StatusBadRequest, "offset out of range")
		return
	}
	lister, ok := s.Repo.(repository.OperationLister)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "operation list unavailable")
		return
	}
	jobs, err := lister.ListProjectOperations(r.Context(), projectID, status, limit+1, offset)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "список заданий временно недоступен")
		return
	}
	more := len(jobs) > limit
	if more {
		jobs = jobs[:limit]
	}
	items := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		items = append(items, publicOperation0217(j))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items, "limit": limit, "offset": offset, "hasMore": more}})
}
