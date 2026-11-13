package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOperationAttemptsAndBackupRoutesDoNotConflict(t *testing.T) {
	mux := http.NewServeMux()
	registerOperationAttemptsRoute(mux, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("operationId"); got != "job-123" {
			t.Errorf("operationId = %q", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	mux.HandleFunc("GET /api/v1/operations/backups/{backupId}", func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("backupId"); got != "attempts" {
			t.Errorf("backupId = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/api/v1/operations/job-123/attempts", http.StatusAccepted},
		{"/api/v1/operations/backups/attempts", http.StatusNoContent},
		{"/api/v1/operations/job-123/unknown", http.StatusNotFound},
	} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rr.Code != tc.status {
			t.Errorf("%s: got %d want %d", tc.path, rr.Code, tc.status)
		}
	}
}
