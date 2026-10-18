package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperationList02110RejectsUnscopedAndInvalidRequests(t *testing.T) {
	h := testServer(t)
	token := loginAdmin(t, h)
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/api/v1/operations/jobs", http.StatusBadRequest},
		{"/api/v1/operations/jobs?projectId=demo-project&offset=-1", http.StatusBadRequest},
		{"/api/v1/operations/jobs?projectId=demo-project&status=injected", http.StatusBadRequest},
		{"/api/v1/operations/jobs?projectId=demo-project&limit=10", http.StatusOK},
	} {
		request := httptest.NewRequest(http.MethodGet, tc.path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, request)
		if recorder.Code != tc.status {
			t.Errorf("%s => %d, wanted %d: %s", tc.path, recorder.Code, tc.status, recorder.Body.String())
		}
		if tc.status == http.StatusOK && (!strings.Contains(recorder.Body.String(), `"items"`) || strings.Contains(recorder.Body.String(), `"leaseToken"`)) {
			t.Errorf("unsafe list response: %s", recorder.Body.String())
		}
	}
}
