package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIContractOnErrors04512(t *testing.T) {
	h := withAPIContract04512(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/projects", nil))
	if w.Code != 403 || w.Header().Get("X-Launcher-API-Contract") != "1.0.0" {
		t.Fatalf("В ответе с ошибкой отсутствует заголовок контракта: %v", w.Result().Header)
	}
}
