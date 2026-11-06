package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLog0459PreservesCorrelationAndStatus(t *testing.T) {
	var stream bytes.Buffer
	previous := accessLogger0459
	accessLogger0459 = slog.New(slog.NewJSONHandler(&stream, nil))
	defer func() { accessLogger0459 = previous }()
	handler := logRequests0459(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if correlationID02111(r) == "" {
			t.Error("missing correlation context")
		}
		w.WriteHeader(http.StatusConflict)
	}))
	req := httptest.NewRequest("POST", "/api/v1/secret/abc123?password=should-not-log", nil)
	req.Header.Set("X-Correlation-ID", "spoofed")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	id := result.Header().Get("X-Correlation-ID")
	if len(id) != 32 || id == "spoofed" {
		t.Fatalf("unexpected id %q", id)
	}
	var record map[string]any
	if err := json.Unmarshal(stream.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["status"] != float64(409) || record["correlation_id"] != id || record["route_group"] != "api" {
		t.Fatalf("Неожиданное содержимое журнала: %v", record)
	}
	if strings.Contains(stream.String(), "abc123") || strings.Contains(stream.String(), "should-not-log") || strings.Contains(stream.String(), "spoofed") {
		t.Fatal("log leaked untrusted data")
	}
}
func TestAccessLog0459NoMetricsNoise(t *testing.T) {
	var stream bytes.Buffer
	old := accessLogger0459
	accessLogger0459 = slog.New(slog.NewJSONHandler(&stream, nil))
	defer func() { accessLogger0459 = old }()
	h := logRequests0459(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/metrics", nil))
	if stream.Len() != 0 {
		t.Fatal("metrics generated log entry")
	}
}
