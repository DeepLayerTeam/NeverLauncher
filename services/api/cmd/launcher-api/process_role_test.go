package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRoles0455(t *testing.T) {
	cases := []struct {
		input, mode         string
		api, workers, valid bool
	}{
		{"", "standard", true, true, true},
		{"all", "network-ha", false, false, false},
		{"api", "network-ha", true, false, true},
		{"worker", "network-ha", false, true, true},
		{"migrate", "network-ha", false, false, true},
		{" WORKER ", "network-ha", false, true, true},
		{"wrong", "standard", false, false, false},
	}
	for _, c := range cases {
		role, err := parseProcessRole0455(c.input, c.mode)
		if (err == nil) != c.valid {
			t.Errorf("%q %q: ошибка=%v", c.input, c.mode, err)
			continue
		}
		if c.valid && (role.api != c.api || role.workers != c.workers) {
			t.Errorf("Некорректная роль: %+v", role)
		}
	}
}

func TestWorkerProbe0455(t *testing.T) {
	var last atomic.Int64
	h := workerProbeHandler0455(&last, nil)
	check := func(path string, expected int) {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != expected {
			t.Errorf("%s: статус %d != %d", path, rr.Code, expected)
		}
	}
	check("/ready", http.StatusServiceUnavailable)
	check("/health", http.StatusOK)
	check("/metrics", http.StatusOK)
	check("/api/v1/status", http.StatusNotFound)
	last.Store(time.Now().Add(-30 * time.Second).UnixNano())
	check("/ready", http.StatusServiceUnavailable)
	last.Store(time.Now().UnixNano())
	check("/ready", http.StatusOK)
	// Настоящая проверка готовности промышленного Backend также должна отказывать
	// при ошибках.
	unhealthy := workerProbeHandler0455(&last, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			http.Error(w, "Redis not ready", http.StatusServiceUnavailable)
		}
	}))
	rr := httptest.NewRecorder()
	unhealthy.ServeHTTP(rr, httptest.NewRequest("GET", "/ready", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("Рабочий процесс скрыл ошибку зависимости: %d", rr.Code)
	}
}
