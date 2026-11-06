package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationModules0338(t *testing.T) {
	if err := migrationModuleEndpoint0338("http://example.org/api"); err == nil {
		t.Fatal("Разрешён небезопасный удалённый транспорт")
	}
	zipPath := filepath.Join(t.TempDir(), "source.zip")
	if err := os.WriteFile(zipPath, []byte("ZIPDATA"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("Отсутствует аутентификация")
		}
		switch r.URL.Path {
		case "/analyze":
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/zip" {
				t.Error("Загружены неверные данные")
			}
			b, _ := io.ReadAll(r.Body)
			if string(b) != "ZIPDATA" {
				t.Error("Источник не передавался потоково")
			}
		case "/status":
			if r.Method != "GET" || r.URL.Query().Get("wrapperPath") != "server/.env" {
				t.Error("Неверный запрос состояния")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":{"state":"online","serverId":"node1","reason":"signed_runtime_heartbeat_fresh"}}`))
			return
		case "/enroll":
			if r.Header.Get("X-Migration-Modules-Confirm") != "run1" || r.Header.Get("X-Migration-Fresh-Keys-Confirmed") != "true" {
				t.Error("Отсутствует подтверждение")
			}
		default:
			t.Error("Неизвестный запрос")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer srv.Close()
	if err := migrationModuleAnalyze0338(srv.URL+"/analyze", "secret", zipPath, filepath.Join(t.TempDir(), "out.json")); err != nil {
		t.Fatal(err)
	}
	if err := migrationModuleEnroll0338(srv.URL+"/enroll", "secret", "run1", "", "modules/wrapper.json", "node1", "Name", "paper", "profile1", "publickey", false); err == nil || !strings.Contains(err.Error(), "fresh") {
		t.Fatalf("Обход подтверждения регистрации: %v", err)
	}
	if err := migrationModuleEnroll0338(srv.URL+"/enroll", "secret", "run1", filepath.Join(t.TempDir(), "enroll.json"), "modules/wrapper.json", "node1", "Name", "paper", "profile1", "publickey", true); err != nil {
		t.Fatal(err)
	}
	if err := migrationBridgeStatus0446(srv.URL+"/status", "secret", "server/.env", filepath.Join(t.TempDir(), "status.json")); err != nil {
		t.Fatal(err)
	}
	if err := migrationBridgeStatus0446(srv.URL+"/status", "secret", "", ""); err == nil {
		t.Fatal("Принята пустая обёртка")
	}
}
