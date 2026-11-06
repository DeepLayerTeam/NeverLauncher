package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func livePG0491() pgAudit0491 {
	var p pgAudit0491
	_ = json.Unmarshal([]byte(`{"readOnly":"on","project":"project-1","migration":{"id":"migration-1","project_id":"project-1","source_kind":"gravit","status":"prepared","step":"source_assessment","revision":7},"extension":{"extension_id":"example.java","scope":"project","scope_id":"project-1","current_version":"1.2.3","current_state":"enabled","generation":4,"enabled":true}}`), &p)
	return p
}
func TestIntegrationAudit0491StrictCrossStoreComparison(t *testing.T) {
	opts := liveIntegrationOptions0491{Project: "project-1", Run: "migration-1", Extension: "example.java", Scope: "project", ScopeID: "project-1"}
	run := migrationAuditRun0491{ID: opts.Run, ProjectID: opts.Project, SourceKind: "gravit", Status: "prepared", Step: "source_assessment", Revision: 7}
	host := hostAudit0491{ExtensionID: opts.Extension, Scope: opts.Scope, ScopeID: opts.ScopeID, Version: "1.2.3", Generation: 4, InstanceID: "real-process", Runtime: "java-jvm", State: "running", Healthy: true}
	if err := matchIntegrationSnapshot0491(opts, run, livePG0491(), host); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*pgAudit0491, *hostAudit0491){
		"disabled":             func(p *pgAudit0491, h *hostAudit0491) { p.Extension.Enabled = false },
		"wrong-JVM":            func(p *pgAudit0491, h *hostAudit0491) { h.InstanceID = "" },
		"stale-generation":     func(p *pgAudit0491, h *hostAudit0491) { h.Generation = 3 },
		"missing-PG-migration": func(p *pgAudit0491, h *hostAudit0491) { p.Migration = nil },
		"wrong-PG-project":     func(p *pgAudit0491, h *hostAudit0491) { p.Migration.ProjectID = "project-2" },
		"fake-JVM":             func(p *pgAudit0491, h *hostAudit0491) { h.Runtime = "native" },
	} {
		t.Run(name, func(t *testing.T) {
			p, h := livePG0491(), host
			mutate(&p, &h)
			if err := matchIntegrationSnapshot0491(opts, run, p, h); err == nil {
				t.Fatal("accepted inconsistent integration")
			}
		})
	}
	for _, bad := range []string{"", "a';DROP TABLE projects;--", "../../../etc/passwd"} {
		if auditIdentifier0491.MatchString(bad) {
			t.Fatalf("accepted dangerous identifier %q", bad)
		}
	}
	if validAuditScope0491("project", "project-2", "project-1") {
		t.Fatal("accepted cross-project extension")
	}
}

func TestIntegrationAudit0491LiveReadbackAndFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses POSIX executable script; production psql runs on Windows")
	}
	root := t.TempDir()
	psql := filepath.Join(root, "psql")
	// Это тестовые данные, а не свидетельство PostgreSQL. В рабочей среде всегда используется
	// установленная оператором утилита psql и действующее перенесённое хранилище SQLRepository.
	script := `#!/bin/sh
[ "$PGDATABASE" = "postgres://test-only" ] || exit 10
[ "$PGOPTIONS" = "-c default_transaction_read_only=on" ] || exit 11
text=$(cat)
printf '%s' "$text" | grep -q 'BEGIN READ ONLY' || exit 12
printf '%s' "$text" | grep -q 'extension_installs' || exit 13
printf '%s' "$text" | grep -q 'migration_runs_0331' || exit 14
printf '%s\n' '{"readOnly":"on","project":"project-1","migration":{"id":"migration-1","project_id":"project-1","source_kind":"gravit","status":"prepared","step":"source_assessment","revision":7},"extension":{"extension_id":"example.java","scope":"project","scope_id":"project-1","current_version":"1.2.3","current_state":"enabled","generation":4,"enabled":true}}'
`
	if err := os.WriteFile(psql, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	var mutate atomic.Bool
	var badHost atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" && r.Header.Get("Authorization") != "Bearer only-test-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case r.URL.Path == "/ready":
			w.Write([]byte(`{"status":"ready","version":"0.49.1","repository":"postgres","checks":{"repository":"ok","migrations":"0115"}}`))
		case r.URL.Path == "/api/v1/admin/migration-runs/migration-1":
			n := calls.Add(1)
			revision := 7
			if mutate.Load() && n >= 2 {
				revision = 8
			}
			w.Write([]byte(`{"data":{"id":"migration-1","projectId":"project-1","sourceKind":"gravit","status":"prepared","step":"source_assessment","revision":` + jsonNumber0491(revision) + `,"fence":12,"result":{},"createdAt":"2026-11-02T12:00:00Z"}}`))
		case strings.HasSuffix(r.URL.Path, "/probe"):
			if r.Method != "POST" {
				http.Error(w, "wrong method", 405)
				return
			}
			healthy := "true"
			if badHost.Load() {
				healthy = "false"
			}
			w.Write([]byte(`{"apiVersion":"1.0","data":{"host":{"extensionId":"example.java","scope":"project","scopeId":"project-1","version":"1.2.3","generation":4,"instanceId":"jvm-1","runtime":"java-jvm","state":"running","healthy":` + healthy + `,"extraVersionedField":"allowed"},"java":{"state":"RUNNING","responsive":true}}}`))
		default:
			http.Error(w, "missing", 404)
		}
	}))
	defer backend.Close()
	opts := liveIntegrationOptions0491{Backend: backend.URL, Project: "project-1", Run: "migration-1", Extension: "example.java", Scope: "project", ScopeID: "project-1", DSN: "postgres://test-only", Token: "only-test-token", PSQL: psql, Output: filepath.Join(root, "pass.json")}
	if err := executeIntegrationAudit0491(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(opts.Output)
	if err != nil {
		t.Fatal(err)
	}
	var data LiveIntegrationAudit0491
	if err = json.Unmarshal(raw, &data); err != nil || data.Result != "passed" || data.MigrationRevision != 7 || data.JavaInstanceID != "jvm-1" || !data.PostgreSQLReadOnly {
		t.Fatalf("bad evidence: %+v err=%v", data, err)
	}
	if strings.Contains(string(raw), opts.DSN) || strings.Contains(string(raw), opts.Token) {
		t.Fatal("secrets in evidence")
	}
	if info, err := os.Stat(opts.Output); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("evidence not private")
	}
	opts.Output = filepath.Join(root, "reject-stale.json")
	mutate.Store(true)
	if err := executeIntegrationAudit0491(context.Background(), opts); err == nil {
		t.Fatal("accepted concurrent migration revision")
	}
	if _, err := os.Stat(opts.Output); !os.IsNotExist(err) {
		t.Fatal("failure wrote PASS evidence")
	}
	mutate.Store(false)
	calls.Store(0)
	badHost.Store(true)
	opts.Output = filepath.Join(root, "reject-jvm.json")
	if err := executeIntegrationAudit0491(context.Background(), opts); err == nil {
		t.Fatal("accepted unhealthy Java JVM")
	}
	if _, err := os.Stat(opts.Output); !os.IsNotExist(err) {
		t.Fatal("bad JVM wrote PASS evidence")
	}
	// Поддельные учётные данные и недоверенный источник не должны порождать свидетельства.
	opts.Token = "wrong-token"
	opts.Output = filepath.Join(root, "reject-token.json")
	if err := executeIntegrationAudit0491(context.Background(), opts); err == nil {
		t.Fatal("accepted bad token")
	}
	opts.Backend = "http://www.example.com"
	if err := executeIntegrationAudit0491(context.Background(), opts); err == nil {
		t.Fatal("accepted unencrypted public backend")
	}
}
func jsonNumber0491(v int) string {
	if v == 7 {
		return "7"
	}
	return "8"
}

func TestIntegrationAudit0491DoesNotForwardAuthSecretsToPSQL(t *testing.T) {
	env := []string{"PATH=/usr/bin", "PGPASSWORD=stale", "LAUNCHER_MIGRATION_GA_TOKEN=top-secret", "LAUNCHER_POSTGRES_DSN=postgres://secret", "CUSTOM_DSN=postgres://secret", "CUSTOM_TOKEN=top-secret", "LANG=C"}
	opts := liveIntegrationOptions0491{DSN: "postgres://secret", Token: "top-secret"}
	got := withoutPostgresEnvironment0491(env, opts)
	if len(got) != 2 || got[0] != "PATH=/usr/bin" || got[1] != "LANG=C" {
		t.Fatalf("leaked sensitive process environment: %v", got)
	}
}
