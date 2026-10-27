package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRehearsalExecAndSubmission03310(t *testing.T) {
	dir := t.TempDir()
	run := "1234567890abcdef"
	stage := "stage_abcdefgh12345678"
	h := strings.Repeat("a", 64)
	must := func(rel string, b []byte, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, b, mode); e != nil {
			t.Fatal(e)
		}
	}
	marker, _ := json.Marshal(map[string]any{"format": "never/migration-stage/v1", "runId": run, "stageId": stage, "isolated": true})
	must(".never-migration-stage.json", marker, 0600)
	player := rehearsalPlayer03310{SourceID: "fileauth:42", UUID: "12345678-1234-1234-1234-123456789abc", InventorySHA256: h, PermissionsSHA256: h, Economy: "100.00", SkinSHA256: h, Admin: true}
	snapshot := rehearsalSnapshot03310{WorldSHA256: h, Loader: "forge", OptionalPresetSHA256: h, Players: []rehearsalPlayer03310{player}}
	data, _ := json.Marshal(snapshot)
	must("source-snapshot.json", data, 0600)
	must("target-snapshot.json", data, 0600)
	for _, name := range rehearsalRequired03310 {
		must("evidence/"+name, []byte("real-test-evidence"), 0600)
		script := "#!/bin/sh\nprintf '{\"passed\":true,\"uuid\":\"" + player.UUID + "\",\"evidenceFile\":\"evidence/" + name + "\"}'\n"
		must("probes/"+name, []byte(script), 0700)
	}
	report, e := migrationRehearsalRun03310(context.Background(), dir, run, h)
	if e != nil || len(report.Probes) != 7 || report.Ready || report.CutoverAllowed || report.Probes[0].EvidenceSHA256 == "" {
		t.Fatalf("runner: %+v %v", report, e)
	}
	sent := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = true
		if r.Header.Get("X-Migration-Rehearsal-Confirm") != run || r.URL.Path != "/api/v1/admin/migration-runs/"+run+"/rehearsal" {
			t.Error("route or confirmation mismatch")
		}
		var x rehearsalReport03310
		if e := json.NewDecoder(r.Body).Decode(&x); e != nil || len(x.Probes) != 7 || x.Ready || x.CutoverAllowed {
			t.Errorf("bad payload %v %+v", e, x)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"ready":false,"cutoverAllowed":false}}`))
	}))
	defer server.Close()
	if e = handleMigrationRehearsal03310([]string{"--backend", server.URL, "--token", "test", "--run", run, "--stage", dir, "--inventory-sha256", h, "--output", filepath.Join(dir, "report.json")}); e != nil {
		t.Fatal(e)
	}
	if !sent {
		t.Fatal("report was not posted")
	}
	must("probes/join", []byte("#!/bin/sh\nexit 1\n"), 0700)
	if _, e = migrationRehearsalRun03310(context.Background(), dir, run, h); e == nil {
		t.Fatal("failed actual join command accepted")
	}
}
func TestRehearsalPathTraversal03310(t *testing.T) {
	dir := t.TempDir()
	if _, e := rehearsalPath03310(dir, "../outside"); e == nil {
		t.Fatal("path escape accepted")
	}
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(dir, "escape")); e != nil {
		t.Fatal(e)
	}
	if _, e := rehearsalPath03310(dir, "escape"); e == nil {
		t.Fatal("symlink escape accepted")
	}
}
