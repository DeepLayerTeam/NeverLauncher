package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBatchCLI0492(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "archive.zip")
	mapping := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(src, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapping, []byte(`[{"profilePath":"profiles/a.json","profileId":"a","profileName":"A","loader":"vanilla","channel":"stable","version":"1"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	suffix := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/migration-runs/r1/dry-run-all" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("invalid authorization or route")
		}
		b, e := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Gravit-Profiles"))
		if e != nil || !strings.Contains(string(b), "profiles/a.json") {
			t.Errorf("invalid profile mapping")
		}
		w.Header().Set("Content-Type", "application/json")
		batch := gravBatch0492{Format: "launcher.gravit-multi-profile-dry-run.v1", RunID: "r1", ProjectID: "p1", SourceSHA256: suffix, InventorySHA256: suffix, TargetSHA256: suffix, Profiles: []gravProfile0492{{Destination: gravDest0492{ProfilePath: "profiles/a.json", ProfileID: "a", ProfileName: "A", Loader: "vanilla", Channel: "stable", Version: "1"}, Status: "manual", Dependencies: []gravDependency0492{}, Blockers: []string{}}}, ProfileCount: 1, Status: "manual", Blockers: []string{}}
		payload, _ := json.Marshal(batch)
		checksum := sha256.Sum256(payload)
		batch.BatchSHA256 = hex.EncodeToString(checksum[:])
		response, _ := json.Marshal(gravBatchResponse0492{Data: batch})
		_, _ = w.Write(response)
	}))
	defer server.Close()
	output := filepath.Join(dir, "report.json")
	args := []string{"dry-run-all", "--backend", server.URL, "--token", "secret", "--run", "r1", "--source", src, "--mapping", mapping, "--output", output}
	if e := handleMigrationWorkflow0331(args); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(output)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("report permissions %v %v", st, e)
	}
	verify := []string{"verify-dry-run-all", "--backend", server.URL, "--token", "secret", "--run", "r1", "--source", src, "--mapping", mapping, "--report", output}
	if e := handleMigrationWorkflow0331(verify); e != nil {
		t.Fatal(e)
	}
	var edited map[string]any
	data, _ := os.ReadFile(output)
	_ = json.Unmarshal(data, &edited)
	editedData := edited["data"].(map[string]any)
	editedData["batchSha256"] = strings.Repeat("b", 64)
	tampered, _ := json.Marshal(edited)
	_ = os.WriteFile(output, tampered, 0600)
	if e := handleMigrationWorkflow0331(verify); e == nil {
		t.Fatal("stale report accepted")
	}
}
