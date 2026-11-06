package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildImportFixture0493(t *testing.T) (string, string, string, gravBatch0492) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "source.zip")
	mapping := filepath.Join(dir, "mapping.json")
	report := filepath.Join(dir, "report.json")
	contents := []byte("unchanged source from verified Gravit archive")
	if err := os.WriteFile(source, contents, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	batch := gravBatch0492{Format: "launcher.gravit-multi-profile-dry-run.v1", RunID: "run", ProjectID: "project", SourceSHA256: hex.EncodeToString(digest[:]), InventorySHA256: strings.Repeat("b", 64), TargetSHA256: strings.Repeat("c", 64), Status: "manual", Blockers: []string{}, Profiles: []gravProfile0492{}}
	for _, p := range []string{"one", "two"} {
		batch.Profiles = append(batch.Profiles, gravProfile0492{Destination: gravDest0492{ProfilePath: "profiles/" + p + ".json", ProfileID: p, ProfileName: p, Loader: "forge", LoaderVersion: "49.0.38", Channel: "stable", Version: "1.0"}, Status: "manual", PlanSHA256: strings.Repeat("d", 64), FilesSHA256: strings.Repeat("f", 64), FileCount: 2, Dependencies: []gravDependency0492{}, Blockers: []string{}})
	}
	batch.ProfileCount = len(batch.Profiles)
	tmp := batch
	tmp.BatchSHA256 = ""
	raw, _ := json.Marshal(tmp)
	sum := sha256.Sum256(raw)
	batch.BatchSHA256 = hex.EncodeToString(sum[:])
	b, _ := json.Marshal(gravBatchResponse0492{Data: batch})
	if err := os.WriteFile(report, b, 0600); err != nil {
		t.Fatal(err)
	}
	dests := []gravDest0492{}
	for _, p := range batch.Profiles {
		dests = append(dests, p.Destination)
	}
	b, _ = json.Marshal(dests)
	if err := os.WriteFile(mapping, b, 0600); err != nil {
		t.Fatal(err)
	}
	return source, mapping, report, batch
}
func jsonData0493(w http.ResponseWriter, val any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": val})
}
func TestImportAllStagesBothProfiles0493(t *testing.T) {
	source, mapping, report, batch := buildImportFixture0493(t)
	staged := map[string]bool{}
	imports := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("отсутствует Bearer-токен")
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/content"):
			key := strings.TrimSuffix(strings.TrimPrefix(r.URL.Query().Get("profilePath"), "profiles/"), ".json")
			if !staged[key] {
				w.WriteHeader(404)
				return
			}
			jsonData0493(w, contentResponseFixture0493(batch, key))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/dry-run"):
			n := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("X-Gravit-Profile-Path"), "profiles/"), ".json")
			if n != "one" && n != "two" {
				t.Errorf("некорректный профиль %s", n)
			}
			if r.Header.Get("X-Loader-Version") != "49.0.38" {
				t.Error("точная версия загрузчика Forge не была перенесена")
			}
			if r.Header.Get("Content-Type") != "application/zip" {
				t.Error("ZIP-файл не был загружен")
			}
			data, _ := io.ReadAll(r.Body)
			sourceBytes, _ := os.ReadFile(source)
			if string(data) != string(sourceBytes) {
				t.Error("байты исходного файла не совпадают")
			}
			plan := livePlanFixture0493(batch, n)
			if n == "two" {
				plan.TargetSHA256 = strings.Repeat("e", 64)
				plan.PlanSHA256 = strings.Repeat("e", 64)
			}
			jsonData0493(w, plan)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/content/import"):
			n := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("X-Gravit-Profile-Path"), "profiles/"), ".json")
			if r.Header.Get("X-Migration-Content-Confirm") != "run" {
				t.Error("отсутствует подтверждение запуска")
			}
			wanted := strings.Repeat("d", 64)
			if n == "two" {
				wanted = strings.Repeat("e", 64)
			}
			if r.Header.Get("X-Migration-Plan-SHA256") != wanted {
				t.Error("не передан закреплённый хеш плана")
			}
			if r.Header.Get("X-Loader-Version") != "49.0.38" {
				t.Error("в коммите отсутствует версия загрузчика")
			}
			if n == "two" && !staged["one"] {
				t.Error("второй профиль импортирован раньше первого")
			}
			imports++
			staged[n] = true
			jsonData0493(w, contentResponseFixture0493(batch, n))
		default:
			t.Errorf("Неожиданный запрос: %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "receipt.json")
	args := []string{"import-content-all", "--backend", server.URL, "--token", "token", "--run", "run", "--confirm", "run", "--source", source, "--mapping", mapping, "--report", report, "--output", output}
	if err := handleMigrationWorkflow0331(args); err != nil {
		t.Fatal(err)
	}
	if imports != 2 {
		t.Fatalf("импортировано только %d профилей", imports)
	}
	resumed := append(append([]string(nil), args[:len(args)-1]...), filepath.Join(t.TempDir(), "resume.json"), "--resume", "true")
	if err := handleMigrationWorkflow0331(resumed); err != nil {
		t.Fatalf("повторяемое возобновление отклонено: %v", err)
	}
	if imports != 2 {
		t.Fatalf("при возобновлении повторно применены ранее подготовленные байты: %d", imports)
	}
	st, err := os.Stat(output)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("отсутствует закрытый результат: %v %v", st, err)
	}
	var result struct {
		Status   string                  `json:"status"`
		Profiles []migrationImported0493 `json:"profiles"`
	}
	payload, _ := os.ReadFile(output)
	if json.Unmarshal(payload, &result) != nil || result.Status != "staged" || len(result.Profiles) != 2 {
		t.Fatalf("некорректная квитанция об успехе %s", payload)
	}
	if err := handleMigrationWorkflow0331(args); err == nil || !strings.Contains(err.Error(), "--resume") {
		t.Fatalf("повторный импорт не был заблокирован: %v", err)
	}
}
func livePlanFixture0493(batch gravBatch0492, n string) migrationLivePlan0493 {
	var row gravProfile0492
	for _, r := range batch.Profiles {
		if r.Destination.ProfileID == n {
			row = r
		}
	}
	p := migrationLivePlan0493{RunID: batch.RunID, ProjectID: batch.ProjectID, SourceSHA256: batch.SourceSHA256, InventorySHA256: batch.InventorySHA256, TargetSHA256: batch.TargetSHA256, PlanSHA256: row.PlanSHA256, Destination: row.Destination, Status: "manual", Blockers: []string{}}
	p.Content.ProfilePath = row.Destination.ProfilePath
	p.Content.SourceSHA256 = batch.SourceSHA256
	p.Content.InventorySHA256 = batch.InventorySHA256
	p.Content.FilesSHA256 = row.FilesSHA256
	p.Content.Ready = true
	p.Content.Files = []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{}`)}
	return p
}
func contentResponseFixture0493(batch gravBatch0492, n string) migrationLiveContent0493 {
	var row gravProfile0492
	for _, r := range batch.Profiles {
		if r.Destination.ProfileID == n {
			row = r
		}
	}
	s := migrationLiveContent0493{Complete: true, WorkspaceID: "ws-" + n, State: "staged", StagedFiles: row.FileCount, TotalFiles: row.FileCount}
	s.Plan.ProfilePath = row.Destination.ProfilePath
	s.Plan.SourceSHA256 = batch.SourceSHA256
	s.Plan.InventorySHA256 = batch.InventorySHA256
	s.Plan.FilesSHA256 = row.FilesSHA256
	s.Plan.Profile.Profile.ID = n
	return s
}
func TestImportAllRejectsStaleTargetAndTamperedInputs0493(t *testing.T) {
	source, mapping, report, batch := buildImportFixture0493(t)
	imports := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/content") {
			w.WriteHeader(404)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/dry-run") {
			p := livePlanFixture0493(batch, "one")
			p.TargetSHA256 = strings.Repeat("a", 64)
			jsonData0493(w, p)
			return
		}
		imports++
		w.WriteHeader(500)
	}))
	defer server.Close()
	args := []string{"import-content-all", "--backend", server.URL, "--token", "token", "--run", "run", "--confirm", "run", "--source", source, "--mapping", mapping, "--report", report}
	if err := handleMigrationWorkflow0331(args); err == nil || !strings.Contains(err.Error(), "target changed") {
		t.Fatalf("устаревшая цель не была отклонена: %v", err)
	}
	if imports != 0 {
		t.Fatal("данные изменены после выявления устаревшей цели")
	}
	if err := os.WriteFile(source, []byte("altered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := handleMigrationWorkflow0331(args); err == nil || !strings.Contains(err.Error(), "source changed") {
		t.Fatalf("принят изменённый ZIP-файл: %v", err)
	}
	args[7] = "wrong" // wrong confirmation
	if err := handleMigrationWorkflow0331(args); err == nil {
		t.Fatal("принято неверное явное подтверждение")
	}
}
func TestImportAllURL0493(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://name:password@host", "http://localhost", "ftp://example.com", "https://example.com/?token=1"} {
		if _, err := migrationURL0493(raw); err == nil {
			t.Fatal(fmt.Sprintf("unsafe URL accepted: %s", raw))
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8080", "https://example.com"} {
		if _, err := migrationURL0493(raw); err != nil {
			t.Fatalf("допустимый URL отклонён: %v", err)
		}
	}
}
