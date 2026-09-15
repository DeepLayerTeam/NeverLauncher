package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunVersion(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("version вернул ошибку: %v", err)
	}
}

func TestManifestBuildValidateHashesDiffAndUpdatePlan(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "old")
	newDir := filepath.Join(root, "new")
	for _, dir := range []string{oldDir, newDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(oldDir, "keep.txt"), []byte("same"), 0o644)
	_ = os.WriteFile(filepath.Join(oldDir, "change.txt"), []byte("old"), 0o644)
	_ = os.WriteFile(filepath.Join(oldDir, "delete.txt"), []byte("delete"), 0o644)
	_ = os.WriteFile(filepath.Join(newDir, "keep.txt"), []byte("same"), 0o644)
	_ = os.WriteFile(filepath.Join(newDir, "change.txt"), []byte("new"), 0o644)
	_ = os.WriteFile(filepath.Join(newDir, "add.txt"), []byte("add"), 0o644)

	oldManifest := filepath.Join(root, "old.json")
	newManifest := filepath.Join(root, "new.json")
	diffPath := filepath.Join(root, "diff.json")
	planPath := filepath.Join(root, "plan.json")

	if err := run([]string{"manifest", "build", oldDir, "--version", "2.6.0", "--output", oldManifest}); err != nil {
		t.Fatalf("old manifest build: %v", err)
	}
	if err := run([]string{"manifest", "build", newDir, "--version", "2.7.0", "--output", newManifest}); err != nil {
		t.Fatalf("new manifest build: %v", err)
	}
	if err := run([]string{"manifest", "validate", newManifest}); err != nil {
		t.Fatalf("manifest validate: %v", err)
	}
	if err := run([]string{"hashes", "check", newManifest, "--root", newDir}); err != nil {
		t.Fatalf("hashes check: %v", err)
	}
	if err := run([]string{"manifest", "diff", "--old", oldManifest, "--new", newManifest, "--output", diffPath}); err != nil {
		t.Fatalf("manifest diff: %v", err)
	}
	if err := run([]string{"update", "plan", "--from", oldManifest, "--to", newManifest, "--output", planPath}); err != nil {
		t.Fatalf("update plan: %v", err)
	}

	var diff ManifestDiff
	diffData, err := os.ReadFile(diffPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(diffData, &diff); err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 1 || len(diff.Changed) != 1 || len(diff.Deleted) != 1 || len(diff.Unchanged) != 1 {
		t.Fatalf("неожиданный diff: %+v", diff)
	}

	var plan UpdatePlan
	planData, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Download) != 2 || len(plan.Delete) != 1 || !plan.ResumeDownloads {
		t.Fatalf("неожиданный update plan: %+v", plan)
	}
}

func TestReleasePackageCreatesFiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "release")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range releaseArtifacts("2.7.0") {
		if name == "SBOM.spdx.json" || name == "PROVENANCE.json" || name == "RELEASE_NOTES.txt" {
			continue
		}
		if err := os.WriteFile(filepath.Join(out, name), []byte("test artifact "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{"release", "package", "--version", "2.7.0", "--out", out}); err != nil {
		t.Fatalf("release package: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(t.TempDir(), "release-private.key")
	publicPath := filepath.Join(t.TempDir(), "release-public.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(publicKey)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release", "sign", out, "--private-key", privatePath}); err != nil {
		t.Fatalf("release sign: %v", err)
	}
	for _, name := range []string{"RELEASE_MANIFEST.json", "SHA256SUMS", "SHA256SUMS.sig", "RELEASE_NOTES.txt"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatalf("ожидался файл %s: %v", name, err)
		}
	}
	if err := run([]string{"release", "verify", out, "--public-key", publicPath}); err != nil {
		t.Fatalf("release verify: %v", err)
	}
	if err := run([]string{"release", "publish-check", out, "--public-key", publicPath}); err != nil {
		t.Fatalf("release publish-check: %v", err)
	}
	if err := os.Remove(filepath.Join(out, "neverruntime-linux-amd64")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"release", "verify", out, "--public-key", publicPath}); err == nil {
		t.Fatal("release verify обязан отклонять bundle без required NeverRuntime artifact")
	}
}

func TestRuntimeResolver740Commands(t *testing.T) {
	for _, args := range [][]string{
		{"runtime", "resolver", "--loader", "neoforge", "--minecraft", "1.21.1"},
		{"runtime", "matrix"},
		{"runtime", "metadata-policy"},
		{"runtime", "launch-plan", "--loader", "fabric", "--loader-version", "0.16.x", "--output", "-"},
	} {
		if err := run(args); err != nil {
			t.Fatalf("%v вернула ошибку: %v", args, err)
		}
	}
}

func TestRuntimeProduct850Commands(t *testing.T) {
	versionJSON := "../../../tests/fixtures/runtime/version-1.21.1.json"
	assetIndex := "../../../tests/fixtures/runtime/assets-17.json"
	fabricMetadata := "../../../tests/fixtures/runtime/fabric-profile.json"
	out := t.TempDir() + "/launch-plan.json"
	for _, args := range [][]string{
		{"runtime", "resolve-version", "--version-json", versionJSON, "--output", "-"},
		{"runtime", "build-classpath", "--version-json", versionJSON, "--asset-index", assetIndex, "--output", "-"},
		{"runtime", "build-launch-plan", "--version-json", versionJSON, "--asset-index", assetIndex, "--output", out},
		{"runtime", "verify-launch-plan", out},
		{"runtime", "resolve-loader", "--loader", "fabric", "--version-json", versionJSON, "--metadata", fabricMetadata, "--output", "-"},
	} {
		if err := run(args); err != nil {
			t.Fatalf("%v вернула ошибку: %v", args, err)
		}
	}
}

func TestAdminOpsCanonicalCommands(t *testing.T) {
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	for _, args := range [][]string{
		{"adminops", "status", "--backend", srv.URL},
		{"adminops", "readiness", "--backend", srv.URL},
		{"adminops", "diagnostics", "--backend", srv.URL, "--token", "test-token"},
		{"adminops", "backup", "--backend", srv.URL, "--token", "test-token"},
	} {
		if err := run(args); err != nil {
			t.Fatalf("%v вернула ошибку: %v", args, err)
		}
	}
	for _, path := range []string{"/api/v1/status", "/ready", "/api/v1/operations/diagnostics", "/api/v1/operations/backup"} {
		if !seen[path] {
			t.Fatalf("canonical endpoint %s was not called", path)
		}
	}
}

func TestRemovedLegacyCommandsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"ecosystem", "status"},
		{"stable", "status"},
		{"rc1", "status"},
		{"security", "freeze"},
		{"runtime", "parity"},
		{"public", "status"},
		{"platform", "status"},
		{"product", "status"},
		{"registry", "list"},
		{"extension", "runtime"},
		{"lts", "policy"},
		{"beta", "smoke"},
		{"deployment", "status"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("legacy command %v must be rejected after cleanup", args)
		}
	}
}

func TestCanonicalOpenAPICompatibilityCheck(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	openapi := filepath.Join(root, "schemas", "openapi.yaml")
	if err := handleAPI([]string{"compatibility-check", "--openapi", openapi}); err != nil {
		t.Fatalf("canonical compatibility-check failed: %v", err)
	}
}

func TestReleaseDoctorAcceptsCanonicalOpenAPI(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldWD) }()
	if err := releaseDoctor(); err != nil {
		t.Fatalf("release doctor rejected canonical P3.2 tree: %v", err)
	}
}

func TestCanonicalOpenAPIRejectsHistoricalPaths(t *testing.T) {
	data := []byte(`{"openapi":"3.1.1","paths":{"/health":{},"/ready":{},"/api/v1/status":{},"/api/v5/status":{}}}`)
	if errs := canonicalOpenAPIErrors(data); len(errs) == 0 {
		t.Fatal("historical /api/v5 path must be rejected")
	}
}
