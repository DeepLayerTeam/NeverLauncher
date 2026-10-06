package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExtensionInit02010CreatesRunnableBackendLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ext")
	if err := extensionInit02010([]string{"--target", "backend,cli,admin,desktop", "--out", root, "--id", "ru.example.sdk", "--name", "SDK Example", "--publisher", "Example"}); err != nil {
		t.Fatal(err)
	}
	manifest, _, _, err := loadCanonicalExtension0201(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, target := range manifest.Targets {
		got[target.Kind] = target.Entrypoint
	}
	want := map[string]string{"backend": "backend/bin/extension-backend", "cli": "cli/bin/extension-cli", "admin": "admin/index.html", "desktop": "desktop/index.html"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("target %s entrypoint=%q want %q", k, got[k], v)
		}
	}
	for _, rel := range []string{"backend/go.mod", "backend/main.go", "cli/go.mod", "cli/main.go", "admin/index.html", "desktop/index.html"} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
	}
}

func TestLocalDevHost02010DenyByDefaultAndHandshake(t *testing.T) {
	manifest := CanonicalExtensionManifest0201{SchemaVersion: "2.0", ID: "ru.example.dev", Name: "Dev", Version: "1.0.0", Publisher: "Example", API: "3.7", Targets: []CanonicalExtensionTarget0201{{Kind: "backend", Entrypoint: "backend/bin/extension-backend"}}, Permissions: []string{"project:read"}}
	manifest, _, _ = normalizeCanonicalExtension0201(manifest)
	host, err := newLocalDevHost02010(manifest, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	do := func(path string, body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, host.url()+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+host.token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	hello := `{"protocolVersion":"1.0","instanceId":"` + host.instance + `","extensionId":"ru.example.dev"}`
	resp := do("/v1/hello", hello)
	if resp.StatusCode != 200 {
		t.Fatalf("hello=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = do("/v1/capabilities/project.get", `{"projectId":"dev-project"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("project.get without explicit grant=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestLocalDevHost02010ExplicitGrant(t *testing.T) {
	manifest := CanonicalExtensionManifest0201{SchemaVersion: "2.0", ID: "ru.example.dev", Name: "Dev", Version: "1.0.0", Publisher: "Example", API: "3.7", Targets: []CanonicalExtensionTarget0201{{Kind: "backend", Entrypoint: "backend/bin/extension-backend"}}, Permissions: []string{"project:read"}}
	manifest, _, _ = normalizeCanonicalExtension0201(manifest)
	host, err := newLocalDevHost02010(manifest, []string{"project:read"}, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"protocolVersion": "1.0", "instanceId": host.instance, "extensionId": manifest.ID})
	req, _ := http.NewRequest(http.MethodPost, host.url()+"/v1/hello", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+host.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("hello=%d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, host.url()+"/v1/capabilities/project.get", strings.NewReader(`{"projectId":"dev-project"}`))
	req.Header.Set("Authorization", "Bearer "+host.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("project.get=%d", resp.StatusCode)
	}
}

func TestDevEnvironment02010DoesNotLeakBackendSecrets(t *testing.T) {
	t.Setenv("NEVERLAUNCHER_DATABASE_DSN", "postgres://secret")
	t.Setenv("NEVERLAUNCHER_AUTH_SIGNING_KEY", "secret")
	m := CanonicalExtensionManifest0201{ID: "ru.example.dev", Version: "1.0.0"}
	env := devEnvironment02010("http://127.0.0.1:1", "token", "callback", "instance", m, "backend")
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "DATABASE_DSN") || strings.Contains(joined, "AUTH_SIGNING_KEY") {
		t.Fatalf("secret leaked into dev environment: %s", joined)
	}
}

func TestSDKEntrypoints02010(t *testing.T) {
	if sdkEntrypoint("backend") != "backend/bin/extension-backend" || sdkEntrypoint("admin") != "admin/index.html" {
		t.Fatalf("unexpected 0.20.10 SDK entrypoints")
	}
	if runtime.GOOS != "windows" && strings.Contains(sdkEntrypoint("backend"), ".go") {
		t.Fatal("backend manifest entrypoint must be executable payload, not Go source")
	}
}
