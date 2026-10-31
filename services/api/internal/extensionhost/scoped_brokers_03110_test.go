package extensionhost

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Execute the production Host capability handlers and the real memory-backed
// grants manager. Isolated unit tests do not pretend to certify kernel state.
func TestScopedBrokerCapabilities03110(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo := repository.NewMemoryRepository("http://example.invalid")
	m := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.scoped", Version: "1.0.0", Name: "Scoped fixture", Publisher: "test.publisher", API: "1.0",
		Targets:     []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}},
		Permissions: []string{"storage:read", "storage:write", "http:outbound", "secrets:read"},
		Sandbox: &model.ExtensionSandboxPolicy{Version: "1", Mode: "isolated", FilesystemRead: []string{"package", "shared:reports"}, FilesystemWrite: []string{"scratch", "shared:reports"},
			NetworkOutbound: []string{"api.example.com:443"}, Secrets: []string{"api_token"}, MaxProcesses: 2, MaxMemoryBytes: 64 << 20, MaxCPUPercent: 25, TimeoutSeconds: 60}}
	if _, err := repo.SaveExtensionVersion(ctx, m); err != nil {
		t.Fatal(err)
	}
	for _, p := range m.Permissions {
		if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: m.ID, Scope: "global", Permission: p, GrantedBy: "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	s := New(Config{SharedRoots: map[string]string{"reports": root}}, repo, nil)
	st := &processState{key: Key{ExtensionID: m.ID, Scope: "global"}, install: model.ExtensionInstall{ExtensionID: m.ID, CurrentVersion: m.Version}, manifest: m, sandboxReady: true}
	data := base64.StdEncoding.EncodeToString([]byte("scoped-content"))
	req := capabilityRequest{Name: "reports", Path: "my-file", BodyBase64: data}
	if r := s.executeCapability(ctx, st, "fs.write", req); r.err != nil || r.status != 200 {
		t.Fatalf("write denied: %+v", r)
	}
	if r := s.executeCapability(ctx, st, "fs.read", req); r.err != nil {
		t.Fatalf("read denied: %+v", r)
	} else {
		obj, ok := r.value.(map[string]any)
		if !ok || obj["contentBase64"] != data {
			t.Fatalf("unexpected read result %+v", r.value)
		}
	}
	if r := s.executeCapability(ctx, st, "fs.read", capabilityRequest{Name: "private", Path: "secret"}); r.status != 403 {
		t.Fatalf("ungranted root exposed %+v", r)
	}
	if r := s.executeCapability(ctx, st, "fs.write", capabilityRequest{Name: "reports", Path: "../secrets", BodyBase64: data}); r.status != 403 {
		t.Fatalf("traversal allowed %+v", r)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("no"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if r := s.executeCapability(ctx, st, "fs.read", capabilityRequest{Name: "reports", Path: "alias"}); r.status != 403 {
		t.Fatalf("symlink allowed %+v", r)
	}
	if r := s.executeCapability(ctx, st, "secret.get", capabilityRequest{Name: "api_token"}); r.status != 403 {
		t.Fatalf("raw secret disclosure %+v", r)
	}
	if r := s.executeCapability(ctx, st, "http.fetch", capabilityRequest{URL: "https://api.example.com.evil.net"}); r.status != 403 {
		t.Fatalf("network bypass %+v", r)
	}
	if r := s.executeCapability(ctx, st, "http.fetch", capabilityRequest{URL: "https://api.example.com", SecretName: "unapproved"}); r.status != 403 {
		t.Fatalf("secret allowlist bypass %+v", r)
	}
	if r := s.executeCapability(ctx, st, "http.fetch", capabilityRequest{URL: "https://api.example.com", SecretName: "api_token", Headers: map[string]string{"authorization": "clash"}}); r.status != 400 {
		t.Fatalf("ambiguous authorization allowed %+v", r)
	}
	if err := repo.RevokeExtensionPermission(ctx, m.ID, "global", "", "storage:read"); err != nil {
		t.Fatal(err)
	}
	if r := s.executeCapability(ctx, st, "fs.read", req); r.status != 403 {
		t.Fatalf("revoked permission still effective %+v", r)
	}
	st.sandboxReady = false
	if r := s.executeCapability(ctx, st, "fs.write", req); r.status != 403 {
		t.Fatalf("unready sandbox gained broker %+v", r)
	}
}
func TestSharedRootsAbsentIsFailClosed03110(t *testing.T) {
	s := New(Config{}, repository.NewMemoryRepository("http://example.invalid"), nil)
	p := &model.ExtensionSandboxPolicy{Mode: "isolated", FilesystemRead: []string{"shared:missing"}}
	if err := s.validateSharedRoots03110(p); err == nil {
		t.Fatal("missing shared root accepted")
	}
}
