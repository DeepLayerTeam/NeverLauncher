package extensionsecurity

import (
	"context"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func fixture0207(t *testing.T) (*Manager, repository.Repository) {
	t.Helper()
	repo := repository.NewMemoryRepository("http://example.test")
	for _, v := range []model.ExtensionManifest{
		{SchemaVersion: "2.0", ID: "example.security", Name: "Security", Version: "1.0.0", Publisher: "test.publisher", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/ext"}}, Permissions: []string{"project:read", "storage:read"}},
		{SchemaVersion: "2.0", ID: "example.security", Name: "Security", Version: "1.1.0", Publisher: "test.publisher", API: "1.0", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/ext"}}, Permissions: []string{"project:read", "storage:read", "http:outbound", "secrets:read"}},
	} {
		if _, err := repo.SaveExtensionVersion(context.Background(), v); err != nil {
			t.Fatal(err)
		}
	}
	for _, projectID := range []string{"p1", "p2"} {
		if _, err := repo.SaveProject(model.Project{ID: projectID, Name: projectID}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := New(repo, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return m, repo
}
func TestDenyByDefaultGrantRevokeAndDiff0207(t *testing.T) {
	m, _ := fixture0207(t)
	ctx := context.Background()
	if ok, err := m.Allowed(ctx, "example.security", "1.0.0", "global", "", "project:read", "demo-project"); err != nil || ok {
		t.Fatalf("deny-by-default failed ok=%v err=%v", ok, err)
	}
	if _, err := m.Grant(ctx, "example.security", "1.0.0", "global", "", "project:read", "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Allowed(ctx, "example.security", "1.0.0", "global", "", "project:read", "demo-project"); err != nil || !ok {
		t.Fatalf("grant not effective ok=%v err=%v", ok, err)
	}
	d, err := m.PermissionDiff(ctx, "example.security", "1.0.0", "1.1.0", "global", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.AddedNotGranted) != 2 || d.AddedNotGranted[0] != "http:outbound" || d.AddedNotGranted[1] != "secrets:read" {
		t.Fatalf("unexpected diff %#v", d)
	}
	if err := m.Revoke(ctx, "example.security", "global", "", "project:read"); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Allowed(ctx, "example.security", "1.0.0", "global", "", "project:read", "demo-project"); err != nil || ok {
		t.Fatalf("revoke failed ok=%v err=%v", ok, err)
	}
}
func TestProjectScopedGrant0207(t *testing.T) {
	m, _ := fixture0207(t)
	ctx := context.Background()
	if _, err := m.Grant(ctx, "example.security", "1.0.0", "project", "p1", "storage:read", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Allowed(ctx, "example.security", "1.0.0", "global", "", "storage:read", "p1"); !ok {
		t.Fatal("project grant should authorize matching project for global install")
	}
	if ok, _ := m.Allowed(ctx, "example.security", "1.0.0", "global", "", "storage:read", "p2"); ok {
		t.Fatal("project grant leaked to another project")
	}
}
func TestSecretsEncryptedAuthenticated0207(t *testing.T) {
	m, repo := fixture0207(t)
	ctx := context.Background()
	meta, err := m.SetSecret(ctx, "example.security", "global", "", "API_KEY", []byte("top-secret"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "API_KEY" {
		t.Fatal(meta)
	}
	stored, err := repo.GetExtensionSecret(ctx, "example.security", "global", "", "API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.Ciphertext) == "top-secret" {
		t.Fatal("plaintext stored")
	}
	plain, err := m.GetSecret(ctx, "example.security", "global", "", "API_KEY")
	if err != nil || string(plain) != "top-secret" {
		t.Fatalf("secret roundtrip failed %q %v", plain, err)
	}
	stored.Ciphertext[0] ^= 0xff
	if _, err := repo.PutExtensionSecret(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetSecret(ctx, "example.security", "global", "", "API_KEY"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
