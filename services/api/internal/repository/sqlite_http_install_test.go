package repository

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestMinimalInstallationSQLite0375(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "http.sqlite")
	r, err := OpenSQLiteHTTPRepository0372(ctx, file, "https://example")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 48)
	if err = r.InitializeMinimalInstallation0375(ctx, token, true); err != nil {
		t.Fatal(err)
	}
	if err = r.InitializeMinimalInstallation0375(ctx, "wrong-token-"+strings.Repeat("b", 40), true); err == nil {
		t.Fatal("cannot replace bootstrap verifier")
	}
	now := time.Now().UTC()
	user := model.User{ID: "admin", Email: "admin@example.test", DisplayName: "Owner", Status: "active", RoleID: "owner", PasswordHash: "hash-not-a-real-secret", CreatedAt: now, UpdatedAt: now}
	identity := model.AuthIdentity{ID: "identity-local-admin", UserID: "admin", Issuer: "launcher", Provider: "local", Subject: "admin", Email: user.Email}
	if _, err = r.BootstrapMinimalAdmin0375(ctx, user, identity, "wrong", "installer"); err == nil {
		t.Fatal("invalid token accepted")
	}
	created, err := r.BootstrapMinimalAdmin0375(ctx, user, identity, token, "installer")
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "admin" {
		t.Fatal("wrong owner")
	}
	if _, err = r.BootstrapMinimalAdmin0375(ctx, user, identity, token, "installer"); err == nil {
		t.Fatal("token reused")
	}
	if err = r.CompleteMinimalInstallation0375(ctx); err == nil {
		t.Fatal("completed without a project")
	}
	if _, err = r.SaveProject(model.Project{ID: "first", Name: "First", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err = r.CompleteMinimalInstallation0375(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenSQLiteHTTPRepository0372(ctx, file, "https://example")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = r.InitializeMinimalInstallation0375(ctx, "", true); err != nil {
		t.Fatal(err)
	}
	_, consumed, completed, err := r.MinimalInstallationStatus0375(ctx)
	if err != nil || !consumed || !completed {
		t.Fatalf("status: consumed=%v completed=%v err=%v", consumed, completed, err)
	}
	actual, err := r.GetUser("admin")
	if err != nil || actual.PasswordHash != user.PasswordHash {
		t.Fatalf("owner password hash lost on restart: %v", err)
	}
	if _, err = r.GetAuthIdentity("local", "admin"); err != nil {
		t.Fatalf("identity not persisted: %v", err)
	}
	if _, err = r.BootstrapMinimalAdmin0375(ctx, user, identity, token, "installer"); err == nil {
		t.Fatal("bootstrap reopened after restart")
	}
}
