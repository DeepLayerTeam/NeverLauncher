package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestBuildWorkspaceCASDeepCopyAndImmutableResult0226(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository("https://neverlauncher.test")
	initial := BuildWorkspace{ID: "ws-test", ProjectID: "demo-project", OwnerID: "admin", ProfileID: "vanilla", Channel: "stable", Version: "0.22.6", ProfileRevision: 1, ProfileDigest: strings.Repeat("a", 64), Settings: BuildSettings{ToolVersions: map[string]string{"api": "0.22.6"}}, Files: []BuildFile{{Path: "mods/first.jar", SHA256: strings.Repeat("b", 64), Size: 5, Selected: true}}}
	saved, err := repo.CreateBuildWorkspace(ctx, initial)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.State != "importing" {
		t.Fatalf("initial revision: %#v", saved)
	}
	saved.Files[0].Path = "tampered.jar"
	saved.Settings.ToolVersions["api"] = "other"
	untouched, err := repo.GetBuildWorkspace(ctx, saved.ID)
	if err != nil || untouched.Files[0].Path != "mods/first.jar" || untouched.Settings.ToolVersions["api"] != "0.22.6" {
		t.Fatalf("external mutation affected repository: %#v %v", untouched, err)
	}
	updated := untouched
	updated.State = "staged"
	stored, err := repo.SaveBuildWorkspace(ctx, updated)
	if err != nil || stored.Revision != 2 {
		t.Fatalf("save: %#v %v", stored, err)
	}
	if _, err = repo.SaveBuildWorkspace(ctx, updated); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update allowed: %v", err)
	}
	hijack := stored
	hijack.OwnerID = "someone-else"
	if _, err = repo.SaveBuildWorkspace(ctx, hijack); !errors.Is(err, ErrConflict) {
		t.Fatalf("owner changed: %v", err)
	}
	stored.State = "built"
	stored.PackageID = "demo-project-vanilla-0.22.6"
	stored.BuildDigest = strings.Repeat("c", 64)
	finished, err := repo.SaveBuildWorkspace(ctx, stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.SaveBuildWorkspace(ctx, finished); !errors.Is(err, ErrImmutable) {
		t.Fatalf("built workspace mutable: %v", err)
	}
	listed, err := repo.ListBuildWorkspaces(ctx, "demo-project", "admin")
	if err != nil || len(listed) != 1 || listed[0].State != "built" {
		t.Fatalf("owner list: %#v %v", listed, err)
	}
	foreign, err := repo.ListBuildWorkspaces(ctx, "demo-project", "not-admin")
	if err != nil || len(foreign) != 0 {
		t.Fatalf("owner leak: %#v %v", foreign, err)
	}
}
