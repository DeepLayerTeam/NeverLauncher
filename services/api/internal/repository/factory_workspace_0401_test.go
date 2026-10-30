package repository

import (
	"context"
	"strings"
	"testing"
)

func TestFactoryWorkspaceTransition0401(t *testing.T) {
	ctx := context.Background()
	repo := &MemoryRepository{}
	base := BuildWorkspace{ID: "factory-workspace", ProjectID: "project", ProfileID: "profile", OwnerID: "owner", Channel: "stable", Version: "0.40.1", ProfileRevision: 1, ProfileDigest: strings.Repeat("a", 64)}
	base.Settings.Minecraft.Version = "1.21.1"
	base.Settings.Minecraft.Loader = "vanilla"
	base.Settings.Runtime.Java.MajorVersion = 21
	ws, err := repo.CreateBuildWorkspace(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	modified := ws
	modified.Settings.Runtime.Launch.ClasspathStrategy = "mojang"
	modified.Settings.Runtime.Launch.VersionMetadataPath = "versions/1.21.1/1.21.1.json"
	modified.Files = []BuildFile{{Path: "versions/1.21.1/1.21.1.json", SHA256: strings.Repeat("b", 64), Size: 16, Ownership: "required", Selected: true}}
	if _, err := repo.SaveBuildWorkspace(ctx, modified); err == nil {
		t.Fatal("ordinary import changed immutable launch settings")
	}
	saved, err := repo.SaveFactoryWorkspace0401(ctx, modified)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != ws.Revision+1 || saved.Settings.Runtime.Launch.ClasspathStrategy != "mojang" {
		t.Fatal("factory commit was not durable")
	}
	if _, err := repo.SaveFactoryWorkspace0401(ctx, modified); err == nil {
		t.Fatal("replayed stale factory revision")
	}
	changed := saved
	changed.Settings.Runtime.Java.MajorVersion = 8
	if _, err := repo.SaveFactoryWorkspace0401(ctx, changed); err == nil {
		t.Fatal("allowed factory to modify pinned java")
	}
	reloaded, err := repo.GetBuildWorkspace(ctx, ws.ID)
	if err != nil || reloaded.Revision != saved.Revision || reloaded.Settings.Runtime.Java.MajorVersion != 21 {
		t.Fatal("rejected mutation was persisted")
	}
}
