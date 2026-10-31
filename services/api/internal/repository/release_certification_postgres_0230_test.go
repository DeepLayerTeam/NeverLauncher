//go:build !launcher_nopgx

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// This is a mandatory database integration case in the 0.23 release workflow.
// It must run against a real PostgreSQL instance, not an in-memory substitute.
func TestGAWorkspacePostgresCASAndAtomicImport0230(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires NEVERLAUNCHER_TEST_POSTGRES_DSN; release workflow must set it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	open := func() *SQLRepository {
		repo, ok := NewSQLRepository("pgx", dsn, "http://127.0.0.1").(*SQLRepository)
		if !ok {
			t.Fatal("expected SQL repository")
		}
		return repo
	}
	a, b := open(), open()
	defer a.db.Close()
	defer b.db.Close()
	if _, err := a.ApplyMigrations(ctx); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("ga-0230-%d", time.Now().UnixNano())
	if _, err := a.SaveProject(model.Project{ID: project, Name: "GA 0230 certification"}); err != nil {
		t.Fatal(err)
	}
	profile := model.Profile{ID: "imported", ProjectID: project, Name: "Imported", Loader: "vanilla"}
	base := certificationWorkspace0230("workspace-" + project)
	base.ProjectID = project
	base.ProfileID = profile.ID
	base.Settings.Minecraft.Loader = "vanilla"
	saved, w, err := a.CreateGravitProfileWorkspace02210(ctx, profile, base)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || w.ProfileDigest != saved.Digest || w.Revision != 1 {
		t.Fatalf("invalid imported record: %+v %+v", saved, w)
	}
	// The imported profile and workspace must be visible on another connection.
	got, err := b.GetBuildWorkspace(ctx, w.ID)
	if err != nil || got.ProfileDigest != saved.Digest {
		t.Fatalf("not durable: %+v %v", got, err)
	}
	conflict := base
	conflict.ID = "workspace-conflict-" + project
	if _, _, err := b.CreateGravitProfileWorkspace02210(ctx, profile, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate import accepted: %v", err)
	}
	if _, err := a.GetBuildWorkspace(ctx, conflict.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("partial import: %v", err)
	}
	// An existing workspace ID cannot be adopted even if timestamps or payloads happen to match.
	if _, err := b.CreateBuildWorkspace(ctx, base); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate workspace accepted: %v", err)
	}
	fromA, err := a.GetBuildWorkspace(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	fromB, err := b.GetBuildWorkspace(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, item := range []struct {
		r *SQLRepository
		w BuildWorkspace
	}{{a, fromA}, {b, fromB}} {
		wg.Add(1)
		go func(r *SQLRepository, x BuildWorkspace) {
			defer wg.Done()
			<-start
			x.State = "staged"
			_, err := r.SaveBuildWorkspace(ctx, x)
			results <- err
		}(item.r, item.w)
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected CAS error: %v", e)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("cross-replica workspace CAS success=%d conflicts=%d", success, conflicts)
	}
	pinned, err := a.GetBuildWorkspace(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	pinned.Settings.ToolVersions["api"] = "tampered"
	if _, err := a.SaveBuildWorkspace(ctx, pinned); !errors.Is(err, ErrConflict) {
		t.Fatalf("settings mutation accepted in SQL: %v", err)
	}
}
