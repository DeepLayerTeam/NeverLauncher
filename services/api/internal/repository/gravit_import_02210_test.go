package repository

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestGravitAtomicImportMemory02210(t *testing.T) {
	r := NewMemoryRepository("http://localhost")
	project := "demo-project"
	source := []byte(`{"title":"Vanilla","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"classLoaderConfig":"SYSTEM_ARGS"}`)
	parsed, e := model.ConvertGravitProfile02210(source, project, "gravit-migration", "", "vanilla")
	if e != nil || !parsed.Ready {
		t.Fatalf("conversion: %v %+v", e, parsed.Fields)
	}
	settings := BuildSettings{Minecraft: parsed.Settings.Minecraft, Runtime: parsed.Settings.Runtime}
	ws := BuildWorkspace{ID: "ws-demo-gravit", ProjectID: project, OwnerID: "operator", ProfileID: parsed.Profile.ID, Channel: "stable", Version: "1.0.0", Settings: settings}
	saved, w, e := r.CreateGravitProfileWorkspace02210(context.Background(), parsed.Profile, ws)
	if e != nil {
		t.Fatal(e)
	}
	if saved.Revision != 1 || saved.IsDefault || w.Revision != 1 || w.State != "importing" || w.ProfileDigest != saved.Digest {
		t.Fatalf("wrong initial state: %+v %+v", saved, w)
	}
	snap, e := ReadProfileSnapshot(r, project, saved.ID)
	if e != nil || snap.Digest != saved.Digest {
		t.Fatalf("missing immutable snapshot: %v %+v", e, snap)
	}
	if _, _, e = r.CreateGravitProfileWorkspace02210(context.Background(), parsed.Profile, BuildWorkspace{ID: "ws-another", ProjectID: project, OwnerID: "operator", ProfileID: parsed.Profile.ID, Channel: "stable", Version: "1.0.1", Settings: settings}); !errors.Is(e, ErrConflict) {
		t.Fatalf("duplicate profile accepted: %v", e)
	}
	if _, e = r.GetBuildWorkspace(context.Background(), "ws-another"); !errors.Is(e, ErrNotFound) {
		t.Fatalf("partial workspace after conflict: %v", e)
	}
	other := parsed.Profile
	other.ID = "another-profile"
	otherWorkspace := ws
	otherWorkspace.ProfileID = other.ID
	if _, _, e = r.CreateGravitProfileWorkspace02210(context.Background(), other, otherWorkspace); !errors.Is(e, ErrConflict) {
		t.Fatalf("workspace conflict not rejected: %v", e)
	}
	profiles, e := r.ListProfiles(project)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range profiles {
		if p.ID == other.ID {
			t.Fatal("partial profile after workspace conflict")
		}
	}
}

func TestGravitAtomicImportConcurrent02210(t *testing.T) {
	r := NewMemoryRepository("http://localhost")
	profile := model.Profile{ID: "gravit-concurrent", ProjectID: "demo-project", Name: "Concurrent", Loader: "vanilla"}
	base := BuildWorkspace{ProjectID: "demo-project", OwnerID: "operator", ProfileID: profile.ID, Channel: "stable", Version: "1.0.0", Settings: BuildSettings{Minecraft: model.MinecraftInfo{Version: "1.20.4", Loader: "vanilla"}}}
	const writers = 24
	var wg sync.WaitGroup
	var okCount atomic.Int64
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer wg.Done()
			w := base
			w.ID = fmt.Sprintf("ws-gravit-%02d", i)
			if _, _, err := r.CreateGravitProfileWorkspace02210(context.Background(), profile, w); err == nil {
				okCount.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected writer error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if okCount.Load() != 1 {
		t.Fatalf("expected one atomic winner, got %d", okCount.Load())
	}
	profiles, err := r.ListProfiles("demo-project")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if p.ID == profile.ID {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("expected exactly one imported profile, got %d", found)
	}
}
