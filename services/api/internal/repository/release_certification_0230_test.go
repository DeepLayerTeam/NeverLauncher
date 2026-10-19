package repository

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func certificationWorkspace0230(id string) BuildWorkspace {
	return BuildWorkspace{
		ID: id, ProjectID: "demo-project", OwnerID: "operator", ProfileID: "vanilla",
		Channel: "stable", Version: "0.23.0", ProfileRevision: 1,
		ProfileDigest: strings.Repeat("a", 64),
		Settings: BuildSettings{
			Minecraft:    model.MinecraftInfo{Version: "1.21.1", Loader: "vanilla"},
			ToolVersions: map[string]string{"api": "0.23.0"},
		},
		Files: []BuildFile{{Path: "mods/client.jar", Size: 3, SHA256: strings.Repeat("b", 64), Ownership: "required", Selected: true}},
	}
}

// Covers the actual store transitions used by upload, stage and materialize.
// Package metadata must remain pinned across retries and concurrent requests.
func TestGAWorkspaceImmutabilityAndStateMachine0230(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryRepository("https://neverlauncher.test")
	w, err := r.CreateBuildWorkspace(ctx, certificationWorkspace0230("ga-workspace"))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*BuildWorkspace){
		"runtime": func(x *BuildWorkspace) { x.Settings.Runtime.Java.MajorVersion = 21 },
		"file rules": func(x *BuildWorkspace) {
			x.Settings.FileRules = []model.FileRule{{Pattern: "mods/**", Ownership: "managed", Action: "include"}}
		},
		"tool version": func(x *BuildWorkspace) { x.Settings.ToolVersions["api"] = "1.0.0" },
		"loader":       func(x *BuildWorkspace) { x.Settings.Minecraft.Loader = "forge" },
		"owner":        func(x *BuildWorkspace) { x.OwnerID = "other-operator" },
	} {
		t.Run(name, func(t *testing.T) {
			original, err := r.GetBuildWorkspace(ctx, w.ID)
			if err != nil {
				t.Fatal(err)
			}
			candidate := cloneWorkspace0226(original)
			mutate(&candidate)
			if _, err := r.SaveBuildWorkspace(ctx, candidate); !errors.Is(err, ErrConflict) {
				t.Fatalf("mutating pinned input was accepted: %v", err)
			}
		})
	}
	w.State = "built"
	w.PackageID = "unsafe"
	w.BuildDigest = strings.Repeat("c", 64)
	if _, err := r.SaveBuildWorkspace(ctx, w); err == nil {
		t.Fatal("build without staging accepted")
	}
	w.State = "staged"
	w.BuildDigest = ""
	w.PackageID = ""
	w, err = r.SaveBuildWorkspace(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	w.PackageID = "reserved-package"
	w, err = r.SaveBuildWorkspace(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"hijack", "reopen"} {
		bad := cloneWorkspace0226(w)
		if change == "hijack" {
			bad.PackageID = "other-package"
		} else {
			bad.BuildDigest = "junk"
		}
		if _, err = r.SaveBuildWorkspace(ctx, bad); err == nil {
			t.Fatalf("invalid reserved transition %s accepted", change)
		}
	}
	w.State = "built"
	w.BuildDigest = strings.Repeat("c", 64)
	finished, err := r.SaveBuildWorkspace(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.SaveBuildWorkspace(ctx, finished); !errors.Is(err, ErrImmutable) {
		t.Fatalf("built workspace mutable: %v", err)
	}
}

func TestGAWorkspaceParallelRevisionCAS0230(t *testing.T) {
	r := NewMemoryRepository("https://neverlauncher.test")
	ctx := context.Background()
	w, err := r.CreateBuildWorkspace(ctx, certificationWorkspace0230("ga-parallel"))
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var conflict atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c := cloneWorkspace0226(w)
			c.State = "staged"
			_, e := r.SaveBuildWorkspace(ctx, c)
			if e == nil {
				success.Add(1)
			} else if errors.Is(e, ErrConflict) {
				conflict.Add(1)
			} else {
				t.Errorf("unexpected write failure: %v", e)
			}
		}()
	}
	close(start)
	wg.Wait()
	if success.Load() != 1 || conflict.Load() != 15 {
		t.Fatalf("CAS failed success=%d conflicts=%d", success.Load(), conflict.Load())
	}
}
