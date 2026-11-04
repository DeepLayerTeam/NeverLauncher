package repository

import (
	"errors"
	"sync"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestExclusiveProfileCreationAndHistory0225(t *testing.T) {
	r := NewMemoryRepository("http://localhost")
	snap, err := ReadProfileSnapshot(r, "demo-project", "vanilla")
	if err != nil {
		t.Fatal(err)
	}
	p, err := model.CreateFromSnapshot0225(snap, "demo-project", "vanilla-copy", "Copy")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := r.CreateProfileExclusive0225(p)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Revision != 1 || actual.IsDefault || actual.Digest != model.ProfileDigest(model.ProfileSpecOf(actual)) {
		t.Fatalf("invalid first revision: %+v", actual)
	}
	if _, err := r.CreateProfileExclusive0225(p); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate conflict: %v", err)
	}
	history, err := r.ListProfileRevisions("demo-project", "vanilla-copy")
	if err != nil || len(history) != 1 || history[0].Digest != actual.Digest {
		t.Fatalf("missing revision: %v %+v", err, history)
	}
	if _, err := r.CreateProfileExclusive0225(model.Profile{ProjectID: "missing", ID: "other", Name: "Test", Loader: "vanilla"}); err == nil {
		t.Fatal("unknown project accepted")
	}
	// A clone is standalone; modifying the original cannot rewrite its first snapshot.
	original, err := r.ListProfiles("demo-project")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range original {
		if v.ID == "vanilla" {
			v.Name = "Renamed original"
			if _, err := r.SaveProfile(v); err != nil {
				t.Fatal(err)
			}
		}
	}
	old, err := ReadProfileSnapshot(r, "demo-project", "vanilla-copy")
	if err != nil || old.Spec.Name != "Copy" {
		t.Fatalf("clone mutated with source %v %+v", err, old)
	}
}

func TestConcurrentExclusiveProfileCreation0225(t *testing.T) {
	r := NewMemoryRepository("http://localhost")
	p := model.Profile{ProjectID: "demo-project", ID: "race", Name: "Race", Loader: "vanilla", IsDefault: true}
	const workers = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, conflicts := 0, 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.CreateProfileExclusive0225(p)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || conflicts != workers-1 {
		t.Fatalf("exclusive creation: success=%d conflicts=%d", successes, conflicts)
	}
	found, _ := r.ListProfiles("demo-project")
	for _, item := range found {
		if item.ID == "race" && item.IsDefault {
			t.Fatal("new profile inherited default role")
		}
	}
	history, err := r.ListProfileRevisions("demo-project", "race")
	if err != nil || len(history) != 1 {
		t.Fatalf("duplicate revisions %v %+v", err, history)
	}
}
