package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestProfileVersionAndReleaseSnapshot0221(t *testing.T) {
	r := NewMemoryRepository("http://localhost")
	profiles, err := r.ListProfiles("demo-project")
	if err != nil {
		t.Fatal(err)
	}
	var p model.Profile
	for _, item := range profiles {
		if item.ID == "vanilla" {
			p = item
		}
	}
	if p.Revision != 1 {
		t.Fatalf("unexpected legacy revision: %+v", p)
	}
	release, err := r.CreateVersion("demo-project", "vanilla", "beta", "profile-0221")
	if err != nil {
		t.Fatal(err)
	}
	if release.Manifest.SchemaVersion != "2.0" || release.Manifest.ProfileSnapshot == nil {
		t.Fatal("draft has no immutable v2 snapshot")
	}
	old := *release.Manifest.ProfileSnapshot
	p.Name = "Renamed"
	saved, err := r.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 2 || saved.Digest == old.Digest {
		t.Fatal("profile edit did not create revision")
	}
	history, err := r.ListProfileRevisions("demo-project", "vanilla")
	if err != nil || len(history) != 2 {
		t.Fatalf("history %v: %v", history, err)
	}
	if history[0].Digest != old.Digest {
		t.Fatal("old history rewritten")
	}
	versions, _ := r.ListVersions("demo-project")
	for _, v := range versions {
		if v.ID == release.ID && v.Manifest.ProfileSnapshot.Digest != old.Digest {
			t.Fatal("release snapshot changed")
		}
	}
	p.Revision = 1
	p.Name = "stale update"
	if _, err := r.SaveProfile(p); err != ErrConflict {
		t.Fatalf("expected CAS conflict got %v", err)
	}
	saved.Name = "Renamed"
	same, err := r.SaveProfile(saved)
	if err != nil || same.Revision != 2 {
		t.Fatal("no-op edited revision")
	}
	if _, err := r.GetManifest("demo-project", "vanilla", "beta"); err != ErrNotFound {
		t.Fatalf("draft leaked in public manifest: %v", err)
	}
}
