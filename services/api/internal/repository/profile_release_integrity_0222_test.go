package repository

import (
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"testing"
)

func TestMemoryReleaseSnapshotPinnedThroughAllMutations0222(t *testing.T) {
	r := NewMemoryRepository("https://launcher.example")
	release, err := r.CreateVersion("demo-project", "vanilla", "beta", "integrity-0222")
	if err != nil {
		t.Fatal(err)
	}
	frozen := *release.Manifest.ProfileSnapshot
	// A caller must not mutate a stored release via the pointer returned by CreateVersion.
	release.Manifest.ProfileSnapshot.Revision = 123
	current, _ := r.ListVersions("demo-project")
	var draft model.ReleaseVersion
	for _, v := range current {
		if v.ID == release.ID {
			draft = v
		}
	}
	if draft.Manifest.ProfileSnapshot == nil || *draft.Manifest.ProfileSnapshot != frozen {
		t.Fatal("CreateVersion leaked mutable snapshot pointer")
	}
	// Legitimate draft metadata edit preserves the pinned revision.
	draft.Manifest.Minecraft.Version = "1.21.1"
	saved, err := r.UpdateVersionManifest(draft.ProjectID, draft.ID, draft.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if *saved.Manifest.ProfileSnapshot != frozen {
		t.Fatal("valid metadata update unpinned the snapshot")
	}
	newer := frozen
	newer.Revision++
	changed := saved.Manifest
	changed.ProfileSnapshot = &newer
	if _, err := r.UpdateVersionManifest(draft.ProjectID, draft.ID, changed); err == nil {
		t.Fatal("snapshot revision injection accepted")
	}
	if _, err := r.PublishVersionWithManifest(draft.ProjectID, draft.ProfileID, draft.Channel, draft.Version, changed); err == nil {
		t.Fatal("publish substituted a different snapshot")
	}
	// An unrelated profile change has no effect on the frozen draft.
	profiles, _ := r.ListProfiles("demo-project")
	for _, p := range profiles {
		if p.ID == "vanilla" {
			p.Name = "Renamed"
			if _, err := r.SaveProfile(p); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	saved, err = r.PublishVersionWithManifest(draft.ProjectID, draft.ProfileID, draft.Channel, draft.Version, saved.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if *saved.Manifest.ProfileSnapshot != frozen {
		t.Fatal("published snapshot changed")
	}
	published, err := r.GetManifest("demo-project", "vanilla", "beta")
	if err != nil {
		t.Fatal(err)
	}
	published.ProfileSnapshot.Spec.Name = "injected"
	current, _ = r.ListVersions("demo-project")
	for _, v := range current {
		if v.ID == release.ID {
			if *v.Manifest.ProfileSnapshot != frozen {
				t.Fatal("public read mutated stored manifest")
			}
			v.Manifest.ProfileSnapshot.Revision = 10
		}
	}
	again, err := r.GetManifest("demo-project", "vanilla", "beta")
	if err != nil || *again.ProfileSnapshot != frozen {
		t.Fatal("ListVersions leaked mutable snapshot pointer")
	}
}
