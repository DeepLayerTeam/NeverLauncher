package model

import (
	"encoding/json"
	"testing"
)

func profileFixture0225() ProfileSnapshot {
	p := Profile{ID: "modpack", ProjectID: "alpha", Name: "Original", Loader: "fabric", Preset: "recommended", IsDefault: true, Revision: 5}
	return SnapshotProfile(p)
}

func TestProfilePortableRoundtripAndIsolation0225(t *testing.T) {
	source := profileFixture0225()
	bundle, err := ExportProfile0225(source)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" {
		t.Fatal("empty export")
	}
	var decoded PortableProfile0225
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	newP, err := ImportProfile0225(decoded, "other-project", "copy", "Copy")
	if err != nil {
		t.Fatal(err)
	}
	if newP.ID != "copy" || newP.ProjectID != "other-project" || newP.Loader != "fabric" || newP.IsDefault || newP.Revision != 0 || newP.Digest == source.Digest {
		t.Fatalf("import did not reset inherited identity/default/revision: %+v", newP)
	}
	if newP.Name != "Copy" || newP.Description != source.Spec.Description || newP.Preset != source.Spec.Preset {
		t.Fatal("important public metadata lost")
	}
	decoded.Snapshot.Spec.Loader = "forge"
	if _, err := ImportProfile0225(decoded, "other-project", "tampered", "Tampered"); err == nil {
		t.Fatal("tampered digest accepted")
	}
	decoded.Snapshot = source
	decoded.Format = "unknown"
	if _, err := ImportProfile0225(decoded, "other-project", "invalid", "Bad"); err == nil {
		t.Fatal("unsupported export format accepted")
	}
}

func TestProfileCreationValidationAndDiff0225(t *testing.T) {
	source := profileFixture0225()
	for _, id := range []string{"../escape", "has space", "", "UPPER"} {
		if _, err := CreateFromSnapshot0225(source, "target", id, "Name"); err == nil {
			t.Errorf("accepted dangerous ID %q", id)
		}
	}
	target := source
	target.Spec.Name = "Edited"
	target.Spec.Loader = "neoforge"
	target.Digest = ProfileDigest(target.Spec)
	target.Revision++
	diff, err := DiffProfile0225(source, target)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Equal || len(diff.Changes) != 2 || diff.Changes[0].Field != "name" || diff.Changes[1].Field != "loader" {
		t.Fatalf("wrong stable diff: %+v", diff)
	}
	if d, err := DiffProfile0225(source, source); err != nil || !d.Equal || len(d.Changes) != 0 {
		t.Fatalf("same revision mismatch %v: %+v", err, d)
	}
	target.Digest = "tampered"
	if _, err := DiffProfile0225(source, target); err == nil {
		t.Fatal("invalid revision accepted")
	}
}

func TestPresetProfilesProduceValidIndependentRecords0225(t *testing.T) {
	presets := ListProfilePresets0225()
	if len(presets) < 5 {
		t.Fatal("missing supported loader presets")
	}
	for _, v := range presets {
		p, err := CreateFromPreset0225("alpha", "fresh-profile", "", v.ID)
		if err != nil {
			t.Fatal(v.ID, err)
		}
		if p.Loader != v.Loader || p.IsDefault || p.Revision != 0 || p.Name == "" {
			t.Fatalf("invalid preset %s: %+v", v.ID, p)
		}
	}
	if _, err := CreateFromPreset0225("alpha", "bad", "", "unsupported"); err == nil {
		t.Fatal("unknown preset accepted")
	}
}
