package model

import "testing"

func TestReleaseManifestTransition0222(t *testing.T) {
	profile, err := NormalizeProfileV2(Profile{ProjectID: "project", ID: "main", Name: "Original", Loader: "vanilla", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := SnapshotProfile(profile)
	original := Manifest{SchemaVersion: ManifestSchemaV2, ProjectID: profile.ProjectID, ProfileID: profile.ID, Channel: "stable", Version: "1", Files: []ManifestFile{}, ProfileSnapshot: &snapshot}
	candidate := original
	candidate.CreatedAt = "2026-10-18T10:00:00Z"
	candidate.Files = []ManifestFile{{Path: "mods/example.jar", SHA256: "00", Size: 2}}
	if err := ValidateReleaseManifestTransition(original, candidate); err != nil {
		t.Fatalf("safe draft update rejected: %v", err)
	}
	mutated := candidate
	newRevision := snapshot
	newRevision.Revision++ // valid digest, but NOT the revision pinned to this draft
	mutated.ProfileSnapshot = &newRevision
	if err := ValidateReleaseManifestTransition(original, mutated); err == nil {
		t.Fatal("different valid revision accepted")
	}
	newSpec := snapshot
	newSpec.Spec.Name = "Edited"
	newSpec.Digest = ProfileDigest(newSpec.Spec)
	mutated.ProfileSnapshot = &newSpec
	if err := ValidateReleaseManifestTransition(original, mutated); err == nil {
		t.Fatal("different valid spec accepted")
	}
	mutated = candidate
	mutated.SchemaVersion = "1.0"
	mutated.ProfileSnapshot = nil
	if err := ValidateReleaseManifestTransition(original, mutated); err == nil {
		t.Fatal("v2 downgrade accepted")
	}
	mutated = candidate
	mutated.Version = "2"
	if err := ValidateReleaseManifestTransition(original, mutated); err == nil {
		t.Fatal("release identity change accepted")
	}
	legacy := Manifest{SchemaVersion: "1.0", ProjectID: "project", ProfileID: "main", Channel: "stable", Version: "legacy", Files: []ManifestFile{}}
	updated := legacy
	updated.Files = []ManifestFile{{Path: "test"}}
	if err := ValidateReleaseManifestTransition(legacy, updated); err != nil {
		t.Fatalf("legacy draft update rejected: %v", err)
	}
	updated.SchemaVersion = "2.0"
	updated.ProfileSnapshot = &snapshot
	if err := ValidateReleaseManifestTransition(legacy, updated); err == nil {
		t.Fatal("silent v1 upgrade accepted")
	}
}
