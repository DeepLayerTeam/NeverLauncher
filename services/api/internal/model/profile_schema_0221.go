package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const ProfileSchemaV2 = "2.0"
const ManifestSchemaV2 = "2.0"

// ProfileSpec is the immutable launch-profile metadata covered by a revision digest.
// User-facing/volatile createdAt and updatedAt are intentionally excluded.
type ProfileSpec struct {
	ProjectID   string `json:"projectId"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Loader      string `json:"loader"`
	Preset      string `json:"preset"`
	IsDefault   bool   `json:"isDefault"`
}

// ProfileSnapshot is copied into a new v2 release when it is created.
// It MUST NOT change when the mutable profile is edited later.
type ProfileSnapshot struct {
	SchemaVersion string      `json:"schemaVersion"`
	Revision      int64       `json:"revision"`
	Digest        string      `json:"digest"`
	Spec          ProfileSpec `json:"spec"`
}

func ProfileSpecOf(p Profile) ProfileSpec {
	return ProfileSpec{ProjectID: p.ProjectID, ID: p.ID, Name: p.Name, Description: p.Description, Loader: p.Loader, Preset: p.Preset, IsDefault: p.IsDefault}
}

// ProfileDigest has the same binary representation in Go and PostgreSQL migration 0056.
// NUL separators make combinations of fields unambiguous; NUL is not valid in PostgreSQL text.
func ProfileDigest(s ProfileSpec) string {
	fields := []string{s.ProjectID, s.ID, s.Name, s.Description, s.Loader, s.Preset, fmt.Sprint(s.IsDefault)}
	digest := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(digest[:])
}

func SnapshotProfile(p Profile) ProfileSnapshot {
	spec := ProfileSpecOf(p)
	return ProfileSnapshot{SchemaVersion: ProfileSchemaV2, Revision: p.Revision, Digest: ProfileDigest(spec), Spec: spec}
}

func ValidateProfileSnapshot(s ProfileSnapshot, projectID, profileID string) error {
	if s.SchemaVersion != ProfileSchemaV2 || s.Revision < 1 || s.Spec.ProjectID != projectID || s.Spec.ID != profileID || s.Spec.Name == "" || s.Spec.Loader == "" {
		return errors.New("invalid v2 profile snapshot identity or revision")
	}
	if s.Digest != ProfileDigest(s.Spec) {
		return errors.New("v2 profile snapshot digest mismatch")
	}
	return nil
}

func ValidateManifestSchema(m Manifest) error {
	switch m.SchemaVersion {
	case "1.0":
		if m.ProfileSnapshot != nil {
			return errors.New("v1 manifests cannot contain a v2 profile snapshot")
		}
	case ManifestSchemaV2:
		if m.ProfileSnapshot == nil {
			return errors.New("v2 manifest requires a profile snapshot")
		}
		if err := ValidateProfileSnapshot(*m.ProfileSnapshot, m.ProjectID, m.ProfileID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported manifest schema %q", m.SchemaVersion)
	}
	if m.SchemaVersion == ManifestSchemaV2 {
		if err := ValidateRuntimeConstraints0223(m); err != nil {
			return err
		}
		if err := ValidateFileOwnership0224(m); err != nil {
			return err
		}
	}
	return nil
}

func NormalizeProfileV2(p Profile) (Profile, error) {
	if p.SchemaVersion != "" && p.SchemaVersion != ProfileSchemaV2 {
		return Profile{}, fmt.Errorf("unsupported profile schema %q", p.SchemaVersion)
	}
	p.SchemaVersion = ProfileSchemaV2
	if p.Loader == "" {
		p.Loader = "vanilla"
	}
	if p.ProjectID == "" || p.ID == "" || p.Name == "" {
		return Profile{}, errors.New("profile projectId, id and name required")
	}
	for _, v := range []string{p.ProjectID, p.ID, p.Name, p.Description, p.Loader, p.Preset} {
		if strings.ContainsRune(v, '\x00') {
			return Profile{}, errors.New("profile fields cannot contain NUL")
		}
	}
	p.Digest = ProfileDigest(ProfileSpecOf(p))
	return p, nil
}

// ValidateReleaseManifestTransition enforces the snapshot pinned when the draft
// was created. Never derive it from the current mutable profile on update/publish.
// A v1 draft can only remain v1; upgrading requires a new release identity.
func ValidateReleaseManifestTransition(existing, candidate Manifest) error {
	if err := ValidateManifestSchema(existing); err != nil {
		return fmt.Errorf("stored release manifest is invalid: %w", err)
	}
	if err := ValidateManifestSchema(candidate); err != nil {
		return err
	}
	if existing.SchemaVersion != candidate.SchemaVersion {
		return errors.New("release manifest schema is immutable; create a new release")
	}
	if existing.SchemaVersion == ManifestSchemaV2 && *existing.ProfileSnapshot != *candidate.ProfileSnapshot {
		return errors.New("release profile snapshot is immutable; create a new release")
	}
	if existing.ProjectID != candidate.ProjectID || existing.ProfileID != candidate.ProfileID || existing.Channel != candidate.Channel || existing.Version != candidate.Version {
		return errors.New("release manifest identity is immutable")
	}
	return nil
}
