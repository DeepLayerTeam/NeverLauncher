package model

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const PortableProfileFormat0225 = "launcher.profile.v1"

// PortableProfile0225 deliberately exports ONLY the immutable public ProfileSpec.
// Release signatures, access rights, credentials and project roles cannot be exported.
type PortableProfile0225 struct {
	Format   string          `json:"format"`
	Snapshot ProfileSnapshot `json:"snapshot"`
}

func ExportProfile0225(snapshot ProfileSnapshot) (PortableProfile0225, error) {
	if err := ValidateProfileSnapshot(snapshot, snapshot.Spec.ProjectID, snapshot.Spec.ID); err != nil {
		return PortableProfile0225{}, err
	}
	return PortableProfile0225{Format: PortableProfileFormat0225, Snapshot: snapshot}, nil
}

var profileID0225 = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// CreateFromSnapshot0225 constructs a new, unprivileged profile. Its identity and
// revision are never copied; callers MUST persist it with exclusive-create.
func CreateFromSnapshot0225(source ProfileSnapshot, projectID, newID, newName string) (Profile, error) {
	if err := ValidateProfileSnapshot(source, source.Spec.ProjectID, source.Spec.ID); err != nil {
		return Profile{}, fmt.Errorf("source snapshot: %w", err)
	}
	newID = strings.TrimSpace(newID)
	newName = strings.TrimSpace(newName)
	if !profileID0225.MatchString(newID) || newID == "." || newID == ".." {
		return Profile{}, errors.New("destination profile ID must be 1-64 lowercase letters/digits/dot/underscore/hyphen")
	}
	if newName == "" || len(newName) > 120 || len(source.Spec.Description) > 4096 {
		return Profile{}, errors.New("invalid destination profile name or description length")
	}
	p := Profile{ProjectID: projectID, ID: newID, Name: newName, Description: source.Spec.Description,
		Loader: source.Spec.Loader, MinecraftVersion: source.Spec.MinecraftVersion, LoaderVersion: source.Spec.LoaderVersion, JavaMajor: source.Spec.JavaMajor, Preset: source.Spec.Preset, IsDefault: false}
	return NormalizeProfileV2(p)
}

func ImportProfile0225(bundle PortableProfile0225, projectID, newID, newName string) (Profile, error) {
	if bundle.Format != PortableProfileFormat0225 {
		return Profile{}, fmt.Errorf("unsupported profile export format %q", bundle.Format)
	}
	return CreateFromSnapshot0225(bundle.Snapshot, projectID, newID, newName)
}

type ProfileFieldChange0225 struct {
	Field string `json:"field"`
	From  any    `json:"from"`
	To    any    `json:"to"`
}

type ProfileDifference0225 struct {
	From    ProfileSnapshot          `json:"from"`
	To      ProfileSnapshot          `json:"to"`
	Changes []ProfileFieldChange0225 `json:"changes"`
	Equal   bool                     `json:"equal"`
}

// DiffProfile0225 compares actual stored revisions, rather than mutable heads.
func DiffProfile0225(from, to ProfileSnapshot) (ProfileDifference0225, error) {
	for _, snap := range []ProfileSnapshot{from, to} {
		if err := ValidateProfileSnapshot(snap, snap.Spec.ProjectID, snap.Spec.ID); err != nil {
			return ProfileDifference0225{}, err
		}
	}
	out := ProfileDifference0225{From: from, To: to, Changes: []ProfileFieldChange0225{}}
	compare := func(field string, old, next any) {
		if old != next {
			out.Changes = append(out.Changes, ProfileFieldChange0225{Field: field, From: old, To: next})
		}
	}
	compare("projectId", from.Spec.ProjectID, to.Spec.ProjectID)
	compare("id", from.Spec.ID, to.Spec.ID)
	compare("name", from.Spec.Name, to.Spec.Name)
	compare("description", from.Spec.Description, to.Spec.Description)
	compare("loader", from.Spec.Loader, to.Spec.Loader)
	compare("minecraftVersion", from.Spec.MinecraftVersion, to.Spec.MinecraftVersion)
	compare("loaderVersion", from.Spec.LoaderVersion, to.Spec.LoaderVersion)
	compare("javaMajor", from.Spec.JavaMajor, to.Spec.JavaMajor)
	compare("preset", from.Spec.Preset, to.Spec.Preset)
	compare("isDefault", from.Spec.IsDefault, to.Spec.IsDefault)
	out.Equal = len(out.Changes) == 0
	return out, nil
}

type ProfilePreset0225 struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Loader      string `json:"loader"`
	Preset      string `json:"preset"`
}

var builtInProfilePresets0225 = []ProfilePreset0225{
	{"vanilla", "Vanilla", "Официальный клиент без модифицированного загрузчика", "vanilla", "custom"},
	{"fabric", "Fabric", "Клиент с загрузчиком Fabric", "fabric", "custom"},
	{"quilt", "Quilt", "Клиент с загрузчиком Quilt", "quilt", "custom"},
	{"forge", "Forge", "Клиент с загрузчиком Forge", "forge", "custom"},
	{"neoforge", "NeoForge", "Клиент с загрузчиком NeoForge", "neoforge", "custom"},
	{"vanilla-lite", "Vanilla Lite", "Облегчённый пресет Vanilla", "vanilla", "lite"},
}

func ListProfilePresets0225() []ProfilePreset0225 {
	out := append([]ProfilePreset0225(nil), builtInProfilePresets0225...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func CreateFromPreset0225(projectID, id, name, presetID string) (Profile, error) {
	for _, preset := range builtInProfilePresets0225 {
		if preset.ID == presetID {
			spec := ProfileSpec{ProjectID: projectID, ID: "_preset", Name: preset.Name, Description: preset.Description, Loader: preset.Loader, Preset: preset.Preset}
			snap := ProfileSnapshot{SchemaVersion: ProfileSchemaV2, Revision: 1, Spec: spec, Digest: ProfileDigest(spec)}
			if name == "" {
				name = preset.Name
			}
			return CreateFromSnapshot0225(snap, projectID, id, name)
		}
	}
	return Profile{}, fmt.Errorf("unknown profile preset %q", presetID)
}
