package repository

import "gitflic.ru/skif4er/launcher/services/api/internal/model"

// Memory repository must not return aliases to immutable release snapshots.
// The production PostgreSQL repository materializes JSON on each read;
// memory mode needs the same isolation to avoid test/dev-only bypasses.
func cloneManifest0222(m model.Manifest) model.Manifest {
	if m.ComponentCatalog != nil {
		original := m.ComponentCatalog
		cloned := *original
		cloned.Components = make([]model.CatalogComponent0241, len(original.Components))
		copy(cloned.Components, original.Components)
		for i := range cloned.Components {
			cloned.Components[i].Files = append([]string(nil), original.Components[i].Files...)
			cloned.Components[i].Actions = append([]model.ComponentAction0245(nil), original.Components[i].Actions...)
			for j := range cloned.Components[i].Actions {
				cloned.Components[i].Actions[j].Args = append([]string(nil), original.Components[i].Actions[j].Args...)
			}
			cloned.Components[i].Dependencies = append([]model.ComponentRequirement0243(nil), original.Components[i].Dependencies...)
			cloned.Components[i].Conflicts = append([]model.ComponentRequirement0243(nil), original.Components[i].Conflicts...)
			if original.Components[i].Conditions != nil {
				cc := *original.Components[i].Conditions
				cc.OS = append([]string(nil), cc.OS...)
				cc.Arch = append([]string(nil), cc.Arch...)
				cc.MinecraftVersions = append([]string(nil), cc.MinecraftVersions...)
				cc.Loaders = append([]string(nil), cc.Loaders...)
				cc.Permissions = append([]string(nil), cc.Permissions...)
				cloned.Components[i].Conditions = &cc
			}
			if original.Components[i].Visible != nil {
				b := *original.Components[i].Visible
				cloned.Components[i].Visible = &b
			}
			if original.Components[i].Metadata != nil {
				cloned.Components[i].Metadata = make(map[string]string, len(original.Components[i].Metadata))
				for k, v := range original.Components[i].Metadata {
					cloned.Components[i].Metadata[k] = v
				}
			}
		}
		cloned.Categories = append([]model.CatalogCategory0242(nil), original.Categories...)
		cloned.Groups = append([]model.CatalogGroup0242(nil), original.Groups...)
		cloned.Presets = append([]model.CatalogPreset0242(nil), original.Presets...)
		for i := range cloned.Presets {
			cloned.Presets[i].Components = append([]string(nil), original.Presets[i].Components...)
		}
		m.ComponentCatalog = &cloned
	}
	if m.ProfileSnapshot != nil {
		v := *m.ProfileSnapshot
		m.ProfileSnapshot = &v
	}
	if m.RollbackSource != nil {
		v := *m.RollbackSource
		m.RollbackSource = &v
	}
	if m.Signature != nil {
		v := *m.Signature
		m.Signature = &v
	}
	m.Minecraft.GameArgs = append([]string(nil), m.Minecraft.GameArgs...)
	m.Runtime.JVMArgs = append([]string(nil), m.Runtime.JVMArgs...)
	m.Runtime.Launch.ClasspathEntries = append([]string(nil), m.Runtime.Launch.ClasspathEntries...)
	m.Runtime.Launch.ModulepathEntries = append([]string(nil), m.Runtime.Launch.ModulepathEntries...)
	m.Runtime.Launch.EnvironmentAllowlist = append([]string(nil), m.Runtime.Launch.EnvironmentAllowlist...)
	if m.Runtime.Launch.Features != nil {
		copy := make(map[string]bool, len(m.Runtime.Launch.Features))
		for k, v := range m.Runtime.Launch.Features {
			copy[k] = v
		}
		m.Runtime.Launch.Features = copy
	}
	if m.FileRules != nil {
		m.FileRules = append([]model.FileRule(nil), m.FileRules...)
	}
	if m.Files != nil {
		files := make([]model.ManifestFile, len(m.Files))
		copy(files, m.Files)
		for i := range files {
			files[i].TargetOS = append([]string(nil), files[i].TargetOS...)
			files[i].Mirrors = append([]string(nil), files[i].Mirrors...)
		}
		m.Files = files
	}
	return m
}

func cloneRelease0222(r model.ReleaseVersion) model.ReleaseVersion {
	r.Manifest = cloneManifest0222(r.Manifest)
	return r
}
