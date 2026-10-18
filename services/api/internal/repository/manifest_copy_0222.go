package repository

import "gitflic.ru/skif4er/neverlauncher/services/api/internal/model"

// Memory repository must not return aliases to immutable release snapshots.
// The production PostgreSQL repository materializes JSON on each read;
// memory mode needs the same isolation to avoid test/dev-only bypasses.
func cloneManifest0222(m model.Manifest) model.Manifest {
	if m.ProfileSnapshot != nil {
		v := *m.ProfileSnapshot
		m.ProfileSnapshot = &v
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
		}
		m.Files = files
	}
	return m
}

func cloneRelease0222(r model.ReleaseVersion) model.ReleaseVersion {
	r.Manifest = cloneManifest0222(r.Manifest)
	return r
}
