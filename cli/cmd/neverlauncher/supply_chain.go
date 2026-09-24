package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type sbomPackage struct {
	SPDXID           string              `json:"SPDXID"`
	Name             string              `json:"name"`
	VersionInfo      string              `json:"versionInfo"`
	DownloadLocation string              `json:"downloadLocation"`
	FilesAnalyzed    bool                `json:"filesAnalyzed"`
	LicenseConcluded string              `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string              `json:"licenseDeclared,omitempty"`
	ExternalRefs     []map[string]string `json:"externalRefs,omitempty"`
}

type sbomRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func dependencySBOM(sourceRoot, ver string) (map[string]any, error) {
	var err error
	sourceRoot, err = resolveRepositoryRoot(sourceRoot)
	if err != nil {
		return nil, err
	}
	packages := []sbomPackage{}
	relationships := []sbomRelationship{}
	seen := map[string]string{}
	add := func(ecosystem, name, ver, license, resolved, parent string) {
		name, ver = strings.TrimSpace(name), strings.TrimSpace(ver)
		if name == "" || ver == "" {
			return
		}
		key := ecosystem + "|" + name + "|" + ver
		id, ok := seen[key]
		if !ok {
			digest := sha256.Sum256([]byte(key))
			id = "SPDXRef-Dep-" + hex.EncodeToString(digest[:8])
			seen[key] = id
			download := resolved
			if download == "" {
				download = "NOASSERTION"
			}
			if license == "" {
				license = "NOASSERTION"
			}
			purlName := strings.ReplaceAll(name, "@", "%40")
			packages = append(packages, sbomPackage{SPDXID: id, Name: name, VersionInfo: ver, DownloadLocation: download, FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: license, ExternalRefs: []map[string]string{{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:" + ecosystem + "/" + purlName + "@" + ver}}})
		}
		if parent != "" {
			relationships = append(relationships, sbomRelationship{SPDXElementID: parent, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: id})
		}
	}

	roots := []struct{ ID, Name string }{
		{"SPDXRef-Package-CLI", "neverlauncher-cli"}, {"SPDXRef-Package-BackendAPI", "neverlauncher-api"},
		{"SPDXRef-Package-Admin", "neverlauncher-admin-web"}, {"SPDXRef-Package-Desktop", "neverlauncher-desktop"},
		{"SPDXRef-Package-NeverRuntime", "neverruntime"}, {"SPDXRef-Package-Bridges", "neverlauncher-server-bridges"},
	}
	for _, root := range roots {
		packages = append(packages, sbomPackage{SPDXID: root.ID, Name: root.Name, VersionInfo: ver, DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "Apache-2.0", LicenseDeclared: "Apache-2.0"})
		relationships = append(relationships, sbomRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: root.ID})
	}
	for _, spec := range []struct{ path, parent string }{{"cli/go.mod", "SPDXRef-Package-CLI"}, {"services/api/go.mod", "SPDXRef-Package-BackendAPI"}} {
		deps, err := parseGoMod(filepath.Join(sourceRoot, spec.path))
		if err != nil {
			return nil, err
		}
		for _, d := range deps {
			add("golang", d[0], d[1], "", "", spec.parent)
		}
	}
	for _, spec := range []struct{ path, parent string }{{"apps/admin/package-lock.json", "SPDXRef-Package-Admin"}, {"apps/desktop/package-lock.json", "SPDXRef-Package-Desktop"}} {
		deps, err := parseNPMLock(filepath.Join(sourceRoot, spec.path))
		if err != nil {
			return nil, err
		}
		for _, d := range deps {
			add("npm", d.Name, d.Version, d.License, d.Resolved, spec.parent)
		}
	}
	for _, spec := range []struct{ path, parent string }{{"apps/desktop/src-tauri/Cargo.toml", "SPDXRef-Package-Desktop"}, {"runtime/neverruntime/Cargo.toml", "SPDXRef-Package-NeverRuntime"}} {
		tomlPath := filepath.Join(sourceRoot, spec.path)
		lockPath := filepath.Join(filepath.Dir(tomlPath), "Cargo.lock")
		if _, statErr := os.Stat(lockPath); statErr == nil {
			deps, err := parseCargoLock(lockPath)
			if err != nil {
				return nil, err
			}
			for _, d := range deps {
				if d[0] != "neverlauncher-desktop" && d[0] != "neverruntime" {
					add("cargo", d[0], d[1], "", "", spec.parent)
				}
			}
		} else {
			deps, err := parseCargoToml(tomlPath)
			if err != nil {
				return nil, err
			}
			for _, d := range deps {
				add("cargo", d[0], d[1], "", "", spec.parent)
			}
		}
	}
	gradleFiles, _ := filepath.Glob(filepath.Join(sourceRoot, "plugins", "*-bridge", "build.gradle.kts"))
	gradleFiles = append(gradleFiles, filepath.Join(sourceRoot, "plugins", "bridge-common", "build.gradle.kts"))
	for _, path := range gradleFiles {
		deps, err := parseGradleDependencies(path)
		if err != nil {
			return nil, err
		}
		for _, d := range deps {
			add("maven", d[0]+"/"+d[1], d[2], "", "", "SPDXRef-Package-Bridges")
		}
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].VersionInfo < packages[j].VersionInfo
		}
		return packages[i].Name < packages[j].Name
	})
	sort.Slice(relationships, func(i, j int) bool {
		a, b := relationships[i], relationships[j]
		if a.SPDXElementID == b.SPDXElementID {
			return a.RelatedSPDXElement < b.RelatedSPDXElement
		}
		return a.SPDXElementID < b.SPDXElementID
	})
	return map[string]any{
		"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "name": "NeverLauncher " + ver,
		"documentNamespace": "https://neverlauncher.local/spdx/" + strings.ReplaceAll(ver, "/", "-") + "/" + time.Now().UTC().Format("20060102T150405.000000000Z"),
		"creationInfo":      map[string]any{"created": time.Now().UTC().Format(time.RFC3339Nano), "creators": []string{"Tool: NeverLauncher CLI " + version}},
		"packages":          packages, "relationships": relationships,
		"dependencyResolution": map[string]any{"go": "go.mod direct+indirect requirements", "npm": "package-lock.json complete package graph", "cargo": "Cargo.lock complete graph when present; Cargo.toml declared dependencies otherwise", "gradle": "declared Maven coordinates in build.gradle.kts"},
	}, nil
}

type npmLockEntry struct{ Name, Version, License, Resolved string }

func parseNPMLock(path string) ([]npmLockEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			License  string `json:"license"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	out := []npmLockEntry{}
	for key, v := range lock.Packages {
		if key == "" || !strings.HasPrefix(key, "node_modules/") || v.Version == "" {
			continue
		}
		name := strings.TrimPrefix(key, "node_modules/")
		out = append(out, npmLockEntry{Name: name, Version: v.Version, License: v.License, Resolved: v.Resolved})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func parseGoMod(path string) ([][2]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][2]string
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.Split(sc.Text(), "//")[0])
		if line == "" {
			continue
		}
		if line == "require (" {
			in = true
			continue
		}
		if in && line == ")" {
			in = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !in {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out = append(out, [2]string{fields[0], fields[1]})
		}
	}
	return out, sc.Err()
}

func parseCargoToml(path string) ([][2]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	section := ""
	out := [][2]string{}
	versionRe := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = t
			continue
		}
		if section != "[dependencies]" && section != "[build-dependencies]" {
			continue
		}
		if t == "" || strings.HasPrefix(t, "#") || !strings.Contains(t, "=") {
			continue
		}
		parts := strings.SplitN(t, "=", 2)
		name := strings.TrimSpace(parts[0])
		rhs := strings.TrimSpace(parts[1])
		if strings.Contains(rhs, "path =") {
			continue
		}
		ver := ""
		if strings.HasPrefix(rhs, "\"") {
			ver = strings.Trim(rhs, "\"")
		} else if m := versionRe.FindStringSubmatch(rhs); len(m) == 2 {
			ver = m[1]
		}
		if ver != "" {
			out = append(out, [2]string{name, ver})
		}
	}
	return out, nil
}

func parseCargoLock(path string) ([][2]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	name, ver := "", ""
	flush := func() {
		if name != "" && ver != "" {
			out = append(out, [2]string{name, ver})
		}
		name, ver = "", ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(t, "name = ") {
			name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "name = ")), "\"")
		}
		if strings.HasPrefix(t, "version = ") {
			ver = strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "version = ")), "\"")
		}
	}
	flush()
	return out, nil
}

func parseGradleDependencies(path string) ([][3]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?:implementation|api|compileOnly|runtimeOnly)\("([^:"]+):([^:"]+):([^"\)]+)"\)`)
	out := [][3]string{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		out = append(out, [3]string{m[1], m[2], m[3]})
	}
	return out, nil
}

func slsaProvenance(sourceRoot, artifactDir, ver string) (map[string]any, error) {
	var rootErr error
	sourceRoot, rootErr = resolveRepositoryRoot(sourceRoot)
	if rootErr != nil {
		return nil, rootErr
	}
	subjects := []map[string]any{}
	if artifactDir != "" {
		entries, err := os.ReadDir(artifactDir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || e.Name() == "PROVENANCE.json" || strings.HasSuffix(e.Name(), ".sig") {
				continue
			}
			sum, _, err := hashFile(filepath.Join(artifactDir, e.Name()))
			if err != nil {
				return nil, err
			}
			subjects = append(subjects, map[string]any{"name": e.Name(), "digest": map[string]string{"sha256": sum}})
		}
	}
	sort.Slice(subjects, func(i, j int) bool { return fmt.Sprint(subjects[i]["name"]) < fmt.Sprint(subjects[j]["name"]) })
	materialPaths := []string{
		"VERSION",
		"cli/go.mod",
		"services/api/go.mod",
		"apps/admin/package-lock.json", "apps/desktop/package-lock.json",
		"apps/desktop/src-tauri/Cargo.toml", "runtime/neverruntime/Cargo.toml",
		"settings.gradle.kts",
		"plugins/bridge-common/build.gradle.kts", "plugins/proxy-family-common/build.gradle.kts", "plugins/bungee-family-common/build.gradle.kts", "plugins/bukkit-family-common/build.gradle.kts", "plugins/velocity-bridge/build.gradle.kts",
		"plugins/bungeecord-bridge/build.gradle.kts", "plugins/waterfall-bridge/build.gradle.kts", "plugins/bukkit-bridge/build.gradle.kts", "plugins/spigot-bridge/build.gradle.kts", "plugins/paper-bridge/build.gradle.kts",
		"plugins/purpur-bridge/build.gradle.kts", "plugins/folia-bridge/build.gradle.kts", "plugins/fabric-bridge/build.gradle.kts",
	}
	for _, rel := range []string{"cli/go.sum", "services/api/go.sum", "apps/desktop/src-tauri/Cargo.lock", "runtime/neverruntime/Cargo.lock"} {
		if st, err := os.Stat(filepath.Join(sourceRoot, rel)); err == nil && !st.IsDir() {
			materialPaths = append(materialPaths, rel)
		}
	}
	materials := []map[string]any{}
	for _, rel := range materialPaths {
		p := filepath.Join(sourceRoot, rel)
		sum, _, err := hashFile(p)
		if err != nil {
			return nil, fmt.Errorf("provenance material %s: %w", rel, err)
		}
		materials = append(materials, map[string]any{"uri": "file://" + filepath.ToSlash(rel), "digest": map[string]string{"sha256": sum}})
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "subject": subjects, "predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{"buildType": "https://neverlauncher.local/build-types/production-release/v1", "externalParameters": map[string]any{"version": ver}, "internalParameters": map[string]any{"toolVersion": version, "failClosed": true}, "resolvedDependencies": materials},
			"runDetails":      map[string]any{"builder": map[string]any{"id": "https://neverlauncher.local/builders/cli-release/" + version}, "metadata": map[string]any{"invocationId": "release-" + ver + "-" + time.Now().UTC().Format("20060102T150405.000000000Z"), "startedOn": now, "finishedOn": now}},
		},
	}, nil
}

func resolveRepositoryRoot(candidate string) (string, error) {
	start, err := filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return "", err
	}
	for i := 0; i < 6; i++ {
		if st, err := os.Stat(filepath.Join(start, "cli", "go.mod")); err == nil && !st.IsDir() {
			if st2, err2 := os.Stat(filepath.Join(start, "VERSION")); err2 == nil && !st2.IsDir() {
				return start, nil
			}
		}
		next := filepath.Dir(start)
		if next == start {
			break
		}
		start = next
	}
	return "", fmt.Errorf("не найден корень NeverLauncher repository от %s", candidate)
}
