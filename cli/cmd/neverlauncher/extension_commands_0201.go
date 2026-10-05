package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const canonicalExtensionManifestName0201 = "neverlauncher-extension.json"

var (
	canonicalExtensionID0201         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	canonicalExtensionSemver0201     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	canonicalExtensionPermission0201 = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{1,127}$`)
)

type CanonicalExtensionTarget0201 struct {
	Kind       string `json:"kind"`
	Entrypoint string `json:"entrypoint"`
}

type CanonicalExtensionDependency0201 struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Optional bool   `json:"optional,omitempty"`
}

type CanonicalExtensionManifest0201 struct {
	SchemaVersion string                             `json:"schemaVersion"`
	ID            string                             `json:"id"`
	Name          string                             `json:"name"`
	Version       string                             `json:"version"`
	Publisher     string                             `json:"publisher"`
	Description   string                             `json:"description,omitempty"`
	Homepage      string                             `json:"homepage,omitempty"`
	Repository    string                             `json:"repository,omitempty"`
	API           string                             `json:"api"`
	Targets       []CanonicalExtensionTarget0201     `json:"targets"`
	Permissions   []string                           `json:"permissions,omitempty"`
	Hooks         []string                           `json:"hooks,omitempty"`
	Dependencies  []CanonicalExtensionDependency0201 `json:"dependencies,omitempty"`
	Metadata      map[string]string                  `json:"metadata,omitempty"`
}

func handleExtension0201(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные extension-подкоманды: template, validate, import-legacy")
	}
	switch args[0] {
	case "template":
		target := strings.ToLower(flagValue(args, "--target", "backend"))
		if !containsString([]string{"backend", "admin", "desktop", "cli"}, target) {
			return errors.New("--target должен быть одним из: backend, admin, desktop, cli")
		}
		out := flagValue(args, "--output", canonicalExtensionManifestName0201)
		manifest := CanonicalExtensionManifest0201{
			SchemaVersion: "2.0",
			ID:            "ru.example.neverlauncher.extension",
			Name:          "Пример расширения NeverLauncher",
			Version:       "1.0.0",
			Publisher:     "Example Publisher",
			API:           "3.7",
			Targets:       []CanonicalExtensionTarget0201{{Kind: target, Entrypoint: sdkEntrypoint(target)}},
			Permissions:   []string{"release:read"},
		}
		manifest, _, err := normalizeCanonicalExtension0201(manifest)
		if err != nil {
			return err
		}
		if out == "-" {
			printJSON(manifest)
			return nil
		}
		return writeJSONFile(out, manifest)
	case "validate":
		if len(args) < 2 {
			return errors.New("extension validate требует путь к neverlauncher-extension.json или каталогу")
		}
		manifest, path, digest, err := loadCanonicalExtension0201(args[1])
		if err != nil {
			return err
		}
		printJSON(map[string]any{"valid": true, "manifest": path, "id": manifest.ID, "version": manifest.Version, "api": manifest.API, "targets": manifest.Targets, "sha256": digest})
		return nil
	case "import-legacy":
		if len(args) < 2 {
			return errors.New("extension import-legacy требует путь к neverlauncher-plugin.json или каталогу")
		}
		publisher := strings.TrimSpace(flagValue(args, "--publisher", ""))
		out := flagValue(args, "--output", canonicalExtensionManifestName0201)
		manifest, source, err := importLegacyPluginManifest0201(args[1], publisher)
		if err != nil {
			return err
		}
		if out == "-" {
			printJSON(manifest)
			return nil
		}
		if err := writeJSONFile(out, manifest); err != nil {
			return err
		}
		_, _, digest, err := loadCanonicalExtension0201(out)
		if err != nil {
			return fmt.Errorf("verify imported canonical manifest: %w", err)
		}
		printJSON(map[string]any{"imported": true, "source": source, "output": out, "id": manifest.ID, "version": manifest.Version, "sha256": digest})
		return nil
	default:
		return fmt.Errorf("неизвестная extension-подкоманда: %s", args[0])
	}
}

func canonicalExtensionManifestPath0201(path string) string {
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		return filepath.Join(path, canonicalExtensionManifestName0201)
	}
	return path
}

func loadCanonicalExtension0201(path string) (CanonicalExtensionManifest0201, string, string, error) {
	path = canonicalExtensionManifestPath0201(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return CanonicalExtensionManifest0201{}, path, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var manifest CanonicalExtensionManifest0201
	if err := dec.Decode(&manifest); err != nil {
		return CanonicalExtensionManifest0201{}, path, "", fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		return CanonicalExtensionManifest0201{}, path, "", fmt.Errorf("%s contains trailing JSON data: %w", path, err)
	}
	manifest, digest, err := normalizeCanonicalExtension0201(manifest)
	if err != nil {
		return CanonicalExtensionManifest0201{}, path, "", err
	}
	return manifest, path, digest, nil
}

func normalizeCanonicalExtension0201(m CanonicalExtensionManifest0201) (CanonicalExtensionManifest0201, string, error) {
	m.SchemaVersion = strings.TrimSpace(m.SchemaVersion)
	m.ID = strings.ToLower(strings.TrimSpace(m.ID))
	m.Name = strings.TrimSpace(m.Name)
	m.Version = strings.TrimSpace(m.Version)
	m.Publisher = strings.TrimSpace(m.Publisher)
	m.Description = strings.TrimSpace(m.Description)
	m.Homepage = strings.TrimSpace(m.Homepage)
	m.Repository = strings.TrimSpace(m.Repository)
	m.API = strings.TrimSpace(m.API)
	if m.SchemaVersion == "" {
		m.SchemaVersion = "2.0"
	}
	if m.SchemaVersion != "2.0" {
		return CanonicalExtensionManifest0201{}, "", fmt.Errorf("schemaVersion должен быть 2.0")
	}
	if !canonicalExtensionID0201.MatchString(m.ID) {
		return CanonicalExtensionManifest0201{}, "", fmt.Errorf("некорректный extension id %q", m.ID)
	}
	if m.Name == "" || len(m.Name) > 160 {
		return CanonicalExtensionManifest0201{}, "", errors.New("name обязателен и не должен превышать 160 символов")
	}
	if m.Publisher == "" || len(m.Publisher) > 160 {
		return CanonicalExtensionManifest0201{}, "", errors.New("publisher обязателен и не должен превышать 160 символов")
	}
	if !canonicalExtensionSemver0201.MatchString(m.Version) {
		return CanonicalExtensionManifest0201{}, "", fmt.Errorf("version %q должен быть semver", m.Version)
	}
	if m.API == "" || len(m.API) > 64 {
		return CanonicalExtensionManifest0201{}, "", errors.New("api обязателен")
	}
	if len(m.Targets) == 0 {
		return CanonicalExtensionManifest0201{}, "", errors.New("targets должен содержать хотя бы одну цель")
	}
	seenTargets := map[string]struct{}{}
	for i := range m.Targets {
		t := &m.Targets[i]
		t.Kind = strings.ToLower(strings.TrimSpace(t.Kind))
		t.Entrypoint = strings.TrimSpace(t.Entrypoint)
		if !containsString([]string{"backend", "admin", "desktop", "cli"}, t.Kind) {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("некорректный target %q", t.Kind)
		}
		if _, ok := seenTargets[t.Kind]; ok {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("target %q указан повторно", t.Kind)
		}
		seenTargets[t.Kind] = struct{}{}
		if t.Entrypoint == "" || filepath.IsAbs(t.Entrypoint) || strings.Contains(t.Entrypoint, "\\") {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("target %s содержит некорректный entrypoint", t.Kind)
		}
		clean := filepath.ToSlash(filepath.Clean(t.Entrypoint))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("target %s entrypoint должен быть относительным путём внутри extension", t.Kind)
		}
		t.Entrypoint = clean
	}
	sort.Slice(m.Targets, func(i, j int) bool { return m.Targets[i].Kind < m.Targets[j].Kind })

	normalizeNames := func(values []string, kind string) ([]string, error) {
		seen := map[string]struct{}{}
		out := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}
			if !canonicalExtensionPermission0201.MatchString(value) {
				return nil, fmt.Errorf("некорректный %s %q", kind, value)
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
		sort.Strings(out)
		return out, nil
	}
	var err error
	m.Permissions, err = normalizeNames(m.Permissions, "permission")
	if err != nil {
		return CanonicalExtensionManifest0201{}, "", err
	}
	m.Hooks, err = normalizeNames(m.Hooks, "hook")
	if err != nil {
		return CanonicalExtensionManifest0201{}, "", err
	}
	seenDeps := map[string]struct{}{}
	for i := range m.Dependencies {
		d := &m.Dependencies[i]
		d.ID = strings.ToLower(strings.TrimSpace(d.ID))
		d.Version = strings.TrimSpace(d.Version)
		if !canonicalExtensionID0201.MatchString(d.ID) || d.ID == m.ID {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("некорректная dependency %q", d.ID)
		}
		if d.Version == "" || len(d.Version) > 128 {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("dependency %s требует version constraint", d.ID)
		}
		if _, ok := seenDeps[d.ID]; ok {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("dependency %q указана повторно", d.ID)
		}
		seenDeps[d.ID] = struct{}{}
	}
	sort.Slice(m.Dependencies, func(i, j int) bool { return m.Dependencies[i].ID < m.Dependencies[j].ID })
	if m.Metadata == nil {
		m.Metadata = map[string]string{}
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return CanonicalExtensionManifest0201{}, "", err
	}
	sum := sha256.Sum256(canonical)
	return m, hex.EncodeToString(sum[:]), nil
}

func importLegacyPluginManifest0201(path, publisher string) (CanonicalExtensionManifest0201, string, error) {
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		path = filepath.Join(path, "neverlauncher-plugin.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return CanonicalExtensionManifest0201{}, path, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var legacy PluginManifest
	if err := dec.Decode(&legacy); err != nil {
		return CanonicalExtensionManifest0201{}, path, fmt.Errorf("decode legacy manifest %s: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		return CanonicalExtensionManifest0201{}, path, fmt.Errorf("legacy manifest %s contains trailing JSON data: %w", path, err)
	}
	publisher = strings.TrimSpace(publisher)
	if publisher == "" && legacy.Metadata != nil {
		publisher = strings.TrimSpace(legacy.Metadata["publisher"])
	}
	if publisher == "" {
		return CanonicalExtensionManifest0201{}, path, errors.New("legacy manifest не содержит publisher; укажите --publisher")
	}
	manifest := CanonicalExtensionManifest0201{
		SchemaVersion: "2.0",
		ID:            legacy.ID,
		Name:          legacy.Name,
		Version:       legacy.Version,
		Publisher:     publisher,
		API:           legacy.API,
		Targets:       []CanonicalExtensionTarget0201{{Kind: legacy.Target, Entrypoint: legacy.Entrypoint}},
		Permissions:   append([]string(nil), legacy.Permissions...),
		Hooks:         append([]string(nil), legacy.Hooks...),
		Metadata:      map[string]string{"importedFrom": "neverlauncher-plugin.json", "legacySchemaVersion": legacy.SchemaVersion},
	}
	for k, v := range legacy.Metadata {
		if k == "publisher" {
			continue
		}
		manifest.Metadata[k] = v
	}
	manifest, _, err = normalizeCanonicalExtension0201(manifest)
	return manifest, path, err
}
