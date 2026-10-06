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

type CanonicalExtensionAdminPage0208 struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}
type CanonicalExtensionAdminNavigation0208 struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}
type CanonicalExtensionAdminWidget0208 struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	PageID string `json:"pageId"`
	Height int    `json:"height,omitempty"`
}
type CanonicalExtensionAdminAction0208 struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}
type CanonicalExtensionAdminContributions0208 struct {
	Pages            []CanonicalExtensionAdminPage0208       `json:"pages,omitempty"`
	Navigation       []CanonicalExtensionAdminNavigation0208 `json:"navigation,omitempty"`
	DashboardWidgets []CanonicalExtensionAdminWidget0208     `json:"dashboardWidgets,omitempty"`
	Actions          []CanonicalExtensionAdminAction0208     `json:"actions,omitempty"`
}

type CanonicalExtensionDesktopPage0209 struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}
type CanonicalExtensionDesktopNavigation0209 struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	PageID string `json:"pageId"`
	Order  int    `json:"order,omitempty"`
}
type CanonicalExtensionDesktopAction0209 struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	PageID    string `json:"pageId"`
	Placement string `json:"placement,omitempty"`
}
type CanonicalExtensionDesktopContributions0209 struct {
	Pages      []CanonicalExtensionDesktopPage0209       `json:"pages,omitempty"`
	Navigation []CanonicalExtensionDesktopNavigation0209 `json:"navigation,omitempty"`
	Actions    []CanonicalExtensionDesktopAction0209     `json:"actions,omitempty"`
}
type CanonicalExtensionCLICommand0209 struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Usage       string `json:"usage,omitempty"`
}
type CanonicalExtensionCLIContributions0209 struct {
	Namespace string                             `json:"namespace"`
	Commands  []CanonicalExtensionCLICommand0209 `json:"commands"`
}

type CanonicalExtensionDependency0201 struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Optional bool   `json:"optional,omitempty"`
}

type CanonicalExtensionConflict02011 struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type CanonicalExtensionManifest0201 struct {
	SchemaVersion string                                      `json:"schemaVersion"`
	ID            string                                      `json:"id"`
	Name          string                                      `json:"name"`
	Version       string                                      `json:"version"`
	Publisher     string                                      `json:"publisher"`
	Description   string                                      `json:"description,omitempty"`
	Homepage      string                                      `json:"homepage,omitempty"`
	Repository    string                                      `json:"repository,omitempty"`
	API           string                                      `json:"api"`
	Targets       []CanonicalExtensionTarget0201              `json:"targets"`
	Permissions   []string                                    `json:"permissions,omitempty"`
	Hooks         []string                                    `json:"hooks,omitempty"`
	Dependencies  []CanonicalExtensionDependency0201          `json:"dependencies,omitempty"`
	Conflicts     []CanonicalExtensionConflict02011           `json:"conflicts,omitempty"`
	Metadata      map[string]string                           `json:"metadata,omitempty"`
	Admin         *CanonicalExtensionAdminContributions0208   `json:"admin,omitempty"`
	Desktop       *CanonicalExtensionDesktopContributions0209 `json:"desktop,omitempty"`
	CLI           *CanonicalExtensionCLIContributions0209     `json:"cli,omitempty"`
}

func handleExtension0201(args []string) error {
	if len(args) == 0 {
		return errors.New("доступные extension-подкоманды: init, dev, test, build, template, validate, import-legacy, pack, sign, verify, inspect, registry, updates, installed, status, install, enable, disable, uninstall, update, rollback, host, capabilities, permissions, permission-grant, permission-revoke, secrets, secret-set, secret-delete, cli")
	}
	switch args[0] {
	case "init", "dev", "test", "build":
		return handleExtensionSDK02010(args[0], args[1:])
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
		if target == "admin" {
			manifest.Permissions = []string{"ui:contribute", "project:read"}
			manifest.Admin = &CanonicalExtensionAdminContributions0208{
				Pages:            []CanonicalExtensionAdminPage0208{{ID: "main", Title: "Example extension"}},
				Navigation:       []CanonicalExtensionAdminNavigation0208{{ID: "main-nav", Label: "Example extension", PageID: "main"}},
				DashboardWidgets: []CanonicalExtensionAdminWidget0208{{ID: "summary", Title: "Example extension", PageID: "main", Height: 280}},
			}
		}
		if target == "desktop" {
			manifest.Permissions = []string{"desktop:contribute", "project:read"}
			manifest.Desktop = &CanonicalExtensionDesktopContributions0209{Pages: []CanonicalExtensionDesktopPage0209{{ID: "main", Title: "Example Desktop extension"}}, Navigation: []CanonicalExtensionDesktopNavigation0209{{ID: "main-nav", Label: "Example extension", PageID: "main"}}}
		}
		if target == "cli" {
			manifest.Permissions = []string{"cli:contribute"}
			manifest.CLI = &CanonicalExtensionCLIContributions0209{Namespace: "example", Commands: []CanonicalExtensionCLICommand0209{{Name: "status", Description: "Show extension status", Usage: "nl x example status"}}}
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
	case "pack", "sign", "verify", "inspect":
		return handleExtensionPackage0202(args)
	case "registry":
		return handleExtensionRegistry0203(args[1:])
	case "updates":
		return handleExtensionUpdates02011(args[1:])
	case "host":
		return handleExtensionHost0205(args[1:])
	case "cli":
		return handleExtensionCLI0209(args[1:])
	case "capabilities", "permissions", "permission-grant", "permission-revoke", "secrets", "secret-set", "secret-delete":
		return handleExtensionSecurity0207(args[0], args[1:])
	case "installed", "installations", "status", "install", "enable", "disable", "uninstall", "update", "rollback":
		return handleExtensionLifecycle0204(args[0], args[1:])
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
	seenConflicts := map[string]struct{}{}
	for i := range m.Conflicts {
		c := &m.Conflicts[i]
		c.ID = strings.ToLower(strings.TrimSpace(c.ID))
		c.Version = strings.TrimSpace(c.Version)
		if !canonicalExtensionID0201.MatchString(c.ID) || c.ID == m.ID {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("некорректный conflict %q", c.ID)
		}
		if c.Version == "" || len(c.Version) > 128 {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("conflict %s требует version constraint", c.ID)
		}
		if _, ok := seenConflicts[c.ID]; ok {
			return CanonicalExtensionManifest0201{}, "", fmt.Errorf("conflict %q указан повторно", c.ID)
		}
		seenConflicts[c.ID] = struct{}{}
	}
	sort.Slice(m.Conflicts, func(i, j int) bool { return m.Conflicts[i].ID < m.Conflicts[j].ID })
	if m.Admin != nil {
		if _, ok := seenTargets["admin"]; !ok {
			return CanonicalExtensionManifest0201{}, "", errors.New("admin contributions require an admin target")
		}
		for _, target := range m.Targets {
			if target.Kind == "admin" && !strings.HasSuffix(strings.ToLower(target.Entrypoint), ".html") {
				return CanonicalExtensionManifest0201{}, "", errors.New("admin contributions require a standalone .html entrypoint")
			}
		}
		if _, ok := setOfStrings0208(m.Permissions)["ui:contribute"]; !ok {
			return CanonicalExtensionManifest0201{}, "", errors.New("admin contributions require ui:contribute permission")
		}
		if err := normalizeAdminContributions0208(m.Admin); err != nil {
			return CanonicalExtensionManifest0201{}, "", err
		}
	}
	if m.Desktop != nil {
		if _, ok := seenTargets["desktop"]; !ok {
			return CanonicalExtensionManifest0201{}, "", errors.New("desktop contributions require a desktop target")
		}
		for _, target := range m.Targets {
			if target.Kind == "desktop" && !strings.HasSuffix(strings.ToLower(target.Entrypoint), ".html") {
				return CanonicalExtensionManifest0201{}, "", errors.New("desktop contributions require a standalone .html entrypoint")
			}
		}
		if _, ok := setOfStrings0208(m.Permissions)["desktop:contribute"]; !ok {
			return CanonicalExtensionManifest0201{}, "", errors.New("desktop contributions require desktop:contribute permission")
		}
		if err := normalizeDesktopContributions0209(m.Desktop); err != nil {
			return CanonicalExtensionManifest0201{}, "", err
		}
	}
	if m.CLI != nil {
		if _, ok := seenTargets["cli"]; !ok {
			return CanonicalExtensionManifest0201{}, "", errors.New("cli contributions require a cli target")
		}
		if _, ok := setOfStrings0208(m.Permissions)["cli:contribute"]; !ok {
			return CanonicalExtensionManifest0201{}, "", errors.New("cli contributions require cli:contribute permission")
		}
		if err := normalizeCLIContributions0209(m.CLI); err != nil {
			return CanonicalExtensionManifest0201{}, "", err
		}
	}
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

func normalizeDesktopContributions0209(d *CanonicalExtensionDesktopContributions0209) error {
	if d == nil {
		return nil
	}
	if len(d.Pages) == 0 || len(d.Pages) > 64 || len(d.Navigation) > 64 || len(d.Actions) > 64 {
		return errors.New("desktop contributions contain invalid item count")
	}
	pages := map[string]struct{}{}
	for i := range d.Pages {
		p := &d.Pages[i]
		p.ID = strings.ToLower(strings.TrimSpace(p.ID))
		p.Title = strings.TrimSpace(p.Title)
		p.Description = strings.TrimSpace(p.Description)
		if !validAdminContributionID0208CLI(p.ID) || p.Title == "" || len(p.Title) > 120 || len(p.Description) > 500 {
			return fmt.Errorf("invalid desktop page %q", p.ID)
		}
		if _, ok := pages[p.ID]; ok {
			return fmt.Errorf("duplicate desktop page %q", p.ID)
		}
		pages[p.ID] = struct{}{}
	}
	seen := map[string]struct{}{}
	for i := range d.Navigation {
		n := &d.Navigation[i]
		n.ID = strings.ToLower(strings.TrimSpace(n.ID))
		n.Label = strings.TrimSpace(n.Label)
		n.PageID = strings.ToLower(strings.TrimSpace(n.PageID))
		if !validAdminContributionID0208CLI(n.ID) || n.Label == "" || len(n.Label) > 80 || n.Order < -10000 || n.Order > 10000 {
			return fmt.Errorf("invalid desktop navigation %q", n.ID)
		}
		if _, ok := pages[n.PageID]; !ok {
			return fmt.Errorf("desktop navigation %s references unknown page %s", n.ID, n.PageID)
		}
		if _, ok := seen[n.ID]; ok {
			return fmt.Errorf("duplicate desktop navigation %q", n.ID)
		}
		seen[n.ID] = struct{}{}
	}
	seen = map[string]struct{}{}
	for i := range d.Actions {
		a := &d.Actions[i]
		a.ID = strings.ToLower(strings.TrimSpace(a.ID))
		a.Label = strings.TrimSpace(a.Label)
		a.PageID = strings.ToLower(strings.TrimSpace(a.PageID))
		a.Placement = strings.ToLower(strings.TrimSpace(a.Placement))
		if a.Placement == "" {
			a.Placement = "toolbar"
		}
		if !validAdminContributionID0208CLI(a.ID) || a.Label == "" || len(a.Label) > 80 || (a.Placement != "toolbar" && a.Placement != "page") {
			return fmt.Errorf("invalid desktop action %q", a.ID)
		}
		if _, ok := pages[a.PageID]; !ok {
			return fmt.Errorf("desktop action %s references unknown page %s", a.ID, a.PageID)
		}
		if _, ok := seen[a.ID]; ok {
			return fmt.Errorf("duplicate desktop action %q", a.ID)
		}
		seen[a.ID] = struct{}{}
	}
	sort.Slice(d.Pages, func(i, j int) bool { return d.Pages[i].ID < d.Pages[j].ID })
	sort.Slice(d.Navigation, func(i, j int) bool {
		if d.Navigation[i].Order == d.Navigation[j].Order {
			return d.Navigation[i].ID < d.Navigation[j].ID
		}
		return d.Navigation[i].Order < d.Navigation[j].Order
	})
	sort.Slice(d.Actions, func(i, j int) bool { return d.Actions[i].ID < d.Actions[j].ID })
	return nil
}
func validAdminContributionID0208CLI(v string) bool {
	if len(v) < 2 || len(v) > 64 {
		return false
	}
	for i, r := range v {
		if i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func normalizeCLIContributions0209(c *CanonicalExtensionCLIContributions0209) error {
	if c == nil {
		return nil
	}
	c.Namespace = strings.ToLower(strings.TrimSpace(c.Namespace))
	if !validAdminContributionID0208CLI(c.Namespace) {
		return errors.New("cli namespace must match [a-z0-9][a-z0-9._-]{1,63}")
	}
	if len(c.Commands) == 0 || len(c.Commands) > 64 {
		return errors.New("cli contributions require 1..64 commands")
	}
	seen := map[string]struct{}{}
	for i := range c.Commands {
		cmd := &c.Commands[i]
		cmd.Name = strings.ToLower(strings.TrimSpace(cmd.Name))
		cmd.Description = strings.TrimSpace(cmd.Description)
		cmd.Usage = strings.TrimSpace(cmd.Usage)
		if !validAdminContributionID0208CLI(cmd.Name) || len(cmd.Description) > 240 || len(cmd.Usage) > 240 {
			return fmt.Errorf("invalid cli command %q", cmd.Name)
		}
		if _, ok := seen[cmd.Name]; ok {
			return fmt.Errorf("duplicate cli command %q", cmd.Name)
		}
		seen[cmd.Name] = struct{}{}
	}
	sort.Slice(c.Commands, func(i, j int) bool { return c.Commands[i].Name < c.Commands[j].Name })
	return nil
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

func setOfStrings0208(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range values {
		out[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	return out
}

func validAdminID0208(v string) bool {
	if len(v) < 2 || len(v) > 64 {
		return false
	}
	for i, r := range v {
		if i == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func normalizeAdminContributions0208(a *CanonicalExtensionAdminContributions0208) error {
	if a == nil {
		return nil
	}
	if len(a.Pages) > 64 || len(a.Navigation) > 64 || len(a.DashboardWidgets) > 32 || len(a.Actions) > 64 {
		return errors.New("admin contributions exceed limits")
	}
	pages := map[string]struct{}{}
	for i := range a.Pages {
		p := &a.Pages[i]
		p.ID = strings.ToLower(strings.TrimSpace(p.ID))
		p.Title = strings.TrimSpace(p.Title)
		p.Description = strings.TrimSpace(p.Description)
		if !validAdminID0208(p.ID) || p.Title == "" || len(p.Title) > 120 {
			return fmt.Errorf("invalid admin page %q", p.ID)
		}
		if _, ok := pages[p.ID]; ok {
			return fmt.Errorf("duplicate admin page %q", p.ID)
		}
		pages[p.ID] = struct{}{}
	}
	seen := map[string]struct{}{}
	for i := range a.Navigation {
		n := &a.Navigation[i]
		n.ID = strings.ToLower(strings.TrimSpace(n.ID))
		n.Label = strings.TrimSpace(n.Label)
		n.PageID = strings.ToLower(strings.TrimSpace(n.PageID))
		if !validAdminID0208(n.ID) || n.Label == "" || len(n.Label) > 80 {
			return fmt.Errorf("invalid admin navigation %q", n.ID)
		}
		if _, ok := pages[n.PageID]; !ok {
			return fmt.Errorf("admin navigation %s references unknown page %s", n.ID, n.PageID)
		}
		if _, ok := seen[n.ID]; ok {
			return fmt.Errorf("duplicate admin navigation %q", n.ID)
		}
		seen[n.ID] = struct{}{}
	}
	seen = map[string]struct{}{}
	for i := range a.DashboardWidgets {
		w := &a.DashboardWidgets[i]
		w.ID = strings.ToLower(strings.TrimSpace(w.ID))
		w.Title = strings.TrimSpace(w.Title)
		w.PageID = strings.ToLower(strings.TrimSpace(w.PageID))
		if w.Height == 0 {
			w.Height = 280
		}
		if !validAdminID0208(w.ID) || w.Title == "" || len(w.Title) > 120 || w.Height < 160 || w.Height > 1200 {
			return fmt.Errorf("invalid admin widget %q", w.ID)
		}
		if _, ok := pages[w.PageID]; !ok {
			return fmt.Errorf("admin widget %s references unknown page %s", w.ID, w.PageID)
		}
		if _, ok := seen[w.ID]; ok {
			return fmt.Errorf("duplicate admin widget %q", w.ID)
		}
		seen[w.ID] = struct{}{}
	}
	seen = map[string]struct{}{}
	for i := range a.Actions {
		x := &a.Actions[i]
		x.ID = strings.ToLower(strings.TrimSpace(x.ID))
		x.Label = strings.TrimSpace(x.Label)
		x.PageID = strings.ToLower(strings.TrimSpace(x.PageID))
		x.Placement = strings.ToLower(strings.TrimSpace(x.Placement))
		if x.Placement == "" {
			x.Placement = "toolbar"
		}
		if !validAdminID0208(x.ID) || x.Label == "" || len(x.Label) > 80 || (x.Placement != "toolbar" && x.Placement != "dashboard") {
			return fmt.Errorf("invalid admin action %q", x.ID)
		}
		if _, ok := pages[x.PageID]; !ok {
			return fmt.Errorf("admin action %s references unknown page %s", x.ID, x.PageID)
		}
		if _, ok := seen[x.ID]; ok {
			return fmt.Errorf("duplicate admin action %q", x.ID)
		}
		seen[x.ID] = struct{}{}
	}
	return nil
}
