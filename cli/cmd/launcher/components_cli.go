package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"runtime"
	"sort"
	"strings"

	cm "gitflic.ru/skif4er/launcher/cli/internal/componentmodel"
)

// The signed manifest is serialized in the exact Go API field order. RawMessage
// preserves the signed nested objects (including unknown supported runtime
// fields) without lossy conversion or map key reordering.
type componentsSignedWire0249 struct {
	SchemaVersion         string                   `json:"schemaVersion"`
	ProjectID             string                   `json:"projectId"`
	ProfileID             string                   `json:"profileId"`
	Channel               string                   `json:"channel"`
	Version               string                   `json:"version"`
	GameReleaseGeneration uint64                   `json:"gameReleaseGeneration,omitempty"`
	TrustEpoch            uint64                   `json:"trustEpoch,omitempty"`
	RollbackSource        json.RawMessage          `json:"rollbackSource,omitempty"`
	CreatedAt             string                   `json:"createdAt"`
	Minecraft             json.RawMessage          `json:"minecraft"`
	Runtime               json.RawMessage          `json:"runtime"`
	Directories           json.RawMessage          `json:"directories,omitempty"`
	Files                 json.RawMessage          `json:"files"`
	FileRules             json.RawMessage          `json:"fileRules,omitempty"`
	ProfileSnapshot       json.RawMessage          `json:"profileSnapshot,omitempty"`
	ComponentCatalog      json.RawMessage          `json:"componentCatalog,omitempty"`
	Signature             *componentsSignature0249 `json:"signature,omitempty"`
}
type componentsSignature0249 struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signedAt"`
}

type componentsInput0249 struct {
	Wire              componentsSignedWire0249
	Manifest          cm.Manifest
	SignatureVerified bool
}

// Reject duplicate keys at every level: Go's standard decoder otherwise keeps
// the last value, which can make two consumers see different signed content.
func rejectDuplicateJSON0249(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds limit")
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("expected JSON object key")
				}
				if seen[name] {
					return fmt.Errorf("duplicate JSON key %q", name)
				}
				seen[name] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("unexpected JSON closing delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func strictJSON0249(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(v); e != nil {
		return e
	}
	if _, e := decoder.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func loadComponents0249(filename, trustedKey string, allowUnsigned bool) (componentsInput0249, error) {
	var out componentsInput0249
	info, e := os.Stat(filename)
	if e != nil {
		return out, e
	}
	if info.Size() > 32<<20 {
		return out, errors.New("component manifest exceeds 32 MiB")
	}
	data, e := os.ReadFile(filename)
	if e != nil {
		return out, e
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&out.Wire); e != nil {
		return out, fmt.Errorf("manifest JSON: %w", e)
	}
	if e = dec.Decode(new(any)); e != io.EOF {
		return out, errors.New("trailing JSON after manifest")
	}
	if out.Wire.SchemaVersion != "3.0" {
		return out, fmt.Errorf("components require Manifest v3, got %q", out.Wire.SchemaVersion)
	}
	if len(out.Wire.ComponentCatalog) == 0 || len(out.Wire.Files) == 0 || len(out.Wire.ProfileSnapshot) == 0 {
		return out, errors.New("v3 manifest requires catalog, files and profile snapshot")
	}
	if e = json.Unmarshal(data, &out.Manifest); e != nil {
		return out, e
	}
	// Trust is never inferred from the untrusted manifest's embedded publicKey.
	if !allowUnsigned {
		if trustedKey == "" {
			return out, errors.New("--public-key is required; use --allow-unsigned only for a local draft")
		}
		if out.Wire.Signature == nil || out.Wire.Signature.Algorithm != "Ed25519" {
			return out, errors.New("missing/unsupported Ed25519 manifest signature")
		}
		key, e := loadEd25519PublicKey(trustedKey)
		if e != nil {
			return out, fmt.Errorf("trusted public key: %w", e)
		}
		embedded, e := hex.DecodeString(out.Wire.Signature.PublicKey)
		if e != nil || !ed25519.PublicKey(embedded).Equal(key) {
			return out, errors.New("manifest public key differs from trusted public key")
		}
		sig, e := hex.DecodeString(out.Wire.Signature.Signature)
		if e != nil || len(sig) != ed25519.SignatureSize {
			return out, errors.New("invalid Ed25519 manifest signature encoding")
		}
		unsigned := out.Wire
		unsigned.Signature = nil
		payload, e := json.Marshal(unsigned)
		if e != nil {
			return out, e
		}
		if !ed25519.Verify(key, payload, sig) {
			return out, errors.New("Ed25519 manifest signature invalid")
		}
		out.SignatureVerified = true
	}
	if e = cm.ValidateComponentCatalog0241(out.Manifest); e != nil {
		return out, fmt.Errorf("catalog validation: %w", e)
	}
	// Validate signed file references and ownership before an export or plan is
	// allowed; otherwise a valid graph could refer to tampered file metadata.
	if e = cm.ValidateSignedFiles0249(out.Manifest.Files); e != nil {
		return out, e
	}
	seen := make(map[string]bool, len(out.Manifest.Files))
	for _, f := range out.Manifest.Files {
		if f.Path == "" || f.Size < 0 || len(f.SHA256) != 64 {
			return out, fmt.Errorf("invalid signed file metadata %q", f.Path)
		}
		if _, e = hex.DecodeString(f.SHA256); e != nil {
			return out, fmt.Errorf("file %q invalid SHA-256", f.Path)
		}
		lower := strings.ToLower(f.Path)
		if seen[lower] {
			return out, fmt.Errorf("duplicate signed file path %q", f.Path)
		}
		seen[lower] = true
	}
	return out, nil
}

type componentReason0249 struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
	Via    string `json:"via,omitempty"`
}
type componentsFile0249 struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Owner  string `json:"owner"`
}
type componentsPlan0249 struct {
	SchemaVersion   string                 `json:"schemaVersion"`
	ManifestVersion string                 `json:"manifestVersion"`
	CatalogRevision uint64                 `json:"catalogRevision"`
	CatalogDigest   string                 `json:"catalogDigest"`
	Preset          string                 `json:"preset"`
	Components      []string               `json:"components"`
	Reasons         []componentReason0249  `json:"reasons"`
	Files           []componentsFile0249   `json:"files"`
	Actions         []componentsAction0249 `json:"actions"`
	DownloadBytes   int64                  `json:"downloadBytes"`
	PlanSHA256      string                 `json:"planSha256"`
}
type componentsAction0249 struct {
	Component string   `json:"component"`
	Type      string   `json:"type"`
	Path      string   `json:"path,omitempty"`
	Args      []string `json:"args,omitempty"`
}

func resolveComponents0249(input componentsInput0249, preset string, env cm.ComponentEnvironment0244) (componentsPlan0249, error) {
	cat := input.Manifest.ComponentCatalog
	out := componentsPlan0249{SchemaVersion: "1.0", ManifestVersion: input.Wire.Version, CatalogRevision: cat.Revision, CatalogDigest: cat.Digest, Preset: preset, Components: []string{}, Reasons: []componentReason0249{}, Files: []componentsFile0249{}, Actions: []componentsAction0249{}}
	if preset == "" {
		out.Preset = cat.DefaultPreset
	}
	var ids []string
	var e error
	switch cat.SchemaVersion {
	case cm.ComponentCatalogSchema0244, cm.ComponentCatalogSchema0245:
		ids, e = cm.ResolveCatalogConditional0244(*cat, preset, env)
	default:
		ids, e = cm.ResolveCatalogPreset0242(*cat, preset)
	}
	if e != nil {
		return out, e
	}
	out.Components = ids
	included := make(map[string]bool, len(ids))
	for _, id := range ids {
		included[id] = true
	}
	byID := make(map[string]cm.CatalogComponent0241, len(cat.Components))
	presetIDs := make(map[string]bool)
	for _, c := range cat.Components {
		byID[c.ID] = c
	}
	if out.Preset != "" {
		for _, p := range cat.Presets {
			if p.ID == out.Preset {
				for _, id := range p.Components {
					presetIDs[id] = true
				}
			}
		}
	} else {
		for _, c := range cat.Components {
			if c.Default {
				presetIDs[c.ID] = true
			}
		}
	}
	dependents := make(map[string][]string)
	for _, id := range ids {
		for _, dep := range byID[id].Dependencies {
			if included[dep.ID] {
				dependents[dep.ID] = append(dependents[dep.ID], id)
			}
		}
	}
	for _, id := range ids {
		c := byID[id]
		reason := "dependency"
		if c.Required {
			reason = "required"
		} else if presetIDs[id] {
			reason = "preset"
			if out.Preset == "" {
				reason = "default"
			}
		}
		r := componentReason0249{ID: id, Reason: reason}
		if reason == "dependency" && len(dependents[id]) > 0 {
			r.Via = dependents[id][0]
		}
		out.Reasons = append(out.Reasons, r)
		for _, a := range c.Actions {
			out.Actions = append(out.Actions, componentsAction0249{Component: id, Type: a.Type, Path: a.Path, Args: a.Args})
		}
	}
	owners := make(map[string]string)
	for _, c := range cat.Components {
		for _, p := range c.Files {
			owners[p] = c.ID
		}
	}
	for _, f := range input.Manifest.Files {
		owner := owners[f.Path]
		if owner != "" && !included[owner] {
			continue
		}
		ownership := cm.FileOwnership0224(f)
		if ownership == "user-owned" || ownership == "generated" {
			continue
		}
		out.Files = append(out.Files, componentsFile0249{Path: f.Path, Size: f.Size, SHA256: f.SHA256, Owner: owner})
		if out.DownloadBytes > int64(^uint64(0)>>1)-f.Size {
			return out, errors.New("download size overflow")
		}
		out.DownloadBytes += f.Size
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	b, e := json.Marshal(struct {
		Digest     string                 `json:"digest"`
		Preset     string                 `json:"preset"`
		Components []string               `json:"components"`
		Files      []componentsFile0249   `json:"files"`
		Actions    []componentsAction0249 `json:"actions"`
	}{cat.Digest, out.Preset, out.Components, out.Files, out.Actions})
	if e != nil {
		return out, e
	}
	sum := sha256.Sum256(b)
	out.PlanSHA256 = hex.EncodeToString(sum[:])
	return out, nil
}

func writeComponentsJSON0249(output string, data any) error {
	raw, e := json.MarshalIndent(data, "", "  ")
	if e != nil {
		return e
	}
	raw = append(raw, '\n')
	if output == "" || output == "-" {
		_, e = os.Stdout.Write(raw)
		return e
	}
	dir := filepath.Dir(output)
	f, e := os.CreateTemp(dir, ".nl-components-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0o644); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), output)
}
func fileDifference0249(before, after []componentsFile0249) (added, removed, changed []componentsFile0249) {
	prev := map[string]componentsFile0249{}
	next := map[string]componentsFile0249{}
	for _, f := range before {
		prev[f.Path] = f
	}
	for _, f := range after {
		next[f.Path] = f
	}
	for _, f := range after {
		if old, ok := prev[f.Path]; !ok {
			added = append(added, f)
		} else if old != f {
			changed = append(changed, f)
		}
	}
	for _, f := range before {
		if _, ok := next[f.Path]; !ok {
			removed = append(removed, f)
		}
	}
	return
}
func componentDifference0249(before, after []cm.CatalogComponent0241) (added, removed, changed []string) {
	prev := map[string]cm.CatalogComponent0241{}
	next := map[string]cm.CatalogComponent0241{}
	for _, c := range before {
		prev[c.ID] = c
	}
	for _, c := range after {
		next[c.ID] = c
	}
	for id, c := range next {
		if old, ok := prev[id]; !ok {
			added = append(added, id)
		} else {
			oldBytes, _ := json.Marshal(old)
			newBytes, _ := json.Marshal(c)
			if string(oldBytes) != string(newBytes) {
				changed = append(changed, id)
			}
		}
	}
	for id := range prev {
		if _, ok := next[id]; !ok {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return
}

func executeComponents0249(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: components validate|resolve|export|diff --manifest FILE [--public-key FILE] [--output FILE]")
	}
	cmd := args[0]
	if cmd != "validate" && cmd != "resolve" && cmd != "export" && cmd != "diff" {
		return fmt.Errorf("unknown components command %q", cmd)
	}
	fs := flag.NewFlagSet("components "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "manifest v3 JSON")
	old := fs.String("old", "", "old manifest for diff")
	newPath := fs.String("new", "", "new manifest for diff")
	pub := fs.String("public-key", "", "trusted Ed25519 public key")
	oldPub := fs.String("old-public-key", "", "trusted key for old release (defaults to --public-key)")
	newPub := fs.String("new-public-key", "", "trusted key for new release (defaults to --public-key)")
	allowUnsigned := fs.Bool("allow-unsigned", false, "local drafts only: do not authenticate manifest")
	output := fs.String("output", "-", "JSON output")
	preset := fs.String("preset", "", "preset ID (default: signed defaultPreset)")
	oldPreset := fs.String("old-preset", "", "old preset for diff")
	osName := fs.String("os", "", "target OS")
	arch := fs.String("arch", "", "target architecture")
	javaMajor := fs.Uint("java-major", 0, "trusted Java major")
	minecraft := fs.String("minecraft", "", "Minecraft version")
	loader := fs.String("loader", "", "Minecraft loader")
	loaderVersion := fs.String("loader-version", "", "Minecraft loader version")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if *manifest == "" && cmd != "diff" && len(fs.Args()) == 1 {
		*manifest = fs.Arg(0)
	}
	if cmd != "diff" && *manifest == "" {
		return errors.New("--manifest is required")
	}
	if *javaMajor > 99 {
		return errors.New("--java-major outside supported range")
	}
	if *osName == "" {
		if runtime.GOOS == "darwin" {
			*osName = "macos"
		} else {
			*osName = runtime.GOOS
		}
	}
	if *arch == "" {
		if runtime.GOARCH == "amd64" {
			*arch = "x86_64"
		} else if runtime.GOARCH == "arm64" {
			*arch = "aarch64"
		} else {
			*arch = runtime.GOARCH
		}
	}
	env := cm.ComponentEnvironment0244{OS: *osName, Arch: *arch, JavaMajor: uint32(*javaMajor), MinecraftVersion: *minecraft, Loader: *loader, LoaderVersion: *loaderVersion}
	// CLI intentionally has NO --permissions: claims from a local flag are not server entitlements.
	if cmd == "diff" {
		if *old == "" || *newPath == "" {
			return errors.New("components diff requires --old and --new")
		}
		okOld := *oldPub
		if okOld == "" {
			okOld = *pub
		}
		okNew := *newPub
		if okNew == "" {
			okNew = *pub
		}
		a, e := loadComponents0249(*old, okOld, *allowUnsigned)
		if e != nil {
			return fmt.Errorf("old: %w", e)
		}
		b, e := loadComponents0249(*newPath, okNew, *allowUnsigned)
		if e != nil {
			return fmt.Errorf("new: %w", e)
		}
		before, e := resolveComponents0249(a, *oldPreset, env)
		if e != nil {
			return fmt.Errorf("old resolve: %w", e)
		}
		after, e := resolveComponents0249(b, *preset, env)
		if e != nil {
			return fmt.Errorf("new resolve: %w", e)
		}
		add, remove, update := componentDifference0249(a.Manifest.ComponentCatalog.Components, b.Manifest.ComponentCatalog.Components)
		filesAdded, filesRemoved, filesChanged := fileDifference0249(before.Files, after.Files)
		return writeComponentsJSON0249(*output, struct {
			SchemaVersion     string               `json:"schemaVersion"`
			Verified          bool                 `json:"signatureVerified"`
			From              componentsPlan0249   `json:"from"`
			To                componentsPlan0249   `json:"to"`
			AddedComponents   []string             `json:"addedComponents"`
			RemovedComponents []string             `json:"removedComponents"`
			ChangedComponents []string             `json:"changedComponents"`
			AddedFiles        []componentsFile0249 `json:"addedFiles"`
			RemovedFiles      []componentsFile0249 `json:"removedFiles"`
			ChangedFiles      []componentsFile0249 `json:"changedFiles"`
		}{"1.0", a.SignatureVerified && b.SignatureVerified, before, after, add, remove, update, filesAdded, filesRemoved, filesChanged})
	}
	input, e := loadComponents0249(*manifest, *pub, *allowUnsigned)
	if e != nil {
		return e
	}
	cat := input.Manifest.ComponentCatalog
	switch cmd {
	case "validate":
		// Validate every named preset's statically resolvable graph, not only one.
		for _, p := range cat.Presets {
			if _, e = cm.PreviewCatalogGraph0248(*cat, p.ID); e != nil {
				return fmt.Errorf("preset %s: %w", p.ID, e)
			}
		}
		if _, e = cm.PreviewCatalogGraph0248(*cat, ""); e != nil {
			return e
		}
		return writeComponentsJSON0249(*output, struct {
			SchemaVersion     string `json:"schemaVersion"`
			Valid             bool   `json:"valid"`
			SignatureVerified bool   `json:"signatureVerified"`
			CatalogRevision   uint64 `json:"catalogRevision"`
			CatalogDigest     string `json:"catalogDigest"`
			ComponentCount    int    `json:"componentCount"`
			PresetCount       int    `json:"presetCount"`
		}{"1.0", true, input.SignatureVerified, cat.Revision, cat.Digest, len(cat.Components), len(cat.Presets)})
	case "resolve":
		plan, e := resolveComponents0249(input, *preset, env)
		if e != nil {
			return e
		}
		return writeComponentsJSON0249(*output, struct {
			SignatureVerified bool               `json:"signatureVerified"`
			Plan              componentsPlan0249 `json:"plan"`
		}{input.SignatureVerified, plan})
	case "export":
		return writeComponentsJSON0249(*output, struct {
			SchemaVersion     string                  `json:"schemaVersion"`
			SignatureVerified bool                    `json:"signatureVerified"`
			ManifestVersion   string                  `json:"manifestVersion"`
			Catalog           cm.ComponentCatalog0241 `json:"catalog"`
			Files             []cm.ManifestFile       `json:"files"`
		}{"1.0", input.SignatureVerified, input.Wire.Version, *cat, input.Manifest.Files})
	}
	return errors.New("unsupported components command")
}

// All commands emit a stable JSON error object, including an explanation code,
// while preserving the process's nonzero status for scripts and CI.
func handleComponents0249(args []string) error {
	err := executeComponents0249(args)
	if err == nil {
		return nil
	}
	code, component, related := "invalid_input", "", ""
	var resolution *cm.ResolutionError0243
	if errors.As(err, &resolution) {
		code = resolution.Code
		component = resolution.Component
		related = resolution.Related
	}
	output := "-"
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--output" {
			output = args[i+1]
		}
	}
	report := struct {
		SchemaVersion string `json:"schemaVersion"`
		Status        string `json:"status"`
		Code          string `json:"code"`
		Component     string `json:"component,omitempty"`
		Related       string `json:"related,omitempty"`
		Message       string `json:"message"`
	}{"1.0", "error", code, component, related, err.Error()}
	if e := writeComponentsJSON0249(output, report); e != nil {
		return fmt.Errorf("%w; cannot write error JSON: %v", err, e)
	}
	return err
}
