package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Each pinned adapter has an independent release version and an implementation
// fingerprint. The embedded sources are from the binary that actually executes
// the installation, not files read from the (potentially untrusted) client.
// This intentionally changes fingerprints when executable materialization code
// changes without a matching manually updated version constant.
//
//go:embed adapter_lifecycle_02711.go client_factory_0271.go vanilla_runtime.go loader_runtime.go loader_resolution.go modern_loader_adapters_0272.go forge_runtime.go forge_processor_recovery.go isolated_build_worker_0273.go isolated_build_worker_0273_linux.go isolated_build_worker_0273_darwin.go isolated_build_worker_0273_windows.go isolated_build_worker_0273_other.go shared_artifacts_0277.go legacy_client_adapters_0278.go authlib_classloader_0279.go
var factoryAdapterSources02711 embed.FS

type factoryAdapterPin02711 struct {
	ID                   string `json:"id"`
	Version              string `json:"version"`
	ImplementationSHA256 string `json:"implementationSha256"`
}

// Keep independently versioned recipes even when several adapters share an
// installer implementation. Future versions can coexist as explicit entries.
var factoryAdapterDefinitions02711 = map[string]struct {
	version string
	files   []string
}{
	"vanilla":        {"1.0.0", []string{"adapter_lifecycle_02711.go", "client_factory_0271.go", "vanilla_runtime.go", "shared_artifacts_0277.go", "legacy_client_adapters_0278.go"}},
	"fabric":         {"1.0.0", []string{"adapter_lifecycle_02711.go", "client_factory_0271.go", "vanilla_runtime.go", "shared_artifacts_0277.go", "loader_runtime.go", "loader_resolution.go", "modern_loader_adapters_0272.go"}},
	"quilt":          {"1.0.0", []string{"adapter_lifecycle_02711.go", "client_factory_0271.go", "vanilla_runtime.go", "shared_artifacts_0277.go", "loader_runtime.go", "loader_resolution.go", "modern_loader_adapters_0272.go"}},
	"forge":          {"1.0.0", []string{"adapter_lifecycle_02711.go", "client_factory_0271.go", "vanilla_runtime.go", "shared_artifacts_0277.go", "forge_runtime.go", "forge_processor_recovery.go", "isolated_build_worker_0273.go", "isolated_build_worker_0273_linux.go", "isolated_build_worker_0273_darwin.go", "isolated_build_worker_0273_windows.go", "isolated_build_worker_0273_other.go", "legacy_client_adapters_0278.go", "authlib_classloader_0279.go"}},
	"neoforge":       {"1.0.0", []string{"adapter_lifecycle_02711.go", "client_factory_0271.go", "vanilla_runtime.go", "shared_artifacts_0277.go", "forge_runtime.go", "forge_processor_recovery.go", "isolated_build_worker_0273.go", "isolated_build_worker_0273_linux.go", "isolated_build_worker_0273_darwin.go", "isolated_build_worker_0273_windows.go", "isolated_build_worker_0273_other.go", "authlib_classloader_0279.go"}},
	"sha256-verify":  {"1.0.0", []string{"client_factory_0271.go"}},
	"atomic-publish": {"1.0.0", []string{"client_factory_0271.go"}},
}

func factoryAdapterPinByID02711(id string) (factoryAdapterPin02711, error) {
	def, ok := factoryAdapterDefinitions02711[id]
	if !ok {
		return factoryAdapterPin02711{}, fmt.Errorf("unknown executable adapter %q", id)
	}
	h := sha256.New()
	_, _ = h.Write([]byte("launcher-adapter-v1\x00" + id + "\x00" + def.version + "\x00"))
	files := append([]string(nil), def.files...)
	sort.Strings(files)
	for _, filename := range files {
		contents, err := factoryAdapterSources02711.ReadFile(filename)
		if err != nil {
			return factoryAdapterPin02711{}, fmt.Errorf("embedded adapter implementation %q: %w", filename, err)
		}
		_, _ = h.Write([]byte(filename + "\x00"))
		_, _ = h.Write(contents)
		_, _ = h.Write([]byte{0})
	}
	return factoryAdapterPin02711{ID: id, Version: def.version, ImplementationSHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func currentFactoryAdapterPins02711(loader string) []factoryAdapterPin02711 {
	steps := factorySteps0271(loader)
	pins := make([]factoryAdapterPin02711, 0, len(steps))
	for _, step := range steps {
		pin, err := factoryAdapterPinByID02711(step.Adapter)
		if err != nil {
			panic(err) // programmer error: factorySteps includes an unknown embedded adapter
		}
		pins = append(pins, pin)
	}
	return pins
}

// Old <=0.27.10 plans remain readable and their on-disk hashes can still be
// checked; they are *not* implicitly assigned new adapter identities.
func validateFactoryAdapterPins02711(p factoryPlan0271) error {
	if len(p.AdapterPins) == 0 {
		return nil
	}
	if len(p.AdapterPins) != len(p.Steps) {
		return errors.New("incomplete factory adapter pin set")
	}
	seen := map[string]bool{}
	for i, pin := range p.AdapterPins {
		if pin.ID != p.Steps[i].Adapter || seen[pin.ID] || strings.TrimSpace(pin.Version) != pin.Version || pin.Version == "" || !isSHA256Hex0271(pin.ImplementationSHA256) {
			return fmt.Errorf("invalid factory adapter pin at step %d", i)
		}
		seen[pin.ID] = true
	}
	return nil
}

func requireCurrentFactoryAdapters02711(p factoryPlan0271) error {
	if len(p.AdapterPins) == 0 {
		return errors.New("legacy install-plan has no versioned adapter evidence; rebuild with --upgrade-adapters=true")
	}
	if err := validateFactoryAdapterPins02711(p); err != nil {
		return err
	}
	current := currentFactoryAdapterPins02711(p.Loader)
	for i, old := range p.AdapterPins {
		if old != current[i] {
			return fmt.Errorf("adapter %q changed from version %s SHA-256 %s to version %s SHA-256 %s; revalidate with --upgrade-adapters=true", old.ID, old.Version, old.ImplementationSHA256, current[i].Version, current[i].ImplementationSHA256)
		}
	}
	return nil
}

// An explicit upgrade may result in different generated files, but may not
// silently replace the bytes of a previously pinned source artifact. New
// sources may be introduced and are recorded in the upgraded plan.
func checkAdapterUpgradeSources02711(old, next []factorySource0271) error {
	known := make(map[string]factorySource0271, len(old))
	for _, s := range old {
		known[s.Path] = s
	}
	for _, s := range next {
		if previous, ok := known[s.Path]; ok && (previous.SHA256 != s.SHA256 || previous.Size != s.Size) {
			return fmt.Errorf("adapter upgrade modified locked source %s", s.Path)
		}
	}
	return nil
}

func factoryAdapterTargetCheck02711(p factoryPlan0271) error {
	for _, target := range p.Targets {
		if _, err := normalizeVanillaTarget(target); err != nil {
			return fmt.Errorf("unsupported build target %s/%s: %w", target.OS, target.Arch, err)
		}
	}
	// The classic Forge 1.7.10 / 1.12.2 routes intentionally use Java 8.
	// Cleanroom/lwjgl3ify bridges have their own explicit install rules and
	// cannot be silently treated as compatible with those classic adapters.
	if p.Loader == "forge" && (p.MinecraftVersion == "1.7.10" || p.MinecraftVersion == "1.12.2") && p.Java.Major != 8 {
		return fmt.Errorf("classic Forge %s requires Java 8; Java %d requires a separately validated bridge target", p.MinecraftVersion, p.Java.Major)
	}
	return nil
}

// The processor journal certifies a result for specific processor/input
// identities. When the implementation changes, it must not resume from an old
// completed entry even if the old outputs appear valid. Removing the journal
// only in the isolated staging copy triggers the existing Forge worker's
// quarantine and recovery path and forces a new processor execution.
func invalidateFactoryProcessorRecovery02711(staging, loader string) error {
	if loader != "forge" && loader != "neoforge" {
		return nil
	}
	installerRoot := filepath.Join(staging, ".launcher", "installers", loader)
	if _, err := os.Lstat(installerRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return filepath.WalkDir(installerRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("installer directory contains symlink %s", path)
		}
		if !d.IsDir() && d.Name() == "processor-journal.json" {
			if !d.Type().IsRegular() {
				return fmt.Errorf("invalid processor journal type %s", path)
			}
			return os.Remove(path)
		}
		return nil
	})
}
