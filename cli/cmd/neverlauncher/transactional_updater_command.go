package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func applyManifestUpdate0156(fromPath, toPath, sourceRoot, targetRoot string) (map[string]any, error) {
	oldManifest, err := readManifest(fromPath)
	if err != nil {
		return nil, err
	}
	newManifest, err := readManifest(toPath)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(sourceRoot) == "" || strings.TrimSpace(targetRoot) == "" {
		return nil, errors.New("update apply требует --source-root и --root")
	}
	files := make([]updaterFileSpec0156, 0, len(newManifest.Files))
	wanted := map[string]bool{}
	for _, file := range newManifest.Files {
		if !manifestFileAppliesToCurrentOS0156(file) {
			continue
		}
		if err := validateUpdaterPath0156(file.Path); err != nil {
			return nil, err
		}
		src := filepath.Join(sourceRoot, filepath.FromSlash(file.Path))
		files = append(files, updaterFileSpec0156{Path: file.Path, Source: src, Size: file.Size, SHA256: file.SHA256, Executable: file.Executable})
		wanted[file.Path] = true
	}
	remove := []string{}
	for _, file := range oldManifest.Files {
		if !manifestFileAppliesToCurrentOS0156(file) || wanted[file.Path] {
			continue
		}
		if err := validateUpdaterPath0156(file.Path); err != nil {
			return nil, err
		}
		remove = append(remove, file.Path)
	}
	sort.Strings(remove)
	updater, err := newTransactionalUpdater0156(targetRoot)
	if err != nil {
		return nil, err
	}
	verify := func() error {
		for _, file := range newManifest.Files {
			if !manifestFileAppliesToCurrentOS0156(file) {
				continue
			}
			path := filepath.Join(targetRoot, filepath.FromSlash(file.Path))
			if err := verifyUpdaterFile0156(path, file.Size, file.SHA256); err != nil {
				return fmt.Errorf("%s: %w", file.Path, err)
			}
		}
		for _, rel := range remove {
			if _, err := os.Lstat(filepath.Join(targetRoot, filepath.FromSlash(rel))); err == nil {
				return fmt.Errorf("obsolete file still exists after update: %s", rel)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	report, err := updater.apply(updaterRequest0156{
		Root:        targetRoot,
		Namespace:   "manifest-update",
		FromVersion: oldManifest.Version,
		ToVersion:   newManifest.Version,
		Files:       files,
		Remove:      remove,
		Verify:      verify,
	})
	if err != nil {
		return nil, err
	}
	report["fromManifest"] = fromPath
	report["toManifest"] = toPath
	report["sourceRoot"] = sourceRoot
	return report, nil
}

func manifestFileAppliesToCurrentOS0156(file ManifestFile) bool {
	if len(file.TargetOS) == 0 {
		return true
	}
	for _, target := range file.TargetOS {
		value := strings.ToLower(strings.TrimSpace(target))
		if value == runtime.GOOS || (runtime.GOOS == "darwin" && value == "macos") || (runtime.GOOS == "windows" && value == "win32") {
			return true
		}
	}
	return false
}

func runUpdaterSelfTest0156() (map[string]any, error) {
	root, err := os.MkdirTemp("", "neverlauncher-updater-selftest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	source := filepath.Join(root, "source")
	live := filepath.Join(root, "live")
	if err := os.MkdirAll(source, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(live, 0o755); err != nil {
		return nil, err
	}
	oldPath := filepath.Join(live, "launcher.bin")
	obsoletePath := filepath.Join(live, "obsolete.bin")
	newPath := filepath.Join(source, "launcher.bin")
	addedPath := filepath.Join(source, "added.bin")
	for path, data := range map[string][]byte{
		oldPath:      []byte("old-launcher"),
		obsoletePath: []byte("obsolete"),
		newPath:      []byte("new-launcher"),
		addedPath:    []byte("added"),
	} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, err
		}
	}
	updater, err := newTransactionalUpdater0156(live)
	if err != nil {
		return nil, err
	}
	launcherSpec, err := selfTestUpdaterSpec0156("launcher.bin", newPath)
	if err != nil {
		return nil, err
	}
	addedSpec, err := selfTestUpdaterSpec0156("added.bin", addedPath)
	if err != nil {
		return nil, err
	}
	commit, err := updater.apply(updaterRequest0156{
		Root: live, Namespace: "self-test-commit", FromVersion: "old", ToVersion: "new",
		Files:  []updaterFileSpec0156{launcherSpec, addedSpec},
		Remove: []string{"obsolete.bin"},
	})
	if err != nil {
		return nil, fmt.Errorf("commit self-test: %w", err)
	}
	if raw, _ := os.ReadFile(oldPath); string(raw) != "new-launcher" {
		return nil, errors.New("commit self-test: launcher bytes mismatch")
	}
	if _, err := os.Stat(obsoletePath); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("commit self-test: obsolete file was not removed")
	}

	rollbackSource := filepath.Join(source, "rollback.bin")
	if err := os.WriteFile(rollbackSource, []byte("must-not-survive"), 0o644); err != nil {
		return nil, err
	}
	rollbackSpec, err := selfTestUpdaterSpec0156("launcher.bin", rollbackSource)
	if err != nil {
		return nil, err
	}
	_, rollbackErr := updater.apply(updaterRequest0156{
		Root: live, Namespace: "self-test-rollback", FromVersion: "new", ToVersion: "broken",
		Files:  []updaterFileSpec0156{rollbackSpec},
		Verify: func() error { return errors.New("intentional self-test rollback") },
	})
	if rollbackErr == nil {
		return nil, errors.New("rollback self-test unexpectedly committed")
	}
	if raw, _ := os.ReadFile(oldPath); string(raw) != "new-launcher" {
		return nil, errors.New("rollback self-test did not restore committed bytes")
	}
	status, err := updater.status()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"schemaVersion": updaterCoreSchema0156,
		"toolVersion":   version,
		"engine":        "unified-transactional-updater",
		"platform":      runtime.GOOS,
		"architecture":  runtime.GOARCH,
		"checks":        []string{"verified-staging", "same-filesystem-switch", "obsolete-removal", "post-verify", "automatic-rollback", "durable-journal"},
		"commit":        commit,
		"statusReport":  status,
		"status":        "ok",
	}, nil
}

func selfTestUpdaterSpec0156(rel, src string) (updaterFileSpec0156, error) {
	sum, size, err := hashFile(src)
	if err != nil {
		return updaterFileSpec0156{}, err
	}
	return updaterFileSpec0156{Path: rel, Source: src, Size: size, SHA256: sum}, nil
}
