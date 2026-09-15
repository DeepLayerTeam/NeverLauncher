package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var managedClientRoots = []string{"libraries", "assets", "versions", "natives", "resources", "mods"}

type clientLifecycleSnapshot struct {
	SchemaVersion string   `json:"schemaVersion"`
	ToolVersion   string   `json:"toolVersion"`
	ID            string   `json:"id"`
	CreatedAt     string   `json:"createdAt"`
	ClientDir     string   `json:"clientDir"`
	Files         []string `json:"files"`
	HadState      bool     `json:"hadState"`
}

type clientVerifyResult struct {
	SchemaVersion   string   `json:"schemaVersion"`
	ToolVersion     string   `json:"toolVersion"`
	PackageID       string   `json:"packageId"`
	ProjectID       string   `json:"projectId"`
	ProfileID       string   `json:"profileId"`
	Channel         string   `json:"channel"`
	Version         string   `json:"version"`
	ClientDir       string   `json:"clientDir"`
	Manifest        string   `json:"manifest"`
	Valid           bool     `json:"valid"`
	Missing         []string `json:"missing"`
	MissingOptional []string `json:"missingOptional,omitempty"`
	Corrupted       []string `json:"corrupted"`
	Orphans         []string `json:"orphans"`
	CheckedFiles    int      `json:"checkedFiles"`
}

func clientInstallOrUpdate(packagePath, storageDir, clientDir, mode string) (map[string]any, error) {
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return nil, err
	}
	snapshotID, err := createClientSnapshot(clientDir)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать rollback snapshot: %w", err)
	}
	apply, err := clientPackageConsume(packagePath, storageDir, clientDir)
	if err != nil {
		return nil, err
	}
	if err := attachRollbackSnapshot(clientDir, snapshotID); err != nil {
		return nil, err
	}
	verify, err := verifyClientInstallation(packagePath, clientDir)
	if err != nil {
		return nil, err
	}
	if !verify.Valid {
		return nil, fmt.Errorf("%s завершён, но post-verify failed: missing=%v corrupted=%v", mode, verify.Missing, verify.Corrupted)
	}
	return map[string]any{
		"schemaVersion":    cliSchemaVersion,
		"toolVersion":      version,
		"mode":             mode,
		"packageId":        manifest.PackageID,
		"version":          manifest.Version,
		"clientDir":        clientDir,
		"rollbackSnapshot": snapshotID,
		"apply":            apply,
		"verify":           verify,
		"status":           "applied-and-verified",
	}, nil
}

func verifyClientInstallation(packagePath, clientDir string) (clientVerifyResult, error) {
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return clientVerifyResult{}, err
	}
	result := clientVerifyResult{
		SchemaVersion: cliSchemaVersion,
		ToolVersion:   version,
		PackageID:     manifest.PackageID,
		ProjectID:     manifest.ProjectID,
		ProfileID:     manifest.ProfileID,
		Channel:       manifest.Channel,
		Version:       manifest.Version,
		ClientDir:     clientDir,
		Manifest:      packagePath,
		Missing:       []string{}, MissingOptional: []string{}, Corrupted: []string{}, Orphans: []string{},
	}
	expected := make(map[string]ClientPackageFile, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := validateClientPackagePath(file.Path); err != nil {
			return result, err
		}
		rel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file.Path)))
		expected[rel] = file
		sum, size, err := hashFile(filepath.Join(clientDir, filepath.FromSlash(rel)))
		if errors.Is(err, os.ErrNotExist) {
			if file.Required {
				result.Missing = append(result.Missing, rel)
			} else {
				result.MissingOptional = append(result.MissingOptional, rel)
			}
			continue
		}
		if err != nil || size != file.Size || !strings.EqualFold(sum, file.SHA256) {
			result.Corrupted = append(result.Corrupted, rel)
			continue
		}
		result.CheckedFiles++
	}
	for _, root := range managedClientRoots {
		base := filepath.Join(clientDir, root)
		_ = filepath.WalkDir(base, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, os.ErrNotExist) {
					return nil
				}
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(clientDir, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if _, ok := expected[rel]; !ok {
				result.Orphans = append(result.Orphans, rel)
			}
			return nil
		})
	}
	sort.Strings(result.Missing)
	sort.Strings(result.MissingOptional)
	sort.Strings(result.Corrupted)
	sort.Strings(result.Orphans)
	result.Valid = len(result.Missing) == 0 && len(result.Corrupted) == 0
	return result, nil
}

func repairClientInstallation(packagePath, storageDir, clientDir string, includeOptional bool) (map[string]any, error) {
	manifest, err := readClientPackageManifest(packagePath)
	if err != nil {
		return nil, err
	}
	before, err := verifyClientInstallation(packagePath, clientDir)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, p := range before.Missing {
		wanted[p] = true
	}
	for _, p := range before.Corrupted {
		wanted[p] = true
	}
	if includeOptional {
		for _, p := range before.MissingOptional {
			wanted[p] = true
		}
	}
	if len(wanted) == 0 {
		return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "already-valid", "verify": before, "repaired": []string{}}, nil
	}
	snapshotID, err := createClientSnapshot(clientDir)
	if err != nil {
		return nil, err
	}
	repaired := []string{}
	for _, file := range manifest.Files {
		rel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file.Path)))
		if !wanted[rel] {
			continue
		}
		src := clientPackageSourcePath(packagePath, storageDir, manifest, file)
		if err := verifiedCopyClientFile(src, filepath.Join(clientDir, filepath.FromSlash(rel)), file); err != nil {
			return nil, err
		}
		repaired = append(repaired, rel)
	}
	if err := attachRollbackSnapshot(clientDir, snapshotID); err != nil {
		return nil, err
	}
	after, err := verifyClientInstallation(packagePath, clientDir)
	if err != nil {
		return nil, err
	}
	if !after.Valid {
		return nil, fmt.Errorf("repair post-verify failed: missing=%v corrupted=%v", after.Missing, after.Corrupted)
	}
	sort.Strings(repaired)
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "repaired-and-verified", "rollbackSnapshot": snapshotID, "repaired": repaired, "verify": after}, nil
}

func cleanupClientInstallation(packagePath, clientDir string) (map[string]any, error) {
	verify, err := verifyClientInstallation(packagePath, clientDir)
	if err != nil {
		return nil, err
	}
	if len(verify.Orphans) == 0 {
		return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "clean", "quarantined": []string{}, "verify": verify}, nil
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	quarantine := filepath.Join(clientDir, ".neverlauncher", "quarantine", stamp)
	moved := []string{}
	for _, rel := range verify.Orphans {
		if !isManagedClientPath(rel) {
			return nil, fmt.Errorf("cleanup отказался трогать unmanaged path: %s", rel)
		}
		src := filepath.Join(clientDir, filepath.FromSlash(rel))
		dst := filepath.Join(quarantine, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		if err := os.Rename(src, dst); err != nil {
			return nil, err
		}
		moved = append(moved, rel)
	}
	after, err := verifyClientInstallation(packagePath, clientDir)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "quarantined", "quarantine": quarantine, "quarantined": moved, "verify": after}, nil
}

func rollbackClientInstallation(clientDir, target string) (map[string]any, error) {
	snapshotRoot := filepath.Join(clientDir, ".neverlauncher", "snapshots")
	targetDir, snap, err := loadClientSnapshot(snapshotRoot, target)
	if err != nil {
		return nil, err
	}
	safetyID, err := createClientSnapshot(clientDir)
	if err != nil {
		return nil, fmt.Errorf("safety snapshot: %w", err)
	}

	// Remove only managed content and paths recorded in current state; user data stays untouched.
	for _, root := range managedClientRoots {
		if err := os.RemoveAll(filepath.Join(clientDir, root)); err != nil {
			return nil, err
		}
	}
	for _, rel := range currentStatePaths(clientDir) {
		if isManagedClientPath(rel) {
			continue
		}
		_ = os.Remove(filepath.Join(clientDir, filepath.FromSlash(rel)))
	}

	filesRoot := filepath.Join(targetDir, "files")
	for _, rel := range snap.Files {
		src := filepath.Join(filesRoot, filepath.FromSlash(rel))
		dst := filepath.Join(clientDir, filepath.FromSlash(rel))
		if err := copyFileAtomic(src, dst); err != nil {
			return nil, err
		}
	}
	stateDst := filepath.Join(clientDir, ".neverlauncher", "client-state.json")
	stateSrc := filepath.Join(targetDir, "client-state.json")
	if snap.HadState {
		if err := copyFileAtomic(stateSrc, stateDst); err != nil {
			return nil, err
		}
	} else {
		_ = os.Remove(stateDst)
	}
	return map[string]any{"schemaVersion": cliSchemaVersion, "toolVersion": version, "status": "rolled-back", "restoredSnapshot": snap.ID, "safetySnapshot": safetyID, "restoredFiles": len(snap.Files)}, nil
}

func createClientSnapshot(clientDir string) (string, error) {
	id := time.Now().UTC().Format("20060102T150405.000000000Z")
	dir := filepath.Join(clientDir, ".neverlauncher", "snapshots", id)
	filesRoot := filepath.Join(dir, "files")
	if err := os.MkdirAll(filesRoot, 0o755); err != nil {
		return "", err
	}

	paths := map[string]bool{}
	for _, rel := range currentStatePaths(clientDir) {
		paths[rel] = true
	}
	for _, root := range managedClientRoots {
		base := filepath.Join(clientDir, root)
		_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(clientDir, path)
			if err != nil {
				return err
			}
			paths[filepath.ToSlash(rel)] = true
			return nil
		})
	}
	list := make([]string, 0, len(paths))
	for rel := range paths {
		if rel == "" || strings.HasPrefix(rel, ".neverlauncher/") {
			continue
		}
		src := filepath.Join(clientDir, filepath.FromSlash(rel))
		if st, err := os.Stat(src); err == nil && !st.IsDir() {
			if err := copyFileAtomic(src, filepath.Join(filesRoot, filepath.FromSlash(rel))); err != nil {
				return "", err
			}
			list = append(list, rel)
		}
	}
	sort.Strings(list)
	statePath := filepath.Join(clientDir, ".neverlauncher", "client-state.json")
	hadState := false
	if st, err := os.Stat(statePath); err == nil && !st.IsDir() {
		if err := copyFileAtomic(statePath, filepath.Join(dir, "client-state.json")); err != nil {
			return "", err
		}
		hadState = true
	}
	snap := clientLifecycleSnapshot{SchemaVersion: cliSchemaVersion, ToolVersion: version, ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ClientDir: clientDir, Files: list, HadState: hadState}
	if err := writeJSONFile(filepath.Join(dir, "snapshot.json"), snap); err != nil {
		return "", err
	}
	return id, nil
}

func loadClientSnapshot(root, target string) (string, clientLifecycleSnapshot, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", clientLifecycleSnapshot{}, err
	}
	ids := []string{}
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return "", clientLifecycleSnapshot{}, errors.New("rollback snapshot отсутствует")
	}
	id := target
	if id == "" || id == "previous" || id == "latest" {
		id = ids[len(ids)-1]
	}
	dir := filepath.Join(root, id)
	raw, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return "", clientLifecycleSnapshot{}, err
	}
	var snap clientLifecycleSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return "", clientLifecycleSnapshot{}, err
	}
	if snap.ID != id {
		return "", clientLifecycleSnapshot{}, errors.New("snapshot id mismatch")
	}
	return dir, snap, nil
}

func currentStatePaths(clientDir string) []string {
	raw, err := os.ReadFile(filepath.Join(clientDir, ".neverlauncher", "client-state.json"))
	if err != nil {
		return nil
	}
	var state struct {
		Files []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	if json.Unmarshal(raw, &state) != nil {
		return nil
	}
	out := []string{}
	for _, f := range state.Files {
		rel := filepath.ToSlash(filepath.Clean(filepath.FromSlash(f.Path)))
		if validateClientPackagePath(rel) == nil {
			out = append(out, rel)
		}
	}
	return out
}

func attachRollbackSnapshot(clientDir, snapshotID string) error {
	path := filepath.Join(clientDir, ".neverlauncher", "client-state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	state["rollbackSnapshot"] = snapshotID
	return writeJSONFile(path, state)
}

func isManagedClientPath(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	for _, root := range managedClientRoots {
		if rel == root || strings.HasPrefix(rel, root+"/") {
			return true
		}
	}
	return false
}

func clientPackageSourcePath(packagePath, storageDir string, manifest ClientPackageManifest, file ClientPackageFile) string {
	prefix := inferStoragePrefix(packagePath, storageDir, manifest)
	src := filepath.Join(storageDir, filepath.FromSlash(prefix), filepath.FromSlash(file.Path))
	if _, err := os.Stat(src); err == nil {
		return src
	}
	return filepath.Join(filepath.Dir(packagePath), filepath.FromSlash(file.Path))
}

func verifiedCopyClientFile(src, dst string, file ClientPackageFile) error {
	sum, size, err := hashFile(src)
	if err != nil {
		return fmt.Errorf("%s: source unavailable: %w", file.Path, err)
	}
	if size != file.Size || !strings.EqualFold(sum, file.SHA256) {
		return fmt.Errorf("%s: source checksum/size mismatch", file.Path)
	}
	if err := copyFileAtomic(src, dst); err != nil {
		return err
	}
	if file.Executable {
		if err := os.Chmod(dst, 0o755); err != nil {
			return fmt.Errorf("%s: не удалось выставить executable bit: %w", file.Path, err)
		}
	}
	sum, size, err = hashFile(dst)
	if err != nil || size != file.Size || !strings.EqualFold(sum, file.SHA256) {
		return fmt.Errorf("%s: destination verification failed", file.Path)
	}
	return nil
}

func copyTreeFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
