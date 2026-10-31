package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecurityGeneration belongs to the signed component-set manifest. It MUST NOT
// be inferred from productVersion, a mirror URL, or the local transaction ID.
// The watermark lives outside the rollback-controlled managed component tree.
// All calls are serialized by the existing transactional updater lock.
const componentSecurityState02311 = ".launcher/component-security"

type componentGenerationRecord02311 struct {
	Schema         uint32 `json:"schema"`
	Generation     uint64 `json:"generation"`
	ManifestDigest string `json:"manifestDigest"`
}

func componentSecurityRequired02311(v string) bool {
	a, b, c, ok := parseCoreVersion(v)
	return ok && (a > 0 || b > 23 || (b == 23 && c >= 11))
}

func componentDigest02311(m componentUpdateManifest0157) string {
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func loadComponentWatermark02311(root string) (componentGenerationRecord02311, error) {
	var found bool
	var current componentGenerationRecord02311
	for i := 0; i < 2; i++ {
		path := filepath.Join(root, fmt.Sprintf("%s-%d.json", componentSecurityState02311, i))
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return current, err
		}
		found = true
		if !info.Mode().IsRegular() || info.Size() > 4096 {
			return current, errors.New("invalid component generation slot: nonregular/oversized")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return current, err
		}
		var item componentGenerationRecord02311
		if json.Unmarshal(raw, &item) != nil || item.Schema != 1 || item.Generation == 0 || len(item.ManifestDigest) != 64 {
			return current, errors.New("corrupt component security generation slot")
		}
		if _, err := hex.DecodeString(item.ManifestDigest); err != nil {
			return current, errors.New("component generation digest corrupted")
		}
		if item.Generation > current.Generation {
			current = item
		} else if item.Generation == current.Generation && current.ManifestDigest != item.ManifestDigest {
			return current, errors.New("conflicting component security generation slots")
		}
	}
	if found && current.Generation == 0 {
		return current, errors.New("component security watermark corrupted; refusing downgrade")
	}
	return current, nil
}

func writeComponentWatermark02311(root string, item componentGenerationRecord02311) error {
	if item.Generation == 0 {
		return nil
	}
	old, err := loadComponentWatermark02311(root)
	if err != nil {
		return err
	}
	if old.Generation > item.Generation {
		return errors.New("cannot decrease component security watermark")
	}
	if old.Generation == item.Generation {
		if old.ManifestDigest != item.ManifestDigest {
			return errors.New("component generation equivocation")
		}
		return nil
	}
	item.Schema = 1
	dest := filepath.Join(root, fmt.Sprintf("%s-%d.json", componentSecurityState02311, item.Generation%2))
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	return writeJSONFileAtomicMode(dest, item, 0o600)
}

func checkComponentGeneration02311(root string, m componentUpdateManifest0157) error {
	floor, err := loadComponentWatermark02311(root)
	if err != nil {
		return err
	}
	if m.SecurityGeneration < floor.Generation {
		return fmt.Errorf("component anti-rollback: signed generation %d below previously accepted %d", m.SecurityGeneration, floor.Generation)
	}
	if m.SecurityGeneration == floor.Generation && floor.Generation > 0 && componentDigest02311(m) != floor.ManifestDigest {
		return errors.New("component generation reused for a different signed set")
	}
	// A verified installed state can be ahead of the watermark if power was lost
	// after atomic commit but before recording the separate watermark.
	statePath := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	st, available, err := readComponentUpdateStateOptional01510(statePath)
	if err != nil {
		return err
	}
	if available && st.SecurityGeneration > m.SecurityGeneration {
		return fmt.Errorf("component anti-rollback: installed generation %d above candidate %d", st.SecurityGeneration, m.SecurityGeneration)
	}
	if available && st.SecurityGeneration == m.SecurityGeneration && st.SecurityGeneration > 0 && st.ManifestDigest != componentDigest02311(m) {
		return errors.New("candidate conflicts with installed component security generation")
	}
	return nil
}

func commitComponentGeneration02311(root string, m componentUpdateManifest0157) error {
	if m.SecurityGeneration == 0 {
		return nil
	}
	path := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	st, present, err := readComponentUpdateStateOptional01510(path)
	if err != nil {
		return err
	}
	if !present || st.SecurityGeneration != m.SecurityGeneration || st.ManifestDigest != componentDigest02311(m) {
		return errors.New("cannot record generation until committed component state matches signed set")
	}
	return writeComponentWatermark02311(root, componentGenerationRecord02311{Generation: st.SecurityGeneration, ManifestDigest: st.ManifestDigest})
}

func reconcileInstalledComponentGeneration02311(root string) error {
	path := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	st, present, err := readComponentUpdateStateOptional01510(path)
	if err != nil {
		return err
	}
	floor, err := loadComponentWatermark02311(root)
	if err != nil {
		return err
	}
	if !present {
		if floor.Generation > 0 {
			return errors.New("component security state missing after generation was accepted")
		}
		return nil
	}
	if st.SecurityGeneration < floor.Generation {
		return errors.New("installed component set is below security watermark")
	}
	if st.SecurityGeneration == floor.Generation && floor.Generation > 0 && st.ManifestDigest != floor.ManifestDigest {
		return errors.New("installed component manifest differs from security watermark")
	}
	if st.SecurityGeneration == 0 {
		return nil
	}
	if !componentSecurityRequired02311(st.Version) || len(st.ManifestDigest) != 64 || strings.TrimSpace(st.ManifestDigest) == "" {
		return errors.New("installed security generation state is malformed")
	}
	if st.SecurityGeneration > floor.Generation {
		// Never raise floor on the basis of an unverified local state alone.
		// The active component tree must match every recorded SHA-256.
		verifyRoot := root
		if st.Platform == "macos" {
			if filepath.Base(st.BundleName) != st.BundleName || !strings.HasSuffix(strings.ToLower(st.BundleName), ".app") {
				return errors.New("macOS active bundle name missing/unsafe in component security state")
			}
			verifyRoot = filepath.Join(root, st.BundleName)
			info, err := os.Lstat(verifyRoot)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("macOS active component bundle is not a trusted directory")
			}
		}
		for _, item := range append(append([]componentUpdateArtifact0157{}, st.Components...), st.SupportFiles...) {
			if err := validateComponentRelativePath0157(item.TargetPath); err != nil {
				return err
			}
			full := filepath.Join(verifyRoot, filepath.FromSlash(item.TargetPath))
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("component %s path is missing or is not a regular file", item.Component)
			}
			if err := verifyUpdaterFile0156(full, item.Size, item.SHA256); err != nil {
				return fmt.Errorf("cannot reconcile unverified installed component %s: %w", item.Component, err)
			}
		}
		return writeComponentWatermark02311(root, componentGenerationRecord02311{Generation: st.SecurityGeneration, ManifestDigest: st.ManifestDigest})
	}
	return nil
}
