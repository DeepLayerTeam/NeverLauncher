package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const loaderResolutionLockSchema = "1.0"

type loaderResolutionLock struct {
	SchemaVersion          string `json:"schemaVersion"`
	Loader                 string `json:"loader"`
	MinecraftVersion       string `json:"minecraftVersion"`
	Selector               string `json:"selector"`
	ResolvedVersion        string `json:"resolvedVersion"`
	ArtifactVersion        string `json:"artifactVersion,omitempty"`
	LoaderMaven            string `json:"loaderMaven,omitempty"`
	IntermediaryMaven      string `json:"intermediaryMaven,omitempty"`
	ResolutionSourceURL    string `json:"resolutionSourceUrl"`
	ResolutionSourceSHA256 string `json:"resolutionSourceSha256"`
	PayloadURL             string `json:"payloadUrl"`
	PayloadSHA256          string `json:"payloadSha256"`
	RuntimeProfileSHA256   string `json:"runtimeProfileSha256"`
	MaterializationSHA256  string `json:"materializationSha256"`
	ReproducibilitySHA256  string `json:"reproducibilitySha256"`
}

func defaultLoaderResolutionLockPath(clientDir, loader string) string {
	return filepath.Join(clientDir, ".neverlauncher", strings.ToLower(strings.TrimSpace(loader))+"-resolution-lock.json")
}

func isMutableLoaderSelector(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "latest", "latest-stable", "stable", "recommended":
		return true
	default:
		return false
	}
}

func sha256HexBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func explicitResolutionSource(loader, minecraft, selector, resolved, artifact string) (string, string) {
	source := fmt.Sprintf("explicit:%s:%s", strings.ToLower(strings.TrimSpace(loader)), strings.TrimSpace(minecraft))
	identity := strings.Join([]string{source, strings.TrimSpace(selector), strings.TrimSpace(resolved), strings.TrimSpace(artifact)}, "\x00")
	return source, sha256HexBytes([]byte(identity))
}

func readLoaderResolutionLock(path, loader, minecraft, selector string) (*loaderResolutionLock, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read loader resolution lock: %w", err)
	}
	var lock loaderResolutionLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("loader resolution lock JSON повреждён: %w", err)
	}
	if err := validateLoaderResolutionLock(&lock, loader, minecraft, selector, true); err != nil {
		return nil, err
	}
	expectedRepro := loaderResolutionReproducibilitySHA256(lock)
	if lock.ReproducibilitySHA256 != expectedRepro {
		return nil, fmt.Errorf("loader resolution lock reproducibility SHA-256 mismatch: expected %s got %s", expectedRepro, lock.ReproducibilitySHA256)
	}
	return &lock, nil
}

func validateLoaderResolutionLock(lock *loaderResolutionLock, loader, minecraft, selector string, complete bool) error {
	if lock == nil {
		return errors.New("loader resolution lock отсутствует")
	}
	if lock.SchemaVersion != loaderResolutionLockSchema {
		return fmt.Errorf("loader resolution lock schemaVersion=%q, expected %s", lock.SchemaVersion, loaderResolutionLockSchema)
	}
	expectedLoader := strings.ToLower(strings.TrimSpace(loader))
	expectedSelector := strings.TrimSpace(selector)
	selectorMatches := lock.Selector == expectedSelector
	if !selectorMatches && !isMutableLoaderSelector(expectedSelector) {
		selectorMatches = expectedSelector == lock.ResolvedVersion || expectedSelector == lock.ArtifactVersion
	}
	if lock.Loader != expectedLoader || lock.MinecraftVersion != strings.TrimSpace(minecraft) || !selectorMatches {
		return fmt.Errorf("loader resolution lock identity mismatch: got %s/%s selector=%s resolved=%s, expected %s/%s selector=%s", lock.Loader, lock.MinecraftVersion, lock.Selector, lock.ResolvedVersion, expectedLoader, strings.TrimSpace(minecraft), expectedSelector)
	}
	if lock.ResolvedVersion == "" || isMutableLoaderSelector(lock.ResolvedVersion) {
		return errors.New("loader resolution lock не содержит immutable resolvedVersion")
	}
	if lock.ResolutionSourceURL == "" || !compatibilitySHA256RE.MatchString(strings.ToLower(lock.ResolutionSourceSHA256)) {
		return errors.New("loader resolution lock не содержит resolution source identity")
	}
	if complete {
		if lock.PayloadURL == "" || !compatibilitySHA256RE.MatchString(strings.ToLower(lock.PayloadSHA256)) {
			return errors.New("loader resolution lock не содержит pinned payload SHA-256")
		}
		if !compatibilitySHA256RE.MatchString(strings.ToLower(lock.RuntimeProfileSHA256)) {
			return errors.New("loader resolution lock не содержит runtime profile SHA-256")
		}
		if !compatibilitySHA256RE.MatchString(strings.ToLower(lock.MaterializationSHA256)) {
			return errors.New("loader resolution lock не содержит materialization SHA-256")
		}
		if !compatibilitySHA256RE.MatchString(strings.ToLower(lock.ReproducibilitySHA256)) {
			return errors.New("loader resolution lock не содержит reproducibility SHA-256")
		}
	}
	return nil
}

func loaderResolutionReproducibilitySHA256(lock loaderResolutionLock) string {
	canonical := struct {
		SchemaVersion          string `json:"schemaVersion"`
		Loader                 string `json:"loader"`
		MinecraftVersion       string `json:"minecraftVersion"`
		Selector               string `json:"selector"`
		ResolvedVersion        string `json:"resolvedVersion"`
		ArtifactVersion        string `json:"artifactVersion,omitempty"`
		LoaderMaven            string `json:"loaderMaven,omitempty"`
		IntermediaryMaven      string `json:"intermediaryMaven,omitempty"`
		ResolutionSourceURL    string `json:"resolutionSourceUrl"`
		ResolutionSourceSHA256 string `json:"resolutionSourceSha256"`
		PayloadURL             string `json:"payloadUrl"`
		PayloadSHA256          string `json:"payloadSha256"`
		RuntimeProfileSHA256   string `json:"runtimeProfileSha256"`
		MaterializationSHA256  string `json:"materializationSha256"`
	}{
		SchemaVersion:          lock.SchemaVersion,
		Loader:                 lock.Loader,
		MinecraftVersion:       lock.MinecraftVersion,
		Selector:               lock.Selector,
		ResolvedVersion:        lock.ResolvedVersion,
		ArtifactVersion:        lock.ArtifactVersion,
		LoaderMaven:            lock.LoaderMaven,
		IntermediaryMaven:      lock.IntermediaryMaven,
		ResolutionSourceURL:    lock.ResolutionSourceURL,
		ResolutionSourceSHA256: strings.ToLower(lock.ResolutionSourceSHA256),
		PayloadURL:             lock.PayloadURL,
		PayloadSHA256:          strings.ToLower(lock.PayloadSHA256),
		RuntimeProfileSHA256:   strings.ToLower(lock.RuntimeProfileSHA256),
		MaterializationSHA256:  strings.ToLower(lock.MaterializationSHA256),
	}
	raw, _ := json.Marshal(canonical)
	return sha256HexBytes(raw)
}

func persistLoaderResolutionLock(path string, lock loaderResolutionLock) (loaderResolutionLock, string, error) {
	lock.SchemaVersion = loaderResolutionLockSchema
	lock.Loader = strings.ToLower(strings.TrimSpace(lock.Loader))
	lock.ResolutionSourceSHA256 = strings.ToLower(strings.TrimSpace(lock.ResolutionSourceSHA256))
	lock.PayloadSHA256 = strings.ToLower(strings.TrimSpace(lock.PayloadSHA256))
	lock.RuntimeProfileSHA256 = strings.ToLower(strings.TrimSpace(lock.RuntimeProfileSHA256))
	lock.MaterializationSHA256 = strings.ToLower(strings.TrimSpace(lock.MaterializationSHA256))
	lock.ReproducibilitySHA256 = loaderResolutionReproducibilitySHA256(lock)
	if err := validateLoaderResolutionLock(&lock, lock.Loader, lock.MinecraftVersion, lock.Selector, true); err != nil {
		return loaderResolutionLock{}, "", err
	}
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return loaderResolutionLock{}, "", err
	}
	raw = append(raw, '\n')
	if err := writeAtomicBytes(path, raw, 0o600); err != nil {
		return loaderResolutionLock{}, "", fmt.Errorf("write loader resolution lock: %w", err)
	}
	return lock, sha256HexBytes(raw), nil
}

func assertPinnedPayload(lock *loaderResolutionLock, payloadURL string, payload []byte) error {
	if lock == nil {
		return nil
	}
	if lock.PayloadURL != payloadURL {
		return fmt.Errorf("loader resolution lock payload URL mismatch: pinned %s got %s", lock.PayloadURL, payloadURL)
	}
	actual := sha256HexBytes(payload)
	if !strings.EqualFold(lock.PayloadSHA256, actual) {
		return fmt.Errorf("loader resolution lock payload SHA-256 mismatch: pinned %s got %s", lock.PayloadSHA256, actual)
	}
	return nil
}

func assertPinnedPayloadSHA256(lock *loaderResolutionLock, payloadURL, actualSHA256 string) error {
	if lock == nil {
		return nil
	}
	if lock.PayloadURL != payloadURL {
		return fmt.Errorf("loader resolution lock payload URL mismatch: pinned %s got %s", lock.PayloadURL, payloadURL)
	}
	if !strings.EqualFold(lock.PayloadSHA256, strings.TrimSpace(actualSHA256)) {
		return fmt.Errorf("loader resolution lock payload SHA-256 mismatch: pinned %s got %s", lock.PayloadSHA256, actualSHA256)
	}
	return nil
}

func assertPinnedRuntimeProfile(lock *loaderResolutionLock, actualSHA256 string) error {
	if lock == nil {
		return nil
	}
	if !strings.EqualFold(lock.RuntimeProfileSHA256, strings.TrimSpace(actualSHA256)) {
		return fmt.Errorf("loader resolution lock runtime profile SHA-256 mismatch: pinned %s got %s", lock.RuntimeProfileSHA256, actualSHA256)
	}
	return nil
}

func loaderMaterializationSHA256(files []vanillaDownloadedFile) string {
	type row struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	rows := make([]row, 0, len(files))
	for _, file := range files {
		rows = append(rows, row{
			Path:   filepath.ToSlash(strings.TrimSpace(file.Path)),
			SHA256: strings.ToLower(strings.TrimSpace(file.SHA256)),
			Size:   file.Size,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		if rows[i].SHA256 != rows[j].SHA256 {
			return rows[i].SHA256 < rows[j].SHA256
		}
		return rows[i].Size < rows[j].Size
	})
	raw, _ := json.Marshal(rows)
	return sha256HexBytes(raw)
}

func assertPinnedMaterialization(lock *loaderResolutionLock, actual string) error {
	if lock == nil {
		return nil
	}
	actual = strings.ToLower(strings.TrimSpace(actual))
	if actual != strings.ToLower(strings.TrimSpace(lock.MaterializationSHA256)) {
		return fmt.Errorf("loader materialization SHA-256 mismatch: lock=%s actual=%s", lock.MaterializationSHA256, actual)
	}
	return nil
}
