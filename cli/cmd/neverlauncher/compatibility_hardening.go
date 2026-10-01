package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const compatibilityMetadataCacheSchema = "1.0"

type vanillaMetadataCacheRecord struct {
	SchemaVersion     string `json:"schemaVersion"`
	RequestedVersion  string `json:"requestedVersion"`
	ResolvedVersion   string `json:"resolvedVersion"`
	ReleaseType       string `json:"releaseType"`
	ManifestURL       string `json:"manifestUrl"`
	ManifestSHA256    string `json:"manifestSha256"`
	VersionURL        string `json:"versionUrl"`
	VersionSHA1       string `json:"versionSha1"`
	VersionJSONSHA256 string `json:"versionJsonSha256"`
	VersionSize       int64  `json:"versionSize"`
	CachedAt          string `json:"cachedAt"`
}

type vanillaResolvedMetadata struct {
	Selected  MojangManifestVersion
	Bytes     []byte
	Recovered bool
}

func resolveVanillaMetadataWithRecovery(ctx context.Context, client *http.Client, root, manifestURL, requestedVersion string) (vanillaResolvedMetadata, error) {
	manifestBytes, err := fetchJSONBytes(ctx, client, manifestURL, 16<<20)
	if err != nil {
		if cached, cacheErr := loadCachedVanillaMetadata(root, manifestURL, requestedVersion); cacheErr == nil {
			cached.Recovered = true
			return cached, nil
		}
		return vanillaResolvedMetadata{}, fmt.Errorf("Mojang version manifest: %w", err)
	}
	var manifest MojangVersionManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		if cached, cacheErr := loadCachedVanillaMetadata(root, manifestURL, requestedVersion); cacheErr == nil {
			cached.Recovered = true
			return cached, nil
		}
		return vanillaResolvedMetadata{}, fmt.Errorf("Mojang version manifest повреждён: %w", err)
	}
	selectedID := resolveRequestedMinecraftVersion(manifest, requestedVersion)
	selected, ok := findMojangManifestVersion(manifest, selectedID)
	if !ok {
		// A successful authoritative manifest which no longer contains a version is
		// not treated as an outage. Do not resurrect a withdrawn/unknown version
		// from stale local state.
		return vanillaResolvedMetadata{}, fmt.Errorf("Minecraft %s отсутствует в Mojang version manifest", selectedID)
	}
	if selected.URL == "" || selected.SHA1 == "" {
		return vanillaResolvedMetadata{}, fmt.Errorf("Mojang manifest entry %s не содержит URL/SHA1", selectedID)
	}
	if err := validateSHA1Hex(selected.SHA1); err != nil {
		return vanillaResolvedMetadata{}, fmt.Errorf("Mojang manifest entry %s: %w", selectedID, err)
	}
	versionBytes, err := fetchBytesVerified(ctx, client, selected.URL, selected.SHA1, 0, 32<<20, true)
	if err != nil {
		if cached, cacheErr := loadCachedVanillaMetadata(root, manifestURL, requestedVersion); cacheErr == nil && cached.Selected.ID == selected.ID && strings.EqualFold(cached.Selected.SHA1, selected.SHA1) {
			cached.Recovered = true
			return cached, nil
		}
		return vanillaResolvedMetadata{}, fmt.Errorf("version.json %s: %w", selectedID, err)
	}
	if err := saveVanillaMetadataCache(root, manifestURL, requestedVersion, manifestBytes, selected, versionBytes); err != nil {
		return vanillaResolvedMetadata{}, fmt.Errorf("Mojang metadata cache: %w", err)
	}
	return vanillaResolvedMetadata{Selected: selected, Bytes: versionBytes}, nil
}

func exactMinecraftVersionForRecovery(requested string) (string, bool) {
	normalized := strings.TrimSpace(requested)
	switch strings.ToLower(normalized) {
	case "", "latest", "latest-release", "latest-snapshot", "snapshot":
		return "", false
	case "1.0.0":
		return "1.0", true
	default:
		return normalized, normalized != ""
	}
}

func vanillaMetadataCachePaths(root, resolvedVersion string) (string, string, error) {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(resolvedVersion) == "" {
		return "", "", errors.New("metadata cache требует root/version")
	}
	stateDir, err := secureClientDestination(root, ".neverlauncher/upstream-cache")
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(resolvedVersion))
	stem := hex.EncodeToString(digest[:16])
	return filepath.Join(stateDir, stem+".json"), filepath.Join(stateDir, stem+".version.json"), nil
}

func saveVanillaMetadataCache(root, manifestURL, requested string, manifestBytes []byte, selected MojangManifestVersion, versionBytes []byte) error {
	recordPath, payloadPath, err := vanillaMetadataCachePaths(root, selected.ID)
	if err != nil {
		return err
	}
	versionSHA1 := sha1.Sum(versionBytes)
	if !strings.EqualFold(hex.EncodeToString(versionSHA1[:]), selected.SHA1) {
		return errors.New("version metadata не совпадает с Mojang SHA-1 перед cache commit")
	}
	manifestSHA256 := sha256.Sum256(manifestBytes)
	versionSHA256 := sha256.Sum256(versionBytes)
	record := vanillaMetadataCacheRecord{
		SchemaVersion:     compatibilityMetadataCacheSchema,
		RequestedVersion:  strings.TrimSpace(requested),
		ResolvedVersion:   selected.ID,
		ReleaseType:       selected.Type,
		ManifestURL:       strings.TrimSpace(manifestURL),
		ManifestSHA256:    hex.EncodeToString(manifestSHA256[:]),
		VersionURL:        selected.URL,
		VersionSHA1:       strings.ToLower(selected.SHA1),
		VersionJSONSHA256: hex.EncodeToString(versionSHA256[:]),
		VersionSize:       int64(len(versionBytes)),
		CachedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeAtomicBytes(payloadPath, versionBytes, 0o644); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeAtomicBytes(recordPath, raw, 0o644); err != nil {
		return err
	}
	return nil
}

func loadCachedVanillaMetadata(root, manifestURL, requested string) (vanillaResolvedMetadata, error) {
	resolved, exact := exactMinecraftVersionForRecovery(requested)
	if !exact {
		return vanillaResolvedMetadata{}, errors.New("latest/snapshot metadata recovery запрещён: требуется свежий authoritative manifest")
	}
	recordPath, payloadPath, err := vanillaMetadataCachePaths(root, resolved)
	if err != nil {
		return vanillaResolvedMetadata{}, err
	}
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		return vanillaResolvedMetadata{}, err
	}
	var record vanillaMetadataCacheRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return vanillaResolvedMetadata{}, fmt.Errorf("metadata cache record JSON: %w", err)
	}
	if record.SchemaVersion != compatibilityMetadataCacheSchema || record.ResolvedVersion != resolved || strings.TrimSpace(record.ManifestURL) != strings.TrimSpace(manifestURL) {
		return vanillaResolvedMetadata{}, errors.New("metadata cache identity mismatch")
	}
	if err := validateSHA1Hex(record.VersionSHA1); err != nil {
		return vanillaResolvedMetadata{}, err
	}
	if len(record.VersionJSONSHA256) != 64 || !isHex(record.VersionJSONSHA256) || record.VersionSize <= 0 || record.VersionSize > 32<<20 {
		return vanillaResolvedMetadata{}, errors.New("metadata cache integrity fields invalid")
	}
	if err := validateRemoteURL(record.VersionURL); err != nil {
		return vanillaResolvedMetadata{}, fmt.Errorf("metadata cache version URL: %w", err)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return vanillaResolvedMetadata{}, err
	}
	if int64(len(payload)) != record.VersionSize {
		return vanillaResolvedMetadata{}, errors.New("metadata cache size mismatch")
	}
	h1 := sha1.Sum(payload)
	h256 := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(h1[:]), record.VersionSHA1) || !strings.EqualFold(hex.EncodeToString(h256[:]), record.VersionJSONSHA256) {
		return vanillaResolvedMetadata{}, errors.New("metadata cache checksum mismatch")
	}
	var metadata vanillaVersionMetadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return vanillaResolvedMetadata{}, fmt.Errorf("cached version.json invalid: %w", err)
	}
	if metadata.ID != "" && metadata.ID != resolved {
		return vanillaResolvedMetadata{}, fmt.Errorf("cached version.json id mismatch: %s != %s", metadata.ID, resolved)
	}
	return vanillaResolvedMetadata{
		Selected:  MojangManifestVersion{ID: resolved, Type: record.ReleaseType, URL: record.VersionURL, SHA1: strings.ToLower(record.VersionSHA1)},
		Bytes:     payload,
		Recovered: true,
	}, nil
}

func validateSHA1Hex(value string) error {
	value = strings.TrimSpace(value)
	if len(value) != 40 || !isHex(value) {
		return errors.New("SHA-1 должен быть 40-символьным hex")
	}
	return nil
}

func isHex(value string) bool {
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

func quarantineCompatibilityArtifact(root, relative, reason string) (bool, error) {
	destination, err := secureClientDestination(root, relative)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("повреждённый cache artifact имеет небезопасный тип: %s", relative)
	}
	quarantineDir, err := secureClientDestination(root, ".neverlauncher/quarantine")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return false, err
	}
	digest := sha256.Sum256([]byte(filepath.ToSlash(relative)))
	base := filepath.Base(destination)
	name := fmt.Sprintf("%d-%s-%s.broken", time.Now().UnixNano(), hex.EncodeToString(digest[:8]), base)
	target := filepath.Join(quarantineDir, name)
	if err := os.Rename(destination, target); err != nil {
		return false, fmt.Errorf("cache quarantine %s: %w", relative, err)
	}
	_ = os.WriteFile(target+".reason", []byte(strings.TrimSpace(reason)+"\n"), 0o600)
	pruneCompatibilityQuarantine(quarantineDir, 32)
	return true, nil
}

func pruneCompatibilityQuarantine(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil || keep < 1 {
		return
	}
	type item struct {
		path string
		mod  time.Time
	}
	items := make([]item, 0)
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".reason") {
			continue
		}
		info, err := entry.Info()
		if err == nil {
			items = append(items, item{path: filepath.Join(dir, entry.Name()), mod: info.ModTime()})
		}
	}
	if len(items) <= keep {
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.Before(items[j].mod) })
	for _, entry := range items[:len(items)-keep] {
		_ = os.Remove(entry.path)
		_ = os.Remove(entry.path + ".reason")
	}
}

func fetchVerifiedBytesWithLocalCache(ctx context.Context, client *http.Client, root, relative, source, expectedSHA1 string, expectedSize, max int64) ([]byte, bool, bool, error) {
	if err := validateSHA1Hex(expectedSHA1); err != nil {
		return nil, false, false, err
	}
	destination, err := secureClientDestination(root, relative)
	if err != nil {
		return nil, false, false, err
	}
	if ok, _, _ := existingFileMatchesSHA1(destination, expectedSHA1, expectedSize); ok {
		data, err := os.ReadFile(destination)
		return data, true, false, err
	}
	quarantined := false
	if _, err := os.Lstat(destination); err == nil {
		quarantined, err = quarantineCompatibilityArtifact(root, relative, "cached metadata failed pinned SHA-1/size verification")
		if err != nil {
			return nil, false, false, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, false, err
	}
	data, err := fetchBytesVerified(ctx, client, source, expectedSHA1, expectedSize, max, true)
	if err != nil {
		return nil, false, quarantined, err
	}
	if err := writeAtomicBytes(destination, data, 0o644); err != nil {
		return nil, false, quarantined, err
	}
	return data, false, quarantined, nil
}
