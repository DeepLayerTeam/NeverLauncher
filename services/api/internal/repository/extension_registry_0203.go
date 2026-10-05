package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var (
	registryPublisherID0203 = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	registryChannel0203     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	registryIdentity0203    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	registrySHA0203         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func normalizeRegistryPublisher0203(in model.ExtensionRegistryPublisher) (model.ExtensionRegistryPublisher, error) {
	in.ID = strings.ToLower(strings.TrimSpace(in.ID))
	in.Name = strings.TrimSpace(in.Name)
	if !registryPublisherID0203.MatchString(in.ID) {
		return model.ExtensionRegistryPublisher{}, fmt.Errorf("invalid registry publisher id %q", in.ID)
	}
	if in.Name == "" || len(in.Name) > 160 {
		return model.ExtensionRegistryPublisher{}, errors.New("registry publisher name must contain 1..160 characters")
	}
	return in, nil
}

func normalizeRegistryPublisherKey0203(in model.ExtensionRegistryPublisherKey) (model.ExtensionRegistryPublisherKey, error) {
	in.PublisherID = strings.ToLower(strings.TrimSpace(in.PublisherID))
	in.Fingerprint = strings.ToLower(strings.TrimSpace(in.Fingerprint))
	in.Algorithm = strings.TrimSpace(in.Algorithm)
	in.PublicKeyBase64 = strings.TrimSpace(in.PublicKeyBase64)
	if !registryPublisherID0203.MatchString(in.PublisherID) {
		return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("invalid registry publisher id %q", in.PublisherID)
	}
	if in.Algorithm == "" {
		in.Algorithm = "Ed25519"
	}
	if in.Algorithm != "Ed25519" {
		return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("unsupported publisher key algorithm %q", in.Algorithm)
	}
	raw, err := base64.StdEncoding.DecodeString(in.PublicKeyBase64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return model.ExtensionRegistryPublisherKey{}, errors.New("publisher publicKeyBase64 must contain a raw 32-byte Ed25519 public key")
	}
	digest := sha256.Sum256(raw)
	expected := "sha256:" + hex.EncodeToString(digest[:])
	if in.Fingerprint == "" {
		in.Fingerprint = expected
	}
	if in.Fingerprint != expected || !registryIdentity0203.MatchString(in.Fingerprint) {
		return model.ExtensionRegistryPublisherKey{}, errors.New("publisher key fingerprint does not match public key")
	}
	return in, nil
}

func normalizeRegistryCompatibility0203(in model.ExtensionRegistryCompatibility) (model.ExtensionRegistryCompatibility, error) {
	in.MinNeverLauncher = strings.TrimSpace(in.MinNeverLauncher)
	in.MaxNeverLauncher = strings.TrimSpace(in.MaxNeverLauncher)
	if in.MinNeverLauncher != "" && !extensionSemver0201.MatchString(in.MinNeverLauncher) {
		return model.ExtensionRegistryCompatibility{}, fmt.Errorf("invalid minNeverLauncher %q", in.MinNeverLauncher)
	}
	if in.MaxNeverLauncher != "" && !extensionSemver0201.MatchString(in.MaxNeverLauncher) {
		return model.ExtensionRegistryCompatibility{}, fmt.Errorf("invalid maxNeverLauncher %q", in.MaxNeverLauncher)
	}
	if in.MinNeverLauncher != "" && in.MaxNeverLauncher != "" && compareRegistrySemver0203(in.MinNeverLauncher, in.MaxNeverLauncher) > 0 {
		return model.ExtensionRegistryCompatibility{}, errors.New("minNeverLauncher cannot be greater than maxNeverLauncher")
	}
	normalizePlatform := func(values []string, field string) ([]string, error) {
		seen := map[string]struct{}{}
		out := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}
			if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`).MatchString(value) {
				return nil, fmt.Errorf("invalid %s value %q", field, value)
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
	in.SupportedOS, err = normalizePlatform(in.SupportedOS, "supportedOs")
	if err != nil {
		return model.ExtensionRegistryCompatibility{}, err
	}
	in.SupportedArchitectures, err = normalizePlatform(in.SupportedArchitectures, "supportedArchitectures")
	if err != nil {
		return model.ExtensionRegistryCompatibility{}, err
	}
	return in, nil
}

func normalizeRegistryChannels0203(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if !registryChannel0203.MatchString(value) {
			return nil, fmt.Errorf("invalid registry channel %q", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		out = []string{"stable"}
	}
	sort.Strings(out)
	return out, nil
}

func normalizeRegistryPublication0203(in model.ExtensionRegistryPublication) (model.ExtensionRegistryPublication, string, error) {
	manifest, manifestDigest, err := NormalizeExtensionManifest(in.Manifest)
	if err != nil {
		return model.ExtensionRegistryPublication{}, "", err
	}
	in.Manifest = manifest
	in.PublisherID = strings.ToLower(strings.TrimSpace(in.PublisherID))
	if !registryPublisherID0203.MatchString(in.PublisherID) || manifest.Publisher != in.PublisherID {
		return model.ExtensionRegistryPublication{}, "", errors.New("registry publisher id must exactly match canonical manifest publisher")
	}
	in.Compatibility, err = normalizeRegistryCompatibility0203(in.Compatibility)
	if err != nil {
		return model.ExtensionRegistryPublication{}, "", err
	}
	in.Channels, err = normalizeRegistryChannels0203(in.Channels)
	if err != nil {
		return model.ExtensionRegistryPublication{}, "", err
	}
	artifact := in.Artifact
	artifact.ExtensionID = strings.ToLower(strings.TrimSpace(artifact.ExtensionID))
	artifact.Version = strings.TrimSpace(artifact.Version)
	artifact.PackageIdentity = strings.ToLower(strings.TrimSpace(artifact.PackageIdentity))
	artifact.SHA256 = strings.ToLower(strings.TrimSpace(artifact.SHA256))
	artifact.SignatureKeyFingerprint = strings.ToLower(strings.TrimSpace(artifact.SignatureKeyFingerprint))
	artifact.StorageProject = strings.TrimSpace(artifact.StorageProject)
	artifact.StorageVersion = strings.TrimSpace(artifact.StorageVersion)
	artifact.StoragePath = strings.TrimSpace(artifact.StoragePath)
	if artifact.ExtensionID != manifest.ID || artifact.Version != manifest.Version {
		return model.ExtensionRegistryPublication{}, "", errors.New("registry artifact extension/version does not match canonical manifest")
	}
	if !registryIdentity0203.MatchString(artifact.PackageIdentity) || !registrySHA0203.MatchString(artifact.SHA256) || !registryIdentity0203.MatchString(artifact.SignatureKeyFingerprint) {
		return model.ExtensionRegistryPublication{}, "", errors.New("registry artifact contains invalid package identity, SHA-256 or key fingerprint")
	}
	if artifact.Size <= 0 || artifact.StorageProject == "" || artifact.StorageVersion == "" || artifact.StoragePath == "" {
		return model.ExtensionRegistryPublication{}, "", errors.New("registry artifact storage metadata is incomplete")
	}
	in.Artifact = artifact
	return in, manifestDigest, nil
}

func compatibilityMatches0203(c model.ExtensionRegistryCompatibility, launcherVersion, osName, arch string) bool {
	launcherVersion = strings.TrimSpace(launcherVersion)
	if launcherVersion != "" {
		if !extensionSemver0201.MatchString(launcherVersion) {
			return false
		}
		if c.MinNeverLauncher != "" && compareRegistrySemver0203(launcherVersion, c.MinNeverLauncher) < 0 {
			return false
		}
		if c.MaxNeverLauncher != "" && compareRegistrySemver0203(launcherVersion, c.MaxNeverLauncher) > 0 {
			return false
		}
	}
	contains := func(values []string, value string) bool {
		if len(values) == 0 || strings.TrimSpace(value) == "" {
			return true
		}
		value = strings.ToLower(strings.TrimSpace(value))
		for _, item := range values {
			if item == value {
				return true
			}
		}
		return false
	}
	return contains(c.SupportedOS, osName) && contains(c.SupportedArchitectures, arch)
}

type registrySemver0203 struct {
	major, minor, patch int
	pre                 []string
}

func parseRegistrySemver0203(value string) registrySemver0203 {
	value = strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(value, "-", 2)
	core := strings.Split(parts[0], ".")
	v := registrySemver0203{}
	if len(core) == 3 {
		v.major, _ = strconv.Atoi(core[0])
		v.minor, _ = strconv.Atoi(core[1])
		v.patch, _ = strconv.Atoi(core[2])
	}
	if len(parts) == 2 {
		v.pre = strings.Split(parts[1], ".")
	}
	return v
}

func compareRegistrySemver0203(a, b string) int {
	x, y := parseRegistrySemver0203(a), parseRegistrySemver0203(b)
	for _, pair := range [][2]int{{x.major, y.major}, {x.minor, y.minor}, {x.patch, y.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if len(x.pre) == 0 && len(y.pre) == 0 {
		return 0
	}
	if len(x.pre) == 0 {
		return 1
	}
	if len(y.pre) == 0 {
		return -1
	}
	max := len(x.pre)
	if len(y.pre) > max {
		max = len(y.pre)
	}
	for i := 0; i < max; i++ {
		if i >= len(x.pre) {
			return -1
		}
		if i >= len(y.pre) {
			return 1
		}
		xi, xe := strconv.Atoi(x.pre[i])
		yi, ye := strconv.Atoi(y.pre[i])
		if xe == nil && ye == nil {
			if xi < yi {
				return -1
			}
			if xi > yi {
				return 1
			}
			continue
		}
		if xe == nil && ye != nil {
			return -1
		}
		if xe != nil && ye == nil {
			return 1
		}
		if x.pre[i] < y.pre[i] {
			return -1
		}
		if x.pre[i] > y.pre[i] {
			return 1
		}
	}
	return 0
}

func equalRegistryCompatibility0203(a, b model.ExtensionRegistryCompatibility) bool {
	return a.MinNeverLauncher == b.MinNeverLauncher && a.MaxNeverLauncher == b.MaxNeverLauncher && strings.Join(a.SupportedOS, "\x00") == strings.Join(b.SupportedOS, "\x00") && strings.Join(a.SupportedArchitectures, "\x00") == strings.Join(b.SupportedArchitectures, "\x00")
}

func (r *MemoryRepository) SaveExtensionRegistryPublisher(ctx context.Context, publisher model.ExtensionRegistryPublisher) (model.ExtensionRegistryPublisher, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionRegistryPublisher{}, err
	}
	publisher, err := normalizeRegistryPublisher0203(publisher)
	if err != nil {
		return model.ExtensionRegistryPublisher{}, err
	}
	now := time.Now().UTC()
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionRegistryPublishers {
		if r.extensionRegistryPublishers[i].ID == publisher.ID {
			publisher.CreatedAt = r.extensionRegistryPublishers[i].CreatedAt
			publisher.UpdatedAt = now
			r.extensionRegistryPublishers[i] = publisher
			return publisher, nil
		}
	}
	publisher.CreatedAt, publisher.UpdatedAt = now, now
	r.extensionRegistryPublishers = append(r.extensionRegistryPublishers, publisher)
	return publisher, nil
}

func (r *MemoryRepository) ListExtensionRegistryPublishers(ctx context.Context) ([]model.ExtensionRegistryPublisher, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := append([]model.ExtensionRegistryPublisher(nil), r.extensionRegistryPublishers...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (r *MemoryRepository) SaveExtensionRegistryPublisherKey(ctx context.Context, key model.ExtensionRegistryPublisherKey) (model.ExtensionRegistryPublisherKey, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	key, err := normalizeRegistryPublisherKey0203(key)
	if err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	now := time.Now().UTC()
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	publisherActive := false
	for _, publisher := range r.extensionRegistryPublishers {
		if publisher.ID == key.PublisherID {
			publisherActive = publisher.Active
			break
		}
	}
	if !publisherActive {
		return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("%w: active registry publisher not found", ErrNotFound)
	}
	for i := range r.extensionRegistryKeys {
		existing := r.extensionRegistryKeys[i]
		if existing.Fingerprint != key.Fingerprint {
			continue
		}
		if existing.PublisherID != key.PublisherID || existing.PublicKeyBase64 != key.PublicKeyBase64 {
			return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("%w: publisher key fingerprint already belongs to another key", ErrConflict)
		}
		if existing.RevokedAt != nil && key.Active {
			return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("%w: revoked publisher key cannot be reactivated", ErrImmutable)
		}
		key.CreatedAt = existing.CreatedAt
		r.extensionRegistryKeys[i] = key
		return key, nil
	}
	key.CreatedAt = now
	r.extensionRegistryKeys = append(r.extensionRegistryKeys, key)
	return key, nil
}

func (r *MemoryRepository) GetExtensionRegistryPublisherKey(ctx context.Context, publisherID, fingerprint string) (model.ExtensionRegistryPublisherKey, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	publisherID, fingerprint = strings.ToLower(strings.TrimSpace(publisherID)), strings.ToLower(strings.TrimSpace(fingerprint))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, key := range r.extensionRegistryKeys {
		if key.PublisherID == publisherID && key.Fingerprint == fingerprint {
			return key, nil
		}
	}
	return model.ExtensionRegistryPublisherKey{}, ErrNotFound
}

func (r *MemoryRepository) ListExtensionRegistryPublisherKeys(ctx context.Context, publisherID string) ([]model.ExtensionRegistryPublisherKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	publisherID = strings.ToLower(strings.TrimSpace(publisherID))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionRegistryPublisherKey, 0)
	for _, key := range r.extensionRegistryKeys {
		if key.PublisherID == publisherID {
			out = append(out, key)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (r *MemoryRepository) PublishExtensionRegistryVersion(ctx context.Context, publication model.ExtensionRegistryPublication) (model.ExtensionRegistryVersion, error) {
	publication, _, err := normalizeRegistryPublication0203(publication)
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	// Reject untrusted publications before touching canonical core state. The
	// SQL path provides the stronger equivalent by doing both operations in one
	// serializable transaction.
	r.extensionMu.Lock()
	publisherActive, keyActive := false, false
	for _, publisher := range r.extensionRegistryPublishers {
		if publisher.ID == publication.PublisherID && publisher.Active {
			publisherActive = true
		}
	}
	for _, key := range r.extensionRegistryKeys {
		if key.PublisherID == publication.PublisherID && key.Fingerprint == publication.Artifact.SignatureKeyFingerprint && key.Active && key.RevokedAt == nil {
			keyActive = true
		}
	}
	r.extensionMu.Unlock()
	if !publisherActive || !keyActive {
		return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: publisher or signing key is not active", ErrConflict)
	}
	if _, err := r.SaveExtensionVersion(ctx, publication.Manifest); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, existing := range r.extensionRegistryVersions {
		if existing.Artifact.PackageIdentity == publication.Artifact.PackageIdentity && (existing.ExtensionID != publication.Manifest.ID || existing.Version != publication.Manifest.Version) {
			return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: package identity is already published", ErrConflict)
		}
	}
	for i := range r.extensionRegistryVersions {
		existing := r.extensionRegistryVersions[i]
		if existing.ExtensionID == publication.Manifest.ID && existing.Version == publication.Manifest.Version {
			if existing.PublisherID != publication.PublisherID || existing.Artifact.PackageIdentity != publication.Artifact.PackageIdentity || existing.Artifact.SHA256 != publication.Artifact.SHA256 || existing.Artifact.Size != publication.Artifact.Size || !equalRegistryCompatibility0203(existing.Compatibility, publication.Compatibility) {
				return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: registry version is immutable", ErrImmutable)
			}
			if existing.YankedAt != nil {
				return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: yanked registry version cannot be republished", ErrImmutable)
			}
			existing.Channels = mergeRegistryChannels0203(r.extensionRegistryVersions, publication.Manifest.ID, publication.Manifest.Version, publication.Channels)
			r.extensionRegistryVersions[i].Channels = existing.Channels
			return existing, nil
		}
	}
	now := time.Now().UTC()
	publication.Artifact.CreatedAt = now
	item := model.ExtensionRegistryVersion{ExtensionID: publication.Manifest.ID, Version: publication.Manifest.Version, PublisherID: publication.PublisherID, Manifest: publication.Manifest, Compatibility: publication.Compatibility, Artifact: publication.Artifact, Channels: append([]string(nil), publication.Channels...), PublishedAt: now}
	for i := range r.extensionRegistryVersions {
		filtered := r.extensionRegistryVersions[i].Channels[:0]
		for _, channel := range r.extensionRegistryVersions[i].Channels {
			move := r.extensionRegistryVersions[i].ExtensionID == item.ExtensionID && containsRegistryChannel0203(item.Channels, channel)
			if !move {
				filtered = append(filtered, channel)
			}
		}
		r.extensionRegistryVersions[i].Channels = filtered
	}
	r.extensionRegistryVersions = append(r.extensionRegistryVersions, item)
	return item, nil
}

func mergeRegistryChannels0203(items []model.ExtensionRegistryVersion, extensionID, version string, channels []string) []string {
	out := append([]string(nil), channels...)
	sort.Strings(out)
	return out
}

func containsRegistryChannel0203(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (r *MemoryRepository) SearchExtensionRegistry(ctx context.Context, query model.ExtensionRegistrySearch) ([]model.ExtensionRegistryVersion, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query.Query))
	channel := strings.ToLower(strings.TrimSpace(query.Channel))
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	out := make([]model.ExtensionRegistryVersion, 0)
	for _, item := range r.extensionRegistryVersions {
		if item.YankedAt != nil && !query.IncludeYanked {
			continue
		}
		if channel != "" && !containsRegistryChannel0203(item.Channels, channel) {
			continue
		}
		if !compatibilityMatches0203(item.Compatibility, query.LauncherVersion, query.OS, query.Architecture) {
			continue
		}
		if q != "" {
			haystack := strings.ToLower(item.ExtensionID + " " + item.Manifest.Name + " " + item.Manifest.Description + " " + item.PublisherID)
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.After(out[j].PublishedAt) })
	return out, nil
}

func (r *MemoryRepository) GetExtensionRegistryVersion(ctx context.Context, extensionID, version string) (model.ExtensionRegistryVersion, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	extensionID, version = strings.ToLower(strings.TrimSpace(extensionID)), strings.TrimSpace(version)
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for _, item := range r.extensionRegistryVersions {
		if item.ExtensionID == extensionID && item.Version == version {
			return item, nil
		}
	}
	return model.ExtensionRegistryVersion{}, ErrNotFound
}

func (r *MemoryRepository) GetExtensionRegistryExtension(ctx context.Context, extensionID string) (model.ExtensionRegistryExtension, error) {
	identity, err := r.GetExtension(ctx, extensionID)
	if err != nil {
		return model.ExtensionRegistryExtension{}, err
	}
	items, err := r.SearchExtensionRegistry(ctx, model.ExtensionRegistrySearch{IncludeYanked: true})
	if err != nil {
		return model.ExtensionRegistryExtension{}, err
	}
	versions := make([]model.ExtensionRegistryVersion, 0)
	for _, item := range items {
		if item.ExtensionID == identity.ID {
			versions = append(versions, item)
		}
	}
	if len(versions) == 0 {
		return model.ExtensionRegistryExtension{}, ErrNotFound
	}
	return model.ExtensionRegistryExtension{Extension: identity, Versions: versions}, nil
}

func (r *MemoryRepository) SetExtensionRegistryChannel(ctx context.Context, extensionID, channel, version string) (model.ExtensionRegistryVersion, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	extensionID, channel, version = strings.ToLower(strings.TrimSpace(extensionID)), strings.ToLower(strings.TrimSpace(channel)), strings.TrimSpace(version)
	if !registryChannel0203.MatchString(channel) {
		return model.ExtensionRegistryVersion{}, fmt.Errorf("invalid registry channel %q", channel)
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	target := -1
	for i := range r.extensionRegistryVersions {
		if r.extensionRegistryVersions[i].ExtensionID == extensionID && r.extensionRegistryVersions[i].Version == version {
			if r.extensionRegistryVersions[i].YankedAt != nil {
				return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: cannot target a yanked version", ErrConflict)
			}
			target = i
		}
	}
	if target < 0 {
		return model.ExtensionRegistryVersion{}, ErrNotFound
	}
	for i := range r.extensionRegistryVersions {
		if r.extensionRegistryVersions[i].ExtensionID != extensionID {
			continue
		}
		filtered := r.extensionRegistryVersions[i].Channels[:0]
		for _, current := range r.extensionRegistryVersions[i].Channels {
			if current != channel {
				filtered = append(filtered, current)
			}
		}
		r.extensionRegistryVersions[i].Channels = filtered
	}
	if !containsRegistryChannel0203(r.extensionRegistryVersions[target].Channels, channel) {
		r.extensionRegistryVersions[target].Channels = append(r.extensionRegistryVersions[target].Channels, channel)
		sort.Strings(r.extensionRegistryVersions[target].Channels)
	}
	return r.extensionRegistryVersions[target], nil
}

func (r *MemoryRepository) YankExtensionRegistryVersion(ctx context.Context, extensionID, version, reason string) (model.ExtensionRegistryVersion, error) {
	if err := ctx.Err(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	extensionID, version, reason = strings.ToLower(strings.TrimSpace(extensionID)), strings.TrimSpace(version), strings.TrimSpace(reason)
	if reason == "" || len(reason) > 500 {
		return model.ExtensionRegistryVersion{}, errors.New("yank reason must contain 1..500 characters")
	}
	r.extensionMu.Lock()
	defer r.extensionMu.Unlock()
	for i := range r.extensionRegistryVersions {
		item := &r.extensionRegistryVersions[i]
		if item.ExtensionID != extensionID || item.Version != version {
			continue
		}
		if item.YankedAt != nil {
			if item.YankReason != reason {
				return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: yank state is irreversible", ErrImmutable)
			}
			return *item, nil
		}
		now := time.Now().UTC()
		item.YankedAt, item.YankReason, item.Channels = &now, reason, nil
		return *item, nil
	}
	return model.ExtensionRegistryVersion{}, ErrNotFound
}

func (r *SQLRepository) SaveExtensionRegistryPublisher(ctx context.Context, publisher model.ExtensionRegistryPublisher) (model.ExtensionRegistryPublisher, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryPublisher{}, err
	}
	publisher, err := normalizeRegistryPublisher0203(publisher)
	if err != nil {
		return model.ExtensionRegistryPublisher{}, err
	}
	err = r.db.QueryRowContext(ctx, `INSERT INTO extension_registry_publishers(id,name,active) VALUES($1,$2,$3)
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,active=EXCLUDED.active,updated_at=now()
RETURNING id,name,active,created_at,updated_at`, publisher.ID, publisher.Name, publisher.Active).Scan(&publisher.ID, &publisher.Name, &publisher.Active, &publisher.CreatedAt, &publisher.UpdatedAt)
	return publisher, err
}

func (r *SQLRepository) ListExtensionRegistryPublishers(ctx context.Context) ([]model.ExtensionRegistryPublisher, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,active,created_at,updated_at FROM extension_registry_publishers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ExtensionRegistryPublisher, 0)
	for rows.Next() {
		var item model.ExtensionRegistryPublisher
		if err := rows.Scan(&item.ID, &item.Name, &item.Active, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanRegistryPublisherKey0203(scanner interface{ Scan(...any) error }) (model.ExtensionRegistryPublisherKey, error) {
	var item model.ExtensionRegistryPublisherKey
	var revoked sql.NullTime
	if err := scanner.Scan(&item.PublisherID, &item.Fingerprint, &item.Algorithm, &item.PublicKeyBase64, &item.Active, &item.CreatedAt, &revoked); err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	if revoked.Valid {
		item.RevokedAt = &revoked.Time
	}
	return item, nil
}

func (r *SQLRepository) SaveExtensionRegistryPublisherKey(ctx context.Context, key model.ExtensionRegistryPublisherKey) (model.ExtensionRegistryPublisherKey, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	key, err := normalizeRegistryPublisherKey0203(key)
	if err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	var publisherActive bool
	if err := r.db.QueryRowContext(ctx, `SELECT active FROM extension_registry_publishers WHERE id=$1`, key.PublisherID).Scan(&publisherActive); errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryPublisherKey{}, ErrNotFound
	} else if err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	} else if !publisherActive {
		return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("%w: publisher is inactive", ErrConflict)
	}
	existing, err := scanRegistryPublisherKey0203(r.db.QueryRowContext(ctx, `SELECT publisher_id,fingerprint,algorithm,public_key_base64,active,created_at,revoked_at FROM extension_registry_publisher_keys WHERE fingerprint=$1`, key.Fingerprint))
	if err == nil {
		if existing.PublisherID != key.PublisherID || existing.PublicKeyBase64 != key.PublicKeyBase64 {
			return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("%w: publisher key fingerprint already belongs to another key", ErrConflict)
		}
		if existing.RevokedAt != nil && key.Active {
			return model.ExtensionRegistryPublisherKey{}, fmt.Errorf("%w: revoked publisher key cannot be reactivated", ErrImmutable)
		}
		_, err = r.db.ExecContext(ctx, `UPDATE extension_registry_publisher_keys SET active=$3 WHERE publisher_id=$1 AND fingerprint=$2`, key.PublisherID, key.Fingerprint, key.Active)
		if err != nil {
			return model.ExtensionRegistryPublisherKey{}, err
		}
		return scanRegistryPublisherKey0203(r.db.QueryRowContext(ctx, `SELECT publisher_id,fingerprint,algorithm,public_key_base64,active,created_at,revoked_at FROM extension_registry_publisher_keys WHERE publisher_id=$1 AND fingerprint=$2`, key.PublisherID, key.Fingerprint))
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	return scanRegistryPublisherKey0203(r.db.QueryRowContext(ctx, `INSERT INTO extension_registry_publisher_keys(publisher_id,fingerprint,algorithm,public_key_base64,active) VALUES($1,$2,$3,$4,$5)
RETURNING publisher_id,fingerprint,algorithm,public_key_base64,active,created_at,revoked_at`, key.PublisherID, key.Fingerprint, key.Algorithm, key.PublicKeyBase64, key.Active))
}

func (r *SQLRepository) GetExtensionRegistryPublisherKey(ctx context.Context, publisherID, fingerprint string) (model.ExtensionRegistryPublisherKey, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryPublisherKey{}, err
	}
	item, err := scanRegistryPublisherKey0203(r.db.QueryRowContext(ctx, `SELECT publisher_id,fingerprint,algorithm,public_key_base64,active,created_at,revoked_at FROM extension_registry_publisher_keys WHERE publisher_id=$1 AND fingerprint=$2`, strings.ToLower(strings.TrimSpace(publisherID)), strings.ToLower(strings.TrimSpace(fingerprint))))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryPublisherKey{}, ErrNotFound
	}
	return item, err
}

func (r *SQLRepository) ListExtensionRegistryPublisherKeys(ctx context.Context, publisherID string) ([]model.ExtensionRegistryPublisherKey, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT publisher_id,fingerprint,algorithm,public_key_base64,active,created_at,revoked_at FROM extension_registry_publisher_keys WHERE publisher_id=$1 ORDER BY created_at`, strings.ToLower(strings.TrimSpace(publisherID)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ExtensionRegistryPublisherKey, 0)
	for rows.Next() {
		item, err := scanRegistryPublisherKey0203(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func saveExtensionVersionTx0203(ctx context.Context, tx *sql.Tx, manifest model.ExtensionManifest, digest string) (model.ExtensionVersion, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return model.ExtensionVersion{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO extensions(id,name,publisher,description,homepage,repository) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING`, manifest.ID, manifest.Name, manifest.Publisher, manifest.Description, manifest.Homepage, manifest.Repository); err != nil {
		return model.ExtensionVersion{}, err
	}
	var publisher string
	if err := tx.QueryRowContext(ctx, `SELECT publisher FROM extensions WHERE id=$1 FOR UPDATE`, manifest.ID).Scan(&publisher); err != nil {
		return model.ExtensionVersion{}, err
	}
	if publisher != manifest.Publisher {
		return model.ExtensionVersion{}, fmt.Errorf("%w: extension publisher is immutable", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE extensions SET name=$2,description=$3,homepage=$4,repository=$5,updated_at=now() WHERE id=$1`, manifest.ID, manifest.Name, manifest.Description, manifest.Homepage, manifest.Repository); err != nil {
		return model.ExtensionVersion{}, err
	}
	var existingDigest string
	var existingCreated time.Time
	err = tx.QueryRowContext(ctx, `SELECT manifest_sha256,created_at FROM extension_versions WHERE extension_id=$1 AND version=$2 FOR UPDATE`, manifest.ID, manifest.Version).Scan(&existingDigest, &existingCreated)
	if err == nil {
		if existingDigest != digest {
			return model.ExtensionVersion{}, fmt.Errorf("%w: extension %s version %s already exists with another manifest", ErrImmutable, manifest.ID, manifest.Version)
		}
		return extensionVersionFromManifest0201(manifest, digest, existingCreated), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionVersion{}, err
	}
	var created time.Time
	if err := tx.QueryRowContext(ctx, `INSERT INTO extension_versions(extension_id,version,schema_version,api,manifest,manifest_sha256) VALUES($1,$2,$3,$4,$5::jsonb,$6) RETURNING created_at`, manifest.ID, manifest.Version, manifest.SchemaVersion, manifest.API, string(raw), digest).Scan(&created); err != nil {
		return model.ExtensionVersion{}, err
	}
	for _, permission := range manifest.Permissions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_permissions(extension_id,version,permission) VALUES($1,$2,$3)`, manifest.ID, manifest.Version, permission); err != nil {
			return model.ExtensionVersion{}, err
		}
	}
	for _, dep := range manifest.Dependencies {
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_dependencies(extension_id,version,dependency_id,version_constraint,optional) VALUES($1,$2,$3,$4,$5)`, manifest.ID, manifest.Version, dep.ID, dep.Version, dep.Optional); err != nil {
			return model.ExtensionVersion{}, err
		}
	}
	return extensionVersionFromManifest0201(manifest, digest, created), nil
}

func (r *SQLRepository) PublishExtensionRegistryVersion(ctx context.Context, publication model.ExtensionRegistryPublication) (model.ExtensionRegistryVersion, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	publication, manifestDigest, err := normalizeRegistryPublication0203(publication)
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	compatOS, _ := json.Marshal(publication.Compatibility.SupportedOS)
	compatArch, _ := json.Marshal(publication.Compatibility.SupportedArchitectures)
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	defer tx.Rollback()
	var publisherActive bool
	if err := tx.QueryRowContext(ctx, `SELECT active FROM extension_registry_publishers WHERE id=$1 FOR UPDATE`, publication.PublisherID).Scan(&publisherActive); errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryVersion{}, ErrNotFound
	} else if err != nil {
		return model.ExtensionRegistryVersion{}, err
	} else if !publisherActive {
		return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: publisher is inactive", ErrConflict)
	}
	var keyActive bool
	var keyPublisher string
	var revoked sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT publisher_id,active,revoked_at FROM extension_registry_publisher_keys WHERE fingerprint=$1 FOR SHARE`, publication.Artifact.SignatureKeyFingerprint).Scan(&keyPublisher, &keyActive, &revoked); errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: trusted publisher key not found", ErrNotFound)
	} else if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	if keyPublisher != publication.PublisherID || !keyActive || revoked.Valid {
		return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: signing key is not active for publisher", ErrConflict)
	}
	if _, err := saveExtensionVersionTx0203(ctx, tx, publication.Manifest, manifestDigest); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	var existingPublisher, existingIdentity, existingSHA, existingMin, existingMax string
	var existingSize int64
	var existingOS, existingArch []byte
	err = tx.QueryRowContext(ctx, `SELECT rv.publisher_id,a.package_identity,a.sha256,a.size_bytes,c.min_neverlauncher,c.max_neverlauncher,c.supported_os,c.supported_architectures
FROM extension_registry_versions rv
JOIN extension_registry_artifacts a ON a.extension_id=rv.extension_id AND a.version=rv.version
JOIN extension_registry_compatibility c ON c.extension_id=rv.extension_id AND c.version=rv.version
WHERE rv.extension_id=$1 AND rv.version=$2 FOR UPDATE`, publication.Manifest.ID, publication.Manifest.Version).Scan(&existingPublisher, &existingIdentity, &existingSHA, &existingSize, &existingMin, &existingMax, &existingOS, &existingArch)
	if err == nil {
		var existingCompatibility model.ExtensionRegistryCompatibility
		existingCompatibility.MinNeverLauncher, existingCompatibility.MaxNeverLauncher = existingMin, existingMax
		if json.Unmarshal(existingOS, &existingCompatibility.SupportedOS) != nil || json.Unmarshal(existingArch, &existingCompatibility.SupportedArchitectures) != nil {
			return model.ExtensionRegistryVersion{}, errors.New("registry contains invalid compatibility metadata")
		}
		if existingPublisher != publication.PublisherID || existingIdentity != publication.Artifact.PackageIdentity || existingSHA != publication.Artifact.SHA256 || existingSize != publication.Artifact.Size || !equalRegistryCompatibility0203(existingCompatibility, publication.Compatibility) {
			return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: registry version already exists with different immutable publication metadata", ErrImmutable)
		}
		var yanked bool
		if err := tx.QueryRowContext(ctx, `SELECT yanked_at IS NOT NULL FROM extension_registry_versions WHERE extension_id=$1 AND version=$2`, publication.Manifest.ID, publication.Manifest.Version).Scan(&yanked); err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
		if yanked {
			return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: yanked registry version cannot be republished", ErrImmutable)
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_registry_versions(extension_id,version,publisher_id) VALUES($1,$2,$3)`, publication.Manifest.ID, publication.Manifest.Version, publication.PublisherID); err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_registry_compatibility(extension_id,version,min_neverlauncher,max_neverlauncher,supported_os,supported_architectures) VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb)`, publication.Manifest.ID, publication.Manifest.Version, publication.Compatibility.MinNeverLauncher, publication.Compatibility.MaxNeverLauncher, string(compatOS), string(compatArch)); err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_registry_artifacts(package_identity,extension_id,version,sha256,size_bytes,storage_project,storage_version,storage_path,signature_key_fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, publication.Artifact.PackageIdentity, publication.Manifest.ID, publication.Manifest.Version, publication.Artifact.SHA256, publication.Artifact.Size, publication.Artifact.StorageProject, publication.Artifact.StorageVersion, publication.Artifact.StoragePath, publication.Artifact.SignatureKeyFingerprint); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: package identity already published", ErrConflict)
			}
			return model.ExtensionRegistryVersion{}, err
		}
	} else {
		return model.ExtensionRegistryVersion{}, err
	}
	for _, channel := range publication.Channels {
		if _, err := tx.ExecContext(ctx, `INSERT INTO extension_registry_channels(extension_id,channel,version) VALUES($1,$2,$3)
ON CONFLICT(extension_id,channel) DO UPDATE SET version=EXCLUDED.version,updated_at=now()`, publication.Manifest.ID, channel, publication.Manifest.Version); err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	return r.GetExtensionRegistryVersion(ctx, publication.Manifest.ID, publication.Manifest.Version)
}

func scanRegistryVersionBase0203(scanner interface{ Scan(...any) error }) (model.ExtensionRegistryVersion, error) {
	var item model.ExtensionRegistryVersion
	var rawManifest, rawOS, rawArch []byte
	var yanked sql.NullTime
	if err := scanner.Scan(&item.ExtensionID, &item.Version, &item.PublisherID, &rawManifest, &item.Compatibility.MinNeverLauncher, &item.Compatibility.MaxNeverLauncher, &rawOS, &rawArch, &item.Artifact.PackageIdentity, &item.Artifact.SHA256, &item.Artifact.Size, &item.Artifact.StorageProject, &item.Artifact.StorageVersion, &item.Artifact.StoragePath, &item.Artifact.SignatureKeyFingerprint, &item.Artifact.CreatedAt, &item.PublishedAt, &yanked, &item.YankReason); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	if err := json.Unmarshal(rawManifest, &item.Manifest); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	if err := json.Unmarshal(rawOS, &item.Compatibility.SupportedOS); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	if err := json.Unmarshal(rawArch, &item.Compatibility.SupportedArchitectures); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	item.Artifact.ExtensionID, item.Artifact.Version = item.ExtensionID, item.Version
	if yanked.Valid {
		item.YankedAt = &yanked.Time
	}
	return item, nil
}

func (r *SQLRepository) GetExtensionRegistryVersion(ctx context.Context, extensionID, version string) (model.ExtensionRegistryVersion, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	item, err := scanRegistryVersionBase0203(r.db.QueryRowContext(ctx, `SELECT rv.extension_id,rv.version,rv.publisher_id,ev.manifest,c.min_neverlauncher,c.max_neverlauncher,c.supported_os,c.supported_architectures,
a.package_identity,a.sha256,a.size_bytes,a.storage_project,a.storage_version,a.storage_path,a.signature_key_fingerprint,a.created_at,rv.published_at,rv.yanked_at,rv.yank_reason
FROM extension_registry_versions rv
JOIN extension_versions ev ON ev.extension_id=rv.extension_id AND ev.version=rv.version
JOIN extension_registry_compatibility c ON c.extension_id=rv.extension_id AND c.version=rv.version
JOIN extension_registry_artifacts a ON a.extension_id=rv.extension_id AND a.version=rv.version
WHERE rv.extension_id=$1 AND rv.version=$2`, strings.ToLower(strings.TrimSpace(extensionID)), strings.TrimSpace(version)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryVersion{}, ErrNotFound
	}
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT channel FROM extension_registry_channels WHERE extension_id=$1 AND version=$2 ORDER BY channel`, item.ExtensionID, item.Version)
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var channel string
		if err := rows.Scan(&channel); err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
		item.Channels = append(item.Channels, channel)
	}
	return item, rows.Err()
}

func (r *SQLRepository) SearchExtensionRegistry(ctx context.Context, query model.ExtensionRegistrySearch) ([]model.ExtensionRegistryVersion, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	q, channel := strings.TrimSpace(query.Query), strings.ToLower(strings.TrimSpace(query.Channel))
	osName, arch := strings.ToLower(strings.TrimSpace(query.OS)), strings.ToLower(strings.TrimSpace(query.Architecture))
	rows, err := r.db.QueryContext(ctx, `SELECT rv.extension_id,rv.version
FROM extension_registry_versions rv
JOIN extensions e ON e.id=rv.extension_id
JOIN extension_registry_compatibility c ON c.extension_id=rv.extension_id AND c.version=rv.version
WHERE ($1='' OR e.id ILIKE '%'||$1||'%' OR e.name ILIKE '%'||$1||'%' OR e.description ILIKE '%'||$1||'%' OR rv.publisher_id ILIKE '%'||$1||'%')
  AND ($2='' OR EXISTS(SELECT 1 FROM extension_registry_channels ch WHERE ch.extension_id=rv.extension_id AND ch.version=rv.version AND ch.channel=$2))
  AND ($3='' OR jsonb_array_length(c.supported_os)=0 OR c.supported_os ? $3)
  AND ($4='' OR jsonb_array_length(c.supported_architectures)=0 OR c.supported_architectures ? $4)
  AND ($5 OR rv.yanked_at IS NULL)
ORDER BY rv.published_at DESC,rv.extension_id,rv.version DESC LIMIT 1000`, q, channel, osName, arch, query.IncludeYanked)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct{ id, version string }
	keys := make([]key, 0)
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.id, &k.version); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]model.ExtensionRegistryVersion, 0, len(keys))
	for _, k := range keys {
		item, err := r.GetExtensionRegistryVersion(ctx, k.id, k.version)
		if err != nil {
			return nil, err
		}
		if !compatibilityMatches0203(item.Compatibility, query.LauncherVersion, osName, arch) {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func (r *SQLRepository) GetExtensionRegistryExtension(ctx context.Context, extensionID string) (model.ExtensionRegistryExtension, error) {
	identity, err := r.GetExtension(ctx, extensionID)
	if err != nil {
		return model.ExtensionRegistryExtension{}, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT version FROM extension_registry_versions WHERE extension_id=$1 ORDER BY published_at DESC,version DESC`, identity.ID)
	if err != nil {
		return model.ExtensionRegistryExtension{}, err
	}
	defer rows.Close()
	versions := make([]string, 0)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return model.ExtensionRegistryExtension{}, err
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return model.ExtensionRegistryExtension{}, err
	}
	if len(versions) == 0 {
		return model.ExtensionRegistryExtension{}, ErrNotFound
	}
	out := model.ExtensionRegistryExtension{Extension: identity, Versions: make([]model.ExtensionRegistryVersion, 0, len(versions))}
	for _, version := range versions {
		item, err := r.GetExtensionRegistryVersion(ctx, identity.ID, version)
		if err != nil {
			return model.ExtensionRegistryExtension{}, err
		}
		out.Versions = append(out.Versions, item)
	}
	return out, nil
}

func (r *SQLRepository) SetExtensionRegistryChannel(ctx context.Context, extensionID, channel, version string) (model.ExtensionRegistryVersion, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	extensionID, channel, version = strings.ToLower(strings.TrimSpace(extensionID)), strings.ToLower(strings.TrimSpace(channel)), strings.TrimSpace(version)
	if !registryChannel0203.MatchString(channel) {
		return model.ExtensionRegistryVersion{}, fmt.Errorf("invalid registry channel %q", channel)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	defer tx.Rollback()
	var yanked bool
	if err := tx.QueryRowContext(ctx, `SELECT yanked_at IS NOT NULL FROM extension_registry_versions WHERE extension_id=$1 AND version=$2 FOR UPDATE`, extensionID, version).Scan(&yanked); errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryVersion{}, ErrNotFound
	} else if err != nil {
		return model.ExtensionRegistryVersion{}, err
	} else if yanked {
		return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: cannot target a yanked version", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO extension_registry_channels(extension_id,channel,version) VALUES($1,$2,$3)
ON CONFLICT(extension_id,channel) DO UPDATE SET version=EXCLUDED.version,updated_at=now()`, extensionID, channel, version); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	return r.GetExtensionRegistryVersion(ctx, extensionID, version)
}

func (r *SQLRepository) YankExtensionRegistryVersion(ctx context.Context, extensionID, version, reason string) (model.ExtensionRegistryVersion, error) {
	if err := r.check(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	extensionID, version, reason = strings.ToLower(strings.TrimSpace(extensionID)), strings.TrimSpace(version), strings.TrimSpace(reason)
	if reason == "" || len(reason) > 500 {
		return model.ExtensionRegistryVersion{}, errors.New("yank reason must contain 1..500 characters")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	defer tx.Rollback()
	var yankedAt sql.NullTime
	var existingReason string
	if err := tx.QueryRowContext(ctx, `SELECT yanked_at,yank_reason FROM extension_registry_versions WHERE extension_id=$1 AND version=$2 FOR UPDATE`, extensionID, version).Scan(&yankedAt, &existingReason); errors.Is(err, sql.ErrNoRows) {
		return model.ExtensionRegistryVersion{}, ErrNotFound
	} else if err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	if yankedAt.Valid {
		if existingReason != reason {
			return model.ExtensionRegistryVersion{}, fmt.Errorf("%w: yank state is irreversible", ErrImmutable)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM extension_registry_channels WHERE extension_id=$1 AND version=$2`, extensionID, version); err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE extension_registry_versions SET yanked_at=now(),yank_reason=$3 WHERE extension_id=$1 AND version=$2`, extensionID, version, reason); err != nil {
			return model.ExtensionRegistryVersion{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.ExtensionRegistryVersion{}, err
	}
	return r.GetExtensionRegistryVersion(ctx, extensionID, version)
}
