package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoaderResolutionLockRoundTripAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fabric-resolution-lock.json")
	lock := loaderResolutionLock{
		Loader: "fabric", MinecraftVersion: "1.21.1", Selector: "latest-stable", ResolvedVersion: "0.16.10",
		LoaderMaven:            "net.fabricmc:fabric-loader:0.16.10",
		ResolutionSourceURL:    "https://meta.fabricmc.net/v2/versions/loader/1.21.1",
		ResolutionSourceSHA256: strings.Repeat("1", 64),
		PayloadURL:             "https://meta.fabricmc.net/v2/versions/loader/1.21.1/0.16.10/profile/json",
		PayloadSHA256:          strings.Repeat("2", 64), RuntimeProfileSHA256: strings.Repeat("3", 64), MaterializationSHA256: strings.Repeat("4", 64),
	}
	persisted, lockSHA, err := persistLoaderResolutionLock(path, lock)
	if err != nil {
		t.Fatal(err)
	}
	if !compatibilitySHA256RE.MatchString(lockSHA) || !compatibilitySHA256RE.MatchString(persisted.ReproducibilitySHA256) {
		t.Fatalf("invalid lock hashes: lock=%s reproducibility=%s", lockSHA, persisted.ReproducibilitySHA256)
	}
	loaded, err := readLoaderResolutionLock(path, "fabric", "1.21.1", "latest-stable")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ResolvedVersion != "0.16.10" || loaded.ReproducibilitySHA256 != persisted.ReproducibilitySHA256 {
		t.Fatalf("round trip mismatch: %+v", loaded)
	}
	if _, err := readLoaderResolutionLock(path, "fabric", "1.21.1", "0.16.10"); err != nil {
		t.Fatalf("explicit replay of the exact pinned version must be accepted: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tampered map[string]any
	if err := json.Unmarshal(raw, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["payloadSha256"] = strings.Repeat("4", 64)
	bad, _ := json.MarshalIndent(tampered, "", "  ")
	if err := os.WriteFile(path, append(bad, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLoaderResolutionLock(path, "fabric", "1.21.1", "latest-stable"); err == nil || !strings.Contains(err.Error(), "reproducibility SHA-256 mismatch") {
		t.Fatalf("tampered lock must fail reproducibility validation, got %v", err)
	}
}

func TestLoaderResolutionLockRejectsMutableResolvedVersion(t *testing.T) {
	lock := loaderResolutionLock{
		SchemaVersion: loaderResolutionLockSchema, Loader: "quilt", MinecraftVersion: "1.21.1", Selector: "latest-stable", ResolvedVersion: "latest-stable",
		ResolutionSourceURL: "https://meta.quiltmc.org/v3/versions/loader/1.21.1", ResolutionSourceSHA256: strings.Repeat("1", 64),
		PayloadURL: "https://meta.quiltmc.org/v3/versions/loader/1.21.1/latest-stable/profile/json", PayloadSHA256: strings.Repeat("2", 64),
		RuntimeProfileSHA256: strings.Repeat("3", 64), MaterializationSHA256: strings.Repeat("4", 64), ReproducibilitySHA256: strings.Repeat("5", 64),
	}
	if err := validateLoaderResolutionLock(&lock, "quilt", "1.21.1", "latest-stable", true); err == nil || !strings.Contains(err.Error(), "immutable resolvedVersion") {
		t.Fatalf("mutable resolved version accepted: %v", err)
	}
}
