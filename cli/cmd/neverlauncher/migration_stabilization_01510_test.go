package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrationStabilization01510MigratesLegacyComponentState(t *testing.T) {
	root := t.TempDir()
	target, err := currentDeliveryTarget()
	if err != nil {
		t.Fatal(err)
	}
	legacy := componentUpdateState0157{
		SchemaVersion: "1.0", ToolVersion: "0.15.9", Version: "0.15.9",
		Platform: target.Platform, Architecture: target.Architecture, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Components: []componentUpdateArtifact0157{
			{Component: "desktop", TargetPath: "desktop", SHA256: strings.Repeat("1", 64), Size: 1, Executable: true},
			{Component: "guard", TargetPath: "guard", SHA256: strings.Repeat("2", 64), Size: 1, Executable: true},
			{Component: "runtime", TargetPath: "runtime", SHA256: strings.Repeat("3", 64), Size: 1, Executable: true},
		},
	}
	legacyPath := filepath.Join(root, filepath.FromSlash(updaterCoreDir0156), "component-update-state.json")
	if err := writeJSONFileAtomicMode(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := migrateComponentUpdateState01510(root)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Migrated || report.Version != "0.15.9" {
		t.Fatalf("unexpected migration report: %+v", report)
	}
	if _, err := os.Stat(legacyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy state still exists: %v", err)
	}
	canonical := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	state, ok, err := readComponentUpdateStateOptional01510(canonical)
	if err != nil || !ok || state.Version != "0.15.9" {
		t.Fatalf("canonical state invalid: ok=%v state=%+v err=%v", ok, state, err)
	}
}

func TestReleaseTrustState01510MigratesAndBindsSameVersionManifest(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "release-trust-state.json")
	rootFP := "sha256:" + strings.Repeat("a", 64)
	legacy := releaseTrustState0158{
		SchemaVersion: releaseSignatureSchema0158, TrustDomain: releaseTrustDomain0158,
		RootFingerprint: rootFP, HighestTrustEpoch: 9, HighestRelease: "0.15.9",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSONFileAtomicMode(statePath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("b", 64)
	ctx := releaseVerificationV2Context{
		Policy:          releaseTrustPolicy0158{Epoch: 10},
		Envelope:        releaseSignatureEnvelopeV2{ReleaseVersion: "0.15.10", ReleaseManifestSHA256: digest, KeyFingerprint: "sha256:" + strings.Repeat("c", 64)},
		RootFingerprint: rootFP, StatePath: statePath,
	}
	if err := commitTrustState0158(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := loadTrustState0158(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.SchemaVersion != releaseTrustStateSchema01510 || state.HighestReleaseManifestSHA256 != digest || state.StateRevision != 1 {
		t.Fatalf("unexpected migrated trust state: %+v", state)
	}
	if err := precheckTrustState0158(statePath, rootFP, 10, "0.15.10", strings.Repeat("d", 64)); err == nil {
		t.Fatal("same-version manifest replacement must be rejected")
	}
}

func TestReleaseTrustStateLock01510RejectsConcurrentVerifier(t *testing.T) {
	state := filepath.Join(t.TempDir(), "trust-state.json")
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withReleaseTrustStateLock01510(state, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	if err := withReleaseTrustStateLock01510(state, func() error { return nil }); err == nil {
		close(release)
		<-done
		t.Fatal("concurrent verifier unexpectedly acquired trust-state lock")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTransactionalUpdater01510CleansRollbackPayload(t *testing.T) {
	root := t.TempDir()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.bin"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "app.bin"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	updater, err := newTransactionalUpdater0156(root)
	if err != nil {
		t.Fatal(err)
	}
	spec := updaterTestSpec0156(t, "app.bin", filepath.Join(source, "app.bin"), false)
	if _, err := updater.apply(updaterRequest0156{Root: root, Files: []updaterFileSpec0156{spec}, Verify: func() error { return errors.New("rollback") }}); err == nil {
		t.Fatal("expected rollback")
	}
	txRoot := filepath.Join(updater.controlDir, "transactions")
	entries, err := os.ReadDir(txRoot)
	if err != nil || len(entries) == 0 {
		t.Fatalf("missing transaction journal: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, payload := range []string{"stage", "backup"} {
			if _, err := os.Stat(filepath.Join(txRoot, entry.Name(), payload)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("terminal payload %s still exists: %v", payload, err)
			}
		}
	}
}
