package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	prestarter "github.com/DeepLayerTeam/Launcher/prestarter"
)

func installTwoSignedReleases0527(t *testing.T) (Options, *installation, record, record) {
	t.Helper()
	root := t.TempDir()
	opts := signedBundle(t, root, true)
	cfg, _, err := VerifyBundle(opts.Bundle, opts.TrustedKey, true)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts.TrustedKey = hex.EncodeToString(pub)
	sign := func() {
		t.Helper()
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := prestarter.SignedEnvelope(raw, priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(opts.Bundle, "bootstrap.signed.json"), signed, 0600); err != nil {
			t.Fatal(err)
		}
	}
	sign()
	if err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	i, err := newInstall(opts)
	if err != nil {
		t.Fatal(err)
	}
	first, err := i.current()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Branding.DisplayName = "Updated Launcher"
	sign()
	if err := Update(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	second, err := i.current()
	if err != nil {
		t.Fatal(err)
	}
	if first.Release == second.Release || first.Generation != 1 || second.Generation != 2 {
		t.Fatalf("fixture: first=%+v second=%+v", first, second)
	}
	return opts, i, *first, *second
}

func TestInstallerRollbackPreviousSignedRelease0527(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test fixture is POSIX")
	}
	opts, i, first, second := installTwoSignedReleases0527(t)
	save := filepath.Join(opts.Root, "profiles", "project", "saves", "world.dat")
	if err := os.MkdirAll(filepath.Dir(save), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(save, []byte("persist across generations"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	active, err := i.current()
	if err != nil {
		t.Fatal(err)
	}
	if active.Release != first.Release || active.Generation != second.Generation+1 {
		t.Fatalf("wrong rollback active: %+v", active)
	}
	if bytes, err := os.ReadFile(save); err != nil || string(bytes) != "persist across generations" {
		t.Fatalf("game save changed: %s %v", bytes, err)
	}
	if err := VerifyInstalled(opts); err != nil {
		t.Fatal(err)
	}
	// Только что деактивированное поколение сохраняется, позволяя оператору явно
	// снова перейти вперёд через тот же проверенный механизм.
	if err := Rollback(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	active, err = i.current()
	if err != nil || active.Release != second.Release || active.Generation != 4 {
		t.Fatalf("roll-forward mismatch: %+v %v", active, err)
	}
}

func TestInstallerRollbackRejectsCorruptPriorPackage0527(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test fixture is POSIX")
	}
	opts, i, first, second := installTwoSignedReleases0527(t)
	binary := filepath.Join(i.base, "releases", first.Release, binaryName())
	if err := os.WriteFile(binary, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(context.Background(), opts); err == nil {
		t.Fatal("tampered previous signed payload was accepted")
	}
	active, err := i.current()
	if err != nil || active.Release != second.Release || active.Generation != second.Generation {
		t.Fatalf("altered active on rejected rollback: %+v %v", active, err)
	}
}

func TestInstallerRollbackCancellationNeverActivates0527(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test fixture is POSIX")
	}
	opts, i, _, second := installTwoSignedReleases0527(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Rollback(ctx, opts); err == nil {
		t.Fatal("canceled provisioning succeeded")
	}
	active, err := i.current()
	if err != nil || active.Release != second.Release || active.Generation != second.Generation {
		t.Fatalf("rollback advanced on cancellation: %+v %v", active, err)
	}
}

func TestInstallerRollbackRejectsAbsentPreviousGeneration0527(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test fixture is POSIX")
	}
	opts := signedBundle(t, t.TempDir(), true)
	if err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "previous") {
		t.Fatalf("unexpected absent prior: %v", err)
	}
}
