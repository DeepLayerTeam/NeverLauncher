package extensionresolver

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type registryFixture02011 struct {
	repo *repository.MemoryRepository
	fp   string
}

func newRegistryFixture02011(t *testing.T) registryFixture02011 {
	t.Helper()
	r := repository.NewMemoryRepository("http://localhost")
	ctx := context.Background()
	if _, err := r.SaveExtensionRegistryPublisher(ctx, model.ExtensionRegistryPublisher{ID: "publisher.test", Name: "Test Publisher", Active: true}); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("neverextensions-02011-test-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	d := sha256.Sum256(pub)
	fp := "sha256:" + hex.EncodeToString(d[:])
	if _, err := r.SaveExtensionRegistryPublisherKey(ctx, model.ExtensionRegistryPublisherKey{PublisherID: "publisher.test", Fingerprint: fp, Algorithm: "Ed25519", PublicKeyBase64: base64.StdEncoding.EncodeToString(pub), Active: true}); err != nil {
		t.Fatal(err)
	}
	return registryFixture02011{repo: r, fp: fp}
}

func (f registryFixture02011) publish(t *testing.T, id, version string, channels []string, deps []model.ExtensionDependency, conflicts []model.ExtensionConflict) {
	t.Helper()
	h := sha256.Sum256([]byte(id + "@" + version))
	sha := hex.EncodeToString(h[:])
	manifest := model.ExtensionManifest{
		SchemaVersion: "2.0", ID: id, Name: id, Version: version, Publisher: "publisher.test", API: "3.7",
		Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/bin/extension"}}, Dependencies: deps, Conflicts: conflicts,
	}
	_, err := f.repo.PublishExtensionRegistryVersion(context.Background(), model.ExtensionRegistryPublication{
		Manifest: manifest, PublisherID: "publisher.test",
		Compatibility: model.ExtensionRegistryCompatibility{MinNeverLauncher: "0.20.0", MaxNeverLauncher: "0.21.99", MinAPI: "3.7", MaxAPI: "3.7"},
		Artifact:      model.ExtensionRegistryArtifact{PackageIdentity: "sha256:" + sha, ExtensionID: id, Version: version, SHA256: sha, Size: int64(len(id) + len(version) + 1), StorageProject: "registry", StorageVersion: id + "-" + version, StoragePath: sha + ".nlext", SignatureKeyFingerprint: f.fp},
		Channels:      channels,
	})
	if err != nil {
		t.Fatalf("publish %s@%s: %v", id, version, err)
	}
}

func TestSemVerRanges02011(t *testing.T) {
	cases := []struct {
		v, c string
		ok   bool
	}{{"1.4.5", "^1.2.0", true}, {"2.0.0", "^1.2.0", false}, {"0.2.9", "^0.2.0", true}, {"0.3.0", "^0.2.0", false}, {"1.5.0", ">=1.2.0 <2.0.0", true}, {"2.0.0-beta.1", "<2.0.0", true}, {"1.3.7", "~1.3.0", true}, {"1.4.0", "~1.3.0", false}, {"1.9.0", "1.x", true}}
	for _, x := range cases {
		if got := Matches(x.v, x.c); got != x.ok {
			t.Fatalf("Matches(%s,%s)=%v", x.v, x.c, got)
		}
	}
}

func TestResolverRequiredOptionalPinAndChannelFallback02011(t *testing.T) {
	f := newRegistryFixture02011(t)
	f.publish(t, "lib.core", "1.5.0", []string{"stable"}, nil, nil)
	f.publish(t, "lib.core", "2.0.0", []string{"beta"}, nil, nil)
	f.publish(t, "app.main", "2.0.0-beta.1", []string{"beta"}, []model.ExtensionDependency{{ID: "lib.core", Version: "^1.0.0"}, {ID: "missing.optional", Version: "^1.0.0", Optional: true}}, nil)
	r := New(f.repo, Environment{LauncherVersion: "0.20.11", APIVersion: "3.7", OS: "linux", Architecture: "amd64", DefaultChannel: "beta"})
	plan, err := r.Resolve(context.Background(), Scope{Scope: "global"}, []model.ExtensionUpdateRoot{{ExtensionID: "app.main", Channel: "beta"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 2 || plan.Items[0].ExtensionID != "lib.core" || plan.Items[0].ToVersion != "1.5.0" || plan.Items[1].ExtensionID != "app.main" {
		t.Fatalf("unexpected plan: %+v", plan.Items)
	}
	if _, err := f.repo.SetExtensionUpdatePin(context.Background(), model.ExtensionUpdatePin{ExtensionID: "lib.core", Scope: "global", Version: "2.0.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), Scope{Scope: "global"}, []model.ExtensionUpdateRoot{{ExtensionID: "app.main", Channel: "beta"}}); err == nil {
		t.Fatal("incompatible pin was accepted")
	}
}

func TestResolverBacktracksOnConflict02011(t *testing.T) {
	f := newRegistryFixture02011(t)
	f.publish(t, "tool.main", "1.0.0", []string{"stable"}, nil, nil)
	f.publish(t, "tool.main", "2.0.0-beta.1", []string{"beta"}, nil, []model.ExtensionConflict{{ID: "guard.ext", Version: ">=2.0.0"}})
	f.publish(t, "guard.ext", "2.0.0", []string{"stable"}, nil, nil)
	r := New(f.repo, Environment{LauncherVersion: "0.20.11", APIVersion: "3.7", OS: "linux", Architecture: "amd64", DefaultChannel: "beta"})
	plan, err := r.Resolve(context.Background(), Scope{Scope: "global"}, []model.ExtensionUpdateRoot{{ExtensionID: "tool.main", Channel: "beta"}, {ExtensionID: "guard.ext", Version: "2.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]string{}
	for _, item := range plan.Items {
		versions[item.ExtensionID] = item.ToVersion
	}
	if versions["tool.main"] != "1.0.0" {
		t.Fatalf("resolver did not backtrack to stable conflict-free version: %v", versions)
	}
}

func TestResolverCycleDetection02011(t *testing.T) {
	f := newRegistryFixture02011(t)
	f.publish(t, "cycle.aaa", "1.0.0", []string{"stable"}, []model.ExtensionDependency{{ID: "cycle.bbb", Version: "^1.0.0"}}, nil)
	f.publish(t, "cycle.bbb", "1.0.0", []string{"stable"}, []model.ExtensionDependency{{ID: "cycle.aaa", Version: "^1.0.0"}}, nil)
	r := New(f.repo, Environment{LauncherVersion: "0.20.11", APIVersion: "3.7", OS: "linux", Architecture: "amd64"})
	if _, err := r.Resolve(context.Background(), Scope{Scope: "global"}, []model.ExtensionUpdateRoot{{ExtensionID: "cycle.aaa"}}); err == nil {
		t.Fatal("dependency cycle was accepted")
	}
}

func TestResolverRejectsIncompatiblePlatformAndAPI02011(t *testing.T) {
	f := newRegistryFixture02011(t)
	id := "platform.ext"
	h := sha256.Sum256([]byte(id + "@1.0.0"))
	sha := hex.EncodeToString(h[:])
	_, err := f.repo.PublishExtensionRegistryVersion(context.Background(), model.ExtensionRegistryPublication{
		Manifest:    model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: id, Version: "1.0.0", Publisher: "publisher.test", API: "3.8", Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/bin/x"}}},
		PublisherID: "publisher.test", Compatibility: model.ExtensionRegistryCompatibility{MinNeverLauncher: "0.20.0", MinAPI: "3.8", SupportedOS: []string{"windows"}, SupportedArchitectures: []string{"amd64"}},
		Artifact: model.ExtensionRegistryArtifact{PackageIdentity: "sha256:" + sha, ExtensionID: id, Version: "1.0.0", SHA256: sha, Size: 1, StorageProject: "r", StorageVersion: "r", StoragePath: "r", SignatureKeyFingerprint: f.fp}, Channels: []string{"stable"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := New(f.repo, Environment{LauncherVersion: "0.20.11", APIVersion: "3.7", OS: "linux", Architecture: "amd64"})
	if _, err := r.Resolve(context.Background(), Scope{Scope: "global"}, []model.ExtensionUpdateRoot{{ExtensionID: id}}); err == nil {
		t.Fatal("incompatible API/OS candidate was accepted")
	}
	_ = fmt.Sprintf("%v", time.Now()) // keep deterministic imports audited by gofmt/vet
}
