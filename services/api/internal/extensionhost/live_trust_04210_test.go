package extensionhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
)

func liveTrustFixture04210(t *testing.T) (*Supervisor, repository.Repository, *processState) {
	t.Helper()
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	id := "example.live-trust"
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Live trust", Version: "1.0.0", Publisher: "example", API: "1.0", Permissions: []string{"storage:read"}}
	if _, err := repo.SaveExtensionVersion(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	install, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
		DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled,
		Enabled: true, Operation: "install", ExpectedGeneration: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: id, Scope: "global", Permission: "storage:read", GrantedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	host := New(Config{ExtensionRoot: t.TempDir()}, repo, storage.NewLocalStorage(t.TempDir()))
	st := &processState{key: Key{ExtensionID: id, Scope: "global"}, install: install, manifest: manifest, state: "running"}
	return host, repo, st
}

func TestLivePermissionRevocationIsImmediate04210(t *testing.T) {
	ctx := context.Background()
	host, repo, st := liveTrustFixture04210(t)
	if ok, err := host.permissionAllowed0207(ctx, st, "storage:read", ""); !ok || err != nil {
		t.Fatalf("initial grant rejected: %v", err)
	}
	if err := repo.RevokeExtensionPermission(ctx, st.key.ExtensionID, "global", "", "storage:read"); err != nil {
		t.Fatal(err)
	}
	if ok, err := host.permissionAllowed0207(ctx, st, "storage:read", ""); ok || err != nil {
		t.Fatalf("revoked grant still effective: %v", err)
	}
}

func TestLiveEmergencyDisableAndQuarantine04210(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"emergency", "quarantine"} {
		t.Run(mode, func(t *testing.T) {
			host, repo, st := liveTrustFixture04210(t)
			if mode == "emergency" {
				if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "incident", Source: "test"}); err != nil {
					t.Fatal(err)
				}
			} else {
				st.install.CurrentPackageIdentity = "sha256:" + strings.Repeat("a", 64)
				if _, err := repo.SaveExtensionQuarantine(ctx, model.ExtensionQuarantineEntry{ID: "q-live-04210", ExtensionID: st.key.ExtensionID, Version: "1.0.0", PackageIdentity: st.install.CurrentPackageIdentity, ArtifactSHA256: strings.Repeat("a", 64), Reason: "incident"}); err != nil {
					t.Fatal(err)
				}
				// Deliberately no persisted change to the installation: the new
				// quarantine alone must be sufficient to revoke the live token.
			}
			if ok, err := host.permissionAllowed0207(ctx, st, "storage:read", ""); ok || err == nil {
				t.Fatalf("revoked live authority accepted: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestLiveUpdateRejectsOldProcess04210(t *testing.T) {
	ctx := context.Background()
	host, repo, st := liveTrustFixture04210(t)
	if _, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{
		ExtensionID: st.key.ExtensionID, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0",
		DesiredState: model.ExtensionInstallStateDisabled, CurrentState: model.ExtensionInstallStateDisabled,
		Enabled: false, Operation: "disable", ExpectedGeneration: st.install.Generation,
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := host.permissionAllowed0207(ctx, st, "storage:read", ""); ok || err == nil {
		t.Fatalf("disabled installation accepted: ok=%v err=%v", ok, err)
	}
}

func TestMonitorTerminatesRevokedProcess04210(t *testing.T) {
	ctx := context.Background()
	host, repo, st := liveTrustFixture04210(t)
	if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "incident", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	host.processes[st.key.String()] = st
	host.monitorOnce(time.Now())
	st.mu.Lock()
	state, stopped := st.state, st.expectedStop
	st.mu.Unlock()
	if !stopped || state != "failing" {
		t.Fatalf("idle revoked host not terminated: %s expectedStop=%t", state, stopped)
	}
}

// The actual HTTP capability endpoint must reject a valid pre-revocation
// bearer token, not merely expose a revoked flag through management APIs.
func TestRevokedHostTokenCannotUseBroker04210(t *testing.T) {
	ctx := context.Background()
	host, repo, st := liveTrustFixture04210(t)
	st.token = strings.Repeat("a", 64)
	host.tokens[st.token] = st
	host.processes[st.key.String()] = st
	invoke := func() int {
		req := httptest.NewRequest(http.MethodPost, "/v1/capabilities/runtime.storage.get", strings.NewReader(`{"key":"sample"}`))
		req.RemoteAddr = "127.0.0.1:12345"
		req.SetPathValue("capability", "runtime.storage.get")
		req.Header.Set("Authorization", "Bearer "+st.token)
		rec := httptest.NewRecorder()
		host.handleCapability(rec, req)
		return rec.Code
	}
	// Before revocation the broker reaches document storage. Missing state
	// must NOT be classified as revoked or unavailable.
	if code := invoke(); code != http.StatusNotFound {
		t.Fatalf("initial capability failed: %d", code)
	}
	if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "security incident", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	if code := invoke(); code != http.StatusServiceUnavailable {
		t.Fatalf("revoked host token still reaches storage: %d", code)
	}
	st.mu.Lock()
	stopped := st.expectedStop
	st.mu.Unlock()
	if !stopped {
		t.Fatal("host was not terminated on broker revocation")
	}
}
