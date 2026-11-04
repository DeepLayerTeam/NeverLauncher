package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/config"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type incidentTransitionError0424 struct{ repository.Repository }

func (r incidentTransitionError0424) TransitionExtensionInstall(context.Context, model.ExtensionLifecycleTransition) (model.ExtensionInstall, error) {
	return model.ExtensionInstall{}, errors.New("durable transition unavailable")
}

func TestEmergencyDisablePersistsDenyEvenWhenStateTransitionFails0424(t *testing.T) {
	ctx := context.Background()
	base := repository.NewMemoryRepository("http://localhost")
	id := "example.incident"
	if _, err := base.SaveExtensionVersion(ctx, model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Incident", Version: "1.0.0", Publisher: "test.publisher", API: "1.0"}); err != nil {
		t.Fatal(err)
	}
	_, err := base.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, Enabled: true, Operation: "install", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	srv := Server{Repo: incidentTransitionError0424{base}, Config: config.Config{ExtensionRoot: t.TempDir()}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/extensions/example.incident/emergency-disable", strings.NewReader(`{"reason":"security incident","scope":"global"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("extensionId", id)
	rec := httptest.NewRecorder()
	srv.extensionEmergencyDisable02012(rec, req)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "kill-switch active") {
		t.Fatalf("failure not disclosed as persisted deny: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := base.GetExtensionEmergencyDisable(ctx, id, "global", ""); err != nil {
		t.Fatalf("kill-switch missing on failed disable: %v", err)
	}
}

func TestTrustSweepQuarantinesActiveLocalPackage0424(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewMemoryRepository("http://localhost")
	id := "example.active-local"
	identity := "sha256:" + strings.Repeat("a", 64)
	if _, err := repo.SaveExtensionVersion(ctx, model.ExtensionManifest{SchemaVersion: "2.0", ID: id, Name: "Local", Version: "1.0.0", Publisher: "test.publisher", API: "1.0"}); err != nil {
		t.Fatal(err)
	}
	_, err := repo.TransitionExtensionInstall(ctx, model.ExtensionLifecycleTransition{ExtensionID: id, Scope: "global", DesiredVersion: "1.0.0", CurrentVersion: "1.0.0", DesiredState: model.ExtensionInstallStateEnabled, CurrentState: model.ExtensionInstallStateEnabled, Enabled: true, PackageIdentity: identity, CurrentPackageIdentity: identity, Source: "local:dev", Operation: "install", ExpectedGeneration: 0})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.SaveExtensionQuarantine(ctx, model.ExtensionQuarantineEntry{ID: "q-active-local", PackageIdentity: identity, ArtifactSHA256: strings.Repeat("b", 64), Reason: "incident"})
	if err != nil {
		t.Fatal(err)
	}
	srv := Server{Repo: repo, Config: config.Config{ExtensionRoot: t.TempDir()}}
	blocked, err := srv.enforceExtensionTrustRuntime02012(ctx, "quarantine-test")
	if err != nil || blocked != 1 {
		t.Fatalf("sweep failed to disable active quarantined package: blocked=%d err=%v", blocked, err)
	}
	if _, err := repo.GetExtensionEmergencyDisable(ctx, id, "global", ""); err != nil {
		t.Fatalf("kill-switch not persisted: %v", err)
	}
	after, err := repo.GetExtensionInstallState(ctx, id, "global", "")
	if err != nil || after.CurrentState != model.ExtensionInstallStateDisabled {
		t.Fatalf("quarantined package remained enabled: %+v %v", after, err)
	}
}
