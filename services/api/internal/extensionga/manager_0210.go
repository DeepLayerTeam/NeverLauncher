package extensionga

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensioncontract"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionresolver"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionsecurity"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensiontrust"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

type Issue struct {
	ExtensionID string `json:"extensionId"`
	Scope       string `json:"scope"`
	ScopeID     string `json:"scopeId,omitempty"`
	Version     string `json:"version,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Disabled    bool   `json:"disabled"`
}

type Report struct {
	SchemaVersion string                     `json:"schemaVersion"`
	GeneratedAt   time.Time                  `json:"generatedAt"`
	Contract      extensioncontract.Contract `json:"contract"`
	Checked       int                        `json:"checked"`
	Enabled       int                        `json:"enabled"`
	Healthy       int                        `json:"healthy"`
	Disabled      int                        `json:"disabled"`
	Issues        []Issue                    `json:"issues"`
}

type Manager struct {
	Repo      repository.Repository
	Lifecycle *extensionlifecycle.Manager
}

func New(root string, backupRetention int, repo repository.Repository, store storage.Storage) *Manager {
	return &Manager{Repo: repo, Lifecycle: extensionlifecycle.New(root, backupRetention, repo, store)}
}

type installationKey struct{ scope, scopeID, id string }

func (m *Manager) validateInstall(ctx context.Context, install model.ExtensionInstall, all map[installationKey]model.ExtensionInstall) (string, string) {
	if install.CurrentVersion == "" {
		return "state.version", "active installation has no current version"
	}
	version, err := m.Repo.GetExtensionVersion(ctx, install.ExtensionID, install.CurrentVersion)
	if err != nil {
		return "manifest.missing", "persisted manifest unavailable: " + err.Error()
	}
	if version.Manifest.ID != install.ExtensionID || version.Manifest.Version != install.CurrentVersion {
		return "manifest.identity", "persisted manifest identity does not match installation"
	}
	if _, err := extensioncontract.CanonicalAPIVersion(version.Manifest.API); err != nil {
		return "contract.api", err.Error()
	}
	if version.Manifest.SchemaVersion != extensioncontract.ManifestSchemaVersion {
		return "contract.manifest", fmt.Sprintf("manifest schema %q is not GA schema %s", version.Manifest.SchemaVersion, extensioncontract.ManifestSchemaVersion)
	}
	for _, permission := range version.Manifest.Permissions {
		if !extensionsecurity.IsKnownPermission(permission) {
			return "permissions.unknown", fmt.Sprintf("manifest requests unknown permission %q", permission)
		}
	}
	if err := m.Lifecycle.VerifyLockfile(ctx, install.ExtensionID, extensionlifecycle.Scope{Scope: install.Scope, ScopeID: install.ScopeID}); err != nil {
		return "lifecycle.lockfile", err.Error()
	}
	if _, err := m.Repo.GetExtensionEmergencyDisable(ctx, install.ExtensionID, install.Scope, install.ScopeID); err == nil {
		if install.CurrentState == model.ExtensionInstallStateEnabled || install.Enabled {
			return "trust.emergency-disabled", "enabled state conflicts with persistent emergency-disable"
		}
	} else if !errors.Is(err, repository.ErrNotFound) {
		return "trust.emergency", err.Error()
	}
	if install.CurrentPackageIdentity != "" {
		quarantined, err := m.Repo.IsExtensionPackageQuarantined(ctx, install.CurrentPackageIdentity)
		if err != nil {
			return "trust.quarantine", err.Error()
		}
		if quarantined {
			return "trust.quarantined", "current package is quarantined"
		}
	}
	if strings.HasPrefix(install.Source, "registry:") || strings.HasPrefix(install.Source, "rollback:") {
		publication, err := m.Repo.GetExtensionRegistryVersion(ctx, install.ExtensionID, install.CurrentVersion)
		if err != nil {
			return "registry.missing", "registry publication unavailable: " + err.Error()
		}
		if publication.Artifact.PackageIdentity != install.CurrentPackageIdentity {
			return "registry.identity", "registry package identity does not match active installation"
		}
		if _, err := extensiontrust.EvaluatePublication(ctx, m.Repo, publication); err != nil {
			return "trust.publication", err.Error()
		}
	}
	lookup := func(id string) (model.ExtensionInstall, bool) {
		id = strings.ToLower(strings.TrimSpace(id))
		if install.Scope == "project" {
			if x, ok := all[installationKey{"project", install.ScopeID, id}]; ok && x.CurrentState != model.ExtensionInstallStateAbsent {
				return x, true
			}
		}
		x, ok := all[installationKey{"global", "", id}]
		return x, ok && x.CurrentState != model.ExtensionInstallStateAbsent
	}
	for _, dep := range version.Manifest.Dependencies {
		x, ok := lookup(dep.ID)
		if !ok {
			if dep.Optional {
				continue
			}
			return "dependencies.missing", fmt.Sprintf("required dependency %s %s is not installed", dep.ID, dep.Version)
		}
		if !extensionresolver.Matches(x.CurrentVersion, dep.Version) {
			return "dependencies.version", fmt.Sprintf("dependency %s@%s does not satisfy %s", dep.ID, x.CurrentVersion, dep.Version)
		}
	}
	for _, conflict := range version.Manifest.Conflicts {
		if x, ok := lookup(conflict.ID); ok && extensionresolver.Matches(x.CurrentVersion, conflict.Version) {
			return "dependencies.conflict", fmt.Sprintf("conflict %s %s matched installed %s", conflict.ID, conflict.Version, x.CurrentVersion)
		}
	}
	return "", ""
}

func (m *Manager) run(ctx context.Context, mutate bool) (Report, error) {
	report := Report{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), Contract: extensioncontract.Frozen(), Issues: []Issue{}}
	if m == nil || m.Repo == nil || m.Lifecycle == nil {
		return report, errors.New("NeverExtensions GA manager is not configured")
	}
	installs, err := m.Repo.ListExtensionInstallStates(ctx, "", "")
	if err != nil {
		return report, err
	}
	sort.Slice(installs, func(i, j int) bool {
		a, b := installs[i], installs[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.ScopeID != b.ScopeID {
			return a.ScopeID < b.ScopeID
		}
		return a.ExtensionID < b.ExtensionID
	})
	all := map[installationKey]model.ExtensionInstall{}
	for _, x := range installs {
		all[installationKey{x.Scope, x.ScopeID, x.ExtensionID}] = x
	}
	for _, install := range installs {
		if install.CurrentState == model.ExtensionInstallStateAbsent {
			continue
		}
		report.Checked++
		if install.CurrentState == model.ExtensionInstallStateEnabled && install.Enabled {
			report.Enabled++
		}
		code, msg := m.validateInstall(ctx, install, all)
		if code == "" {
			report.Healthy++
			continue
		}
		issue := Issue{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID, Version: install.CurrentVersion, Code: code, Message: msg}
		if mutate && (install.CurrentState == model.ExtensionInstallStateEnabled || install.Enabled) {
			reason := fmt.Sprintf("NeverExtensions GA reconciliation failed [%s]: %s", code, msg)
			if _, e := m.Repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID, Reason: reason, Source: "ga-reconcile"}); e != nil {
				issue.Message += "; emergency-disable persistence failed: " + e.Error()
			} else if _, e := m.Lifecycle.Disable(ctx, install.ExtensionID, extensionlifecycle.Scope{Scope: install.Scope, ScopeID: install.ScopeID}); e != nil {
				issue.Message += "; lifecycle disable failed: " + e.Error()
			} else {
				issue.Disabled = true
				report.Disabled++
				m.Repo.AddAuditEvent(model.AuditEvent{Actor: "system:neverextensions-ga", Action: "extension:ga:reconcile:disable", Target: install.ExtensionID + ":" + install.Scope + ":" + install.ScopeID + ":" + code, UserAgent: "NeverExtensions GA/0.21.0", CreatedAt: time.Now().UTC()})
			}
		}
		report.Issues = append(report.Issues, issue)
	}
	return report, nil
}

// Validate performs all GA integrity/trust/dependency checks without mutation.
func (m *Manager) Validate(ctx context.Context) (Report, error) { return m.run(ctx, false) }

// Reconcile fail-closes invalid enabled installations by persisting the kill-switch and disabling them.
func (m *Manager) Reconcile(ctx context.Context) (Report, error) { return m.run(ctx, true) }
