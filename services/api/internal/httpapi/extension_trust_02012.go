package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionhost"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensionlifecycle"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensiontrust"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type trustPolicyWrite02012 struct {
	Mode              string   `json:"mode"`
	AllowedPublishers []string `json:"allowedPublishers"`
}
type emergencyDisableWrite02012 struct {
	Scope   string `json:"scope"`
	ScopeID string `json:"scopeId,omitempty"`
	Reason  string `json:"reason"`
}
type recoveryImportWrite02012 struct {
	State model.ExtensionRecoveryExport `json:"state"`
}
type recoveryBackup02012 struct {
	SchemaVersion string                        `json:"schemaVersion"`
	CreatedAt     time.Time                     `json:"createdAt"`
	StateSHA256   string                        `json:"stateSha256"`
	State         model.ExtensionRecoveryExport `json:"state"`
}

func randomID02012(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func (s Server) extensionTrustPolicyGet02012(w http.ResponseWriter, r *http.Request) {
	p, err := s.Repo.GetExtensionTrustPolicy(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"policy": p}})
}
func (s Server) extensionTrustPolicyPut02012(w http.ResponseWriter, r *http.Request) {
	var req trustPolicyWrite02012
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, "invalid trust policy: "+err.Error())
		return
	}
	p, err := s.Repo.SaveExtensionTrustPolicy(r.Context(), model.ExtensionTrustPolicy{Mode: req.Mode, AllowedPublishers: req.AllowedPublishers})
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	blocked, sweepErr := s.enforceExtensionTrustRuntime02012(r.Context(), "trust-policy")
	if sweepErr != nil {
		writeError(w, 500, "trust policy saved but runtime enforcement failed: "+sweepErr.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:trust:policy", p.Mode)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"policy": p, "runtimeDisabled": blocked}})
}
func (s Server) extensionPublisherKeyRevoke02012(w http.ResponseWriter, r *http.Request) {
	publisher := strings.ToLower(strings.TrimSpace(r.PathValue("publisherId")))
	fingerprint := strings.ToLower(strings.TrimSpace(r.PathValue("fingerprint")))
	key, err := s.Repo.RevokeExtensionRegistryPublisherKey(r.Context(), publisher, fingerprint)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, 404, "publisher key not found")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	// Immediately quarantine every published artifact signed by this key. This
	// makes revocation effective even for already-installed exact versions.
	versions, listErr := s.Repo.SearchExtensionRegistry(r.Context(), model.ExtensionRegistrySearch{IncludeYanked: true})
	if listErr == nil {
		for _, item := range versions {
			if item.PublisherID != publisher || item.Artifact.SignatureKeyFingerprint != fingerprint {
				continue
			}
			id, idErr := randomID02012("q-")
			if idErr != nil {
				continue
			}
			_, _ = s.Repo.SaveExtensionQuarantine(r.Context(), model.ExtensionQuarantineEntry{ID: id, PackageIdentity: item.Artifact.PackageIdentity, ArtifactSHA256: item.Artifact.SHA256, ExtensionID: item.ExtensionID, Version: item.Version, PublisherID: item.PublisherID, KeyFingerprint: fingerprint, Reason: "publisher signing key revoked", StorageProject: item.Artifact.StorageProject, StorageVersion: item.Artifact.StorageVersion, StoragePath: item.Artifact.StoragePath})
		}
	}
	blocked, sweepErr := s.enforceExtensionTrustRuntime02012(r.Context(), "publisher-key-revocation")
	if sweepErr != nil {
		writeError(w, 500, "key revoked but runtime enforcement failed: "+sweepErr.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:trust:key:revoke", publisher+"/"+fingerprint)
	key.PublicKeyBase64 = ""
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"key": key, "runtimeDisabled": blocked}})
}

// enforceExtensionTrustRuntime02012 closes the time-of-check/time-of-use gap for
// already running registry extensions. A policy/key/quarantine change is applied
// to the live host set immediately and persisted as an emergency disable so a
// backend restart cannot resurrect an artifact rejected by current trust state.
func (s Server) enforceExtensionTrustRuntime02012(ctx context.Context, source string) (int, error) {
	installs, err := s.Repo.ListExtensionInstallStates(ctx, "", "")
	if err != nil {
		return 0, err
	}
	blocked := 0
	for _, install := range installs {
		if !install.Enabled || install.CurrentState != model.ExtensionInstallStateEnabled || install.CurrentVersion == "" {
			continue
		}
		publication, err := s.Repo.GetExtensionRegistryVersion(ctx, install.ExtensionID, install.CurrentVersion)
		if errors.Is(err, repository.ErrNotFound) {
			continue // Local/legacy installation: registry trust policy does not own it.
		}
		if err != nil {
			return blocked, err
		}
		decision, trustErr := extensiontrust.EvaluatePublication(ctx, s.Repo, publication)
		if trustErr == nil && decision.Allowed {
			continue
		}
		reason := "extension trust rejected active installation"
		if trustErr != nil {
			reason += ": " + trustErr.Error()
		} else if len(decision.Violations) > 0 {
			reason += ": " + strings.Join(decision.Violations, "; ")
		}
		scope := extensionlifecycle.Scope{Scope: install.Scope, ScopeID: install.ScopeID}
		if s.ExtensionHost != nil {
			_ = s.ExtensionHost.Stop(ctx, extensionhostKey02012(install.ExtensionID, scope))
		}
		if _, err := s.Repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: install.ExtensionID, Scope: install.Scope, ScopeID: install.ScopeID, Reason: reason, Source: source}); err != nil {
			return blocked, err
		}
		if _, err := s.lifecycleManager0204().Disable(ctx, install.ExtensionID, scope); err != nil && !errors.Is(err, repository.ErrNotFound) {
			return blocked, err
		}
		blocked++
	}
	return blocked, nil
}

func (s Server) extensionQuarantineList02012(w http.ResponseWriter, r *http.Request) {
	activeOnly := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("active"))) != "false"
	items, err := s.Repo.ListExtensionQuarantine(r.Context(), activeOnly)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"count": len(items), "items": items}})
}
func (s Server) extensionQuarantineRelease02012(w http.ResponseWriter, r *http.Request) {
	item, err := s.Repo.ReleaseExtensionQuarantine(r.Context(), r.PathValue("quarantineId"), s.adminActor(r))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, 404, "quarantine entry not found")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:quarantine:release", item.ID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"entry": item}})
}

func (s Server) extensionEmergencyDisableList02012(w http.ResponseWriter, r *http.Request) {
	items, err := s.Repo.ListExtensionEmergencyDisables(r.Context(), true)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"count": len(items), "items": items, "safeMode": s.ExtensionSafeMode}})
}
func (s Server) extensionEmergencyDisable02012(w http.ResponseWriter, r *http.Request) {
	var req emergencyDisableWrite02012
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, "invalid emergency-disable payload: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeError(w, 400, "reason is required")
		return
	}
	scope := lifecycleScopeFromRequest0204(req.Scope, req.ScopeID)
	id := r.PathValue("extensionId")
	if s.ExtensionHost != nil {
		_ = s.ExtensionHost.Stop(r.Context(), extensionhostKey02012(id, scope))
	}
	install, err := s.lifecycleManager0204().Disable(r.Context(), id, scope)
	if err != nil && !errors.Is(err, repository.ErrNotFound) && !strings.Contains(strings.ToLower(err.Error()), "not installed") {
		writeLifecycleError0204(w, err)
		return
	}
	item, err := s.Repo.SetExtensionEmergencyDisable(r.Context(), model.ExtensionEmergencyDisable{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID, Reason: req.Reason, Source: "admin"})
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:emergency:disable", item.ExtensionID+":"+item.Scope+":"+item.ScopeID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"emergencyDisable": item, "install": install}})
}
func extensionhostKey02012(id string, scope extensionlifecycle.Scope) extensionhost.Key {
	return extensionhost.Key{ExtensionID: id, Scope: scope.Scope, ScopeID: scope.ScopeID}
}
func (s Server) extensionEmergencyClear02012(w http.ResponseWriter, r *http.Request) {
	scope := lifecycleScopeFromRequest0204(r.URL.Query().Get("scope"), r.URL.Query().Get("scopeId"))
	item, err := s.Repo.ClearExtensionEmergencyDisable(r.Context(), r.PathValue("extensionId"), scope.Scope, scope.ScopeID, s.adminActor(r))
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, 404, "active emergency disable not found")
		return
	}
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:emergency:clear", item.ExtensionID+":"+item.Scope+":"+item.ScopeID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"emergencyDisable": item}})
}

func (s Server) buildExtensionRecoveryExport02012(ctx context.Context) (model.ExtensionRecoveryExport, error) {
	policy, err := s.Repo.GetExtensionTrustPolicy(ctx)
	if err != nil {
		return model.ExtensionRecoveryExport{}, err
	}
	publishers, err := s.Repo.ListExtensionRegistryPublishers(ctx)
	if err != nil {
		return model.ExtensionRecoveryExport{}, err
	}
	keys := []model.ExtensionRegistryPublisherKey{}
	for _, p := range publishers {
		ks, e := s.Repo.ListExtensionRegistryPublisherKeys(ctx, p.ID)
		if e != nil {
			return model.ExtensionRecoveryExport{}, e
		}
		keys = append(keys, ks...)
	}
	installs, err := s.Repo.ListExtensionInstallStates(ctx, "", "")
	if err != nil {
		return model.ExtensionRecoveryExport{}, err
	}
	emergency, err := s.Repo.ListExtensionEmergencyDisables(ctx, true)
	if err != nil {
		return model.ExtensionRecoveryExport{}, err
	}
	quarantine, err := s.Repo.ListExtensionQuarantine(ctx, true)
	if err != nil {
		return model.ExtensionRecoveryExport{}, err
	}
	pins := []model.ExtensionUpdatePin{}
	seen := map[string]bool{"global\x00": true}
	scopes := [][2]string{{"global", ""}}
	for _, i := range installs {
		k := i.Scope + "\x00" + i.ScopeID
		if !seen[k] {
			seen[k] = true
			scopes = append(scopes, [2]string{i.Scope, i.ScopeID})
		}
	}
	for _, sc := range scopes {
		ps, e := s.Repo.ListExtensionUpdatePins(ctx, sc[0], sc[1])
		if e != nil {
			return model.ExtensionRecoveryExport{}, e
		}
		pins = append(pins, ps...)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].PublisherID == keys[j].PublisherID {
			return keys[i].Fingerprint < keys[j].Fingerprint
		}
		return keys[i].PublisherID < keys[j].PublisherID
	})
	return model.ExtensionRecoveryExport{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), TrustPolicy: policy, Publishers: publishers, PublisherKeys: keys, EmergencyDisables: emergency, Quarantine: quarantine, Installs: installs, Pins: pins}, nil
}
func (s Server) extensionRecoveryExport02012(w http.ResponseWriter, r *http.Request) {
	state, err := s.buildExtensionRecoveryExport02012(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"state": state}})
}

func canonicalRecoveryState02012(state model.ExtensionRecoveryExport) ([]byte, error) {
	b, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (s Server) extensionRecoveryBackup02012(w http.ResponseWriter, r *http.Request) {
	state, err := s.buildExtensionRecoveryExport02012(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	raw, err := canonicalRecoveryState02012(state)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	sum := sha256.Sum256(raw)
	backup := recoveryBackup02012{SchemaVersion: "1.0", CreatedAt: time.Now().UTC(), StateSHA256: hex.EncodeToString(sum[:]), State: state}
	s.audit(r, s.adminActor(r), "extension:recovery:backup", backup.StateSHA256)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"backup": backup}})
}

func (s Server) importExtensionRecoveryState02012(ctx context.Context, state model.ExtensionRecoveryExport, restoreInstalls bool) (map[string]int, error) {
	if state.SchemaVersion != "1.0" {
		return nil, errors.New("unsupported extension recovery schemaVersion")
	}
	counts := map[string]int{"publishers": 0, "keys": 0, "quarantine": 0, "pins": 0, "installs": 0, "emergencyDisables": 0}
	// Import in a monotonic trust-safe order. Publisher records are temporarily
	// activated only so their public keys can be inserted through the normal
	// repository invariants; the exact active state is restored after keys.
	// Revoked keys are never reactivated.
	publisherStates := make([]model.ExtensionRegistryPublisher, 0, len(state.Publishers))
	for _, p := range state.Publishers {
		publisherStates = append(publisherStates, p)
		staged := p
		staged.Active = true
		if _, err := s.Repo.SaveExtensionRegistryPublisher(ctx, staged); err != nil {
			return counts, err
		}
		counts["publishers"]++
	}
	for _, k := range state.PublisherKeys {
		revoked := k.RevokedAt != nil || !k.Active
		k.Active = !revoked
		k.RevokedAt = nil
		created, err := s.Repo.SaveExtensionRegistryPublisherKey(ctx, k)
		if err != nil {
			return counts, err
		}
		if revoked {
			if _, err = s.Repo.RevokeExtensionRegistryPublisherKey(ctx, created.PublisherID, created.Fingerprint); err != nil {
				return counts, err
			}
		}
		counts["keys"]++
	}
	for _, p := range publisherStates {
		if _, err := s.Repo.SaveExtensionRegistryPublisher(ctx, p); err != nil {
			return counts, err
		}
	}
	if _, err := s.Repo.SaveExtensionTrustPolicy(ctx, state.TrustPolicy); err != nil {
		return counts, err
	}
	for _, entry := range state.Quarantine {
		if !entry.Active || entry.ReleasedAt != nil {
			continue
		}
		existing, getErr := s.Repo.GetExtensionQuarantine(ctx, entry.ID)
		if getErr == nil && existing.Active {
			counts["quarantine"]++
			continue
		}
		if getErr != nil && !errors.Is(getErr, repository.ErrNotFound) {
			return counts, getErr
		}
		if getErr == nil && !existing.Active {
			id, err := randomID02012("q-restore-")
			if err != nil {
				return counts, err
			}
			entry.ID = id
		}
		entry.Active = true
		entry.ReleasedAt = nil
		entry.ReleasedBy = ""
		if _, err := s.Repo.SaveExtensionQuarantine(ctx, entry); err != nil {
			return counts, err
		}
		counts["quarantine"]++
	}
	for _, pin := range state.Pins {
		if _, err := s.Repo.SetExtensionUpdatePin(ctx, pin); err != nil {
			return counts, err
		}
		counts["pins"]++
	}
	if restoreInstalls {
		mgr := s.lifecycleManager0204()
		for _, wanted := range state.Installs {
			if wanted.CurrentState == model.ExtensionInstallStateAbsent || wanted.CurrentVersion == "" {
				continue
			}
			item, err := s.Repo.GetExtensionRegistryVersion(ctx, wanted.ExtensionID, wanted.CurrentVersion)
			if err != nil {
				return counts, fmt.Errorf("restore %s@%s: %w", wanted.ExtensionID, wanted.CurrentVersion, err)
			}
			scope := extensionlifecycle.Scope{Scope: wanted.Scope, ScopeID: wanted.ScopeID}
			cur, curErr := s.Repo.GetExtensionInstallState(ctx, wanted.ExtensionID, wanted.Scope, wanted.ScopeID)
			var got model.ExtensionInstall
			if errors.Is(curErr, repository.ErrNotFound) || cur.CurrentState == model.ExtensionInstallStateAbsent {
				got, err = mgr.Install(ctx, item, scope)
			} else if cur.CurrentVersion != wanted.CurrentVersion || cur.CurrentPackageIdentity != wanted.CurrentPackageIdentity {
				got, err = mgr.Update(ctx, item, scope)
			} else {
				got = cur
			}
			if err != nil {
				return counts, fmt.Errorf("restore %s: %w", wanted.ExtensionID, err)
			}
			if wanted.CurrentState == model.ExtensionInstallStateEnabled && wanted.Enabled {
				if _, err = mgr.Enable(ctx, got.ExtensionID, scope); err != nil {
					return counts, err
				}
			} else {
				if _, err = mgr.Disable(ctx, got.ExtensionID, scope); err != nil {
					return counts, err
				}
			}
			counts["installs"]++
		}
	}
	for _, e := range state.EmergencyDisables {
		if e.ClearedAt != nil {
			continue
		}
		e.ClearedAt = nil
		e.ClearedBy = ""
		if _, err := s.Repo.SetExtensionEmergencyDisable(ctx, e); err != nil {
			return counts, err
		}
		if restoreInstalls {
			_, _ = s.lifecycleManager0204().Disable(ctx, e.ExtensionID, extensionlifecycle.Scope{Scope: e.Scope, ScopeID: e.ScopeID})
		}
		counts["emergencyDisables"]++
	}
	return counts, nil
}
func (s Server) extensionRecoveryImport02012(w http.ResponseWriter, r *http.Request) {
	var req recoveryImportWrite02012
	if err := decodeSingleJSON0203(r, &req); err != nil {
		writeError(w, 400, "invalid recovery import: "+err.Error())
		return
	}
	counts, err := s.importExtensionRecoveryState02012(r.Context(), req.State, false)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:recovery:import", fmt.Sprint(counts))
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"imported": counts}})
}
func (s Server) extensionRecoveryRestore02012(w http.ResponseWriter, r *http.Request) {
	var backup recoveryBackup02012
	if err := decodeSingleJSON0203(r, &backup); err != nil {
		writeError(w, 400, "invalid recovery backup: "+err.Error())
		return
	}
	if backup.SchemaVersion != "1.0" {
		writeError(w, 400, "unsupported backup schemaVersion")
		return
	}
	raw, err := canonicalRecoveryState02012(backup.State)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	sum := sha256.Sum256(raw)
	if !strings.EqualFold(backup.StateSHA256, hex.EncodeToString(sum[:])) {
		writeError(w, 409, "extension recovery backup SHA-256 mismatch")
		return
	}
	counts, err := s.importExtensionRecoveryState02012(r.Context(), backup.State, true)
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "extension:recovery:restore", backup.StateSHA256)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"restored": counts, "stateSha256": backup.StateSHA256}})
}

// quarantineRejectedUpload02012 persists suspicious bytes into configured
// storage before returning the rejection. This is intentionally best-effort at
// the callsite: the artifact is never accepted even if forensic storage fails.
func (s Server) quarantineRejectedUpload02012(ctx context.Context, tmpPath, uploadSHA, reason string, meta *model.ExtensionRegistryVersion) (model.ExtensionQuarantineEntry, error) {
	id, err := randomID02012("q-")
	if err != nil {
		return model.ExtensionQuarantineEntry{}, err
	}
	identity := "sha256:" + strings.ToLower(uploadSHA)
	entry := model.ExtensionQuarantineEntry{ID: id, PackageIdentity: identity, ArtifactSHA256: strings.ToLower(uploadSHA), Reason: reason}
	if meta != nil {
		entry.PackageIdentity = meta.Artifact.PackageIdentity
		entry.ExtensionID = meta.ExtensionID
		entry.Version = meta.Version
		entry.PublisherID = meta.PublisherID
		entry.KeyFingerprint = meta.Artifact.SignatureKeyFingerprint
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		return entry, err
	}
	defer f.Close()
	entry.StorageProject = "neverextensions-quarantine"
	entry.StorageVersion = time.Now().UTC().Format("2006-01-02")
	entry.StoragePath = id + ".nlext"
	_, size, err := s.Storage.Save(entry.StorageProject, entry.StorageVersion, entry.StoragePath, f)
	if err != nil {
		return entry, err
	}
	if size <= 0 {
		return entry, io.ErrUnexpectedEOF
	}
	return s.Repo.SaveExtensionQuarantine(ctx, entry)
}

func (s Server) enforcePublisherTrust02012(ctx context.Context, publisherID string) error {
	d, err := extensiontrust.EvaluatePublisher(ctx, s.Repo, publisherID)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return errors.New(strings.Join(d.Violations, "; "))
	}
	return nil
}
