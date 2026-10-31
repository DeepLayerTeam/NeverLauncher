package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type managedWizardRequest02910 struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Config json.RawMessage `json:"config"`
	Reason string          `json:"reason"`
}
type managedActivationRequest02910 struct {
	Revision               int64  `json:"revision"`
	ExpectedActiveRevision int64  `json:"expectedActiveRevision"`
	Reason                 string `json:"reason"`
}

func decodeWizardBody02910(w http.ResponseWriter, r *http.Request, out any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 48<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing request")
	}
	return nil
}
func wizardStore02910(s Server) (repository.ManagedProviderStore02910, bool) {
	v, ok := s.Repo.(repository.ManagedProviderStore02910)
	return v, ok
}
func (s Server) wizardList02910(w http.ResponseWriter, r *http.Request) {
	store, ok := wizardStore02910(s)
	if !ok {
		writeError(w, 503, "provider management unavailable")
		return
	}
	heads, err := store.ListManagedProviders02910(r.Context())
	if err != nil {
		writeError(w, 503, "provider management unavailable")
		return
	}
	if heads == nil {
		heads = []repository.ManagedProviderHead02910{}
	}
	// These revisions contain only non-secret, validated configs with env references.
	writeJSON(w, 200, map[string]any{"items": heads})
}
func wizardRevision02910(req managedWizardRequest02910) repository.ManagedProviderRevision02910 {
	return repository.ManagedProviderRevision02910{ID: strings.ToLower(strings.TrimSpace(req.ID)), Kind: strings.ToLower(strings.TrimSpace(req.Kind)), Config: req.Config, Reason: strings.TrimSpace(req.Reason)}
}
func (s Server) wizardTest02910(w http.ResponseWriter, r *http.Request) {
	var req managedWizardRequest02910
	if err := decodeWizardBody02910(w, r, &req); err != nil {
		writeError(w, 400, "invalid request")
		return
	}
	v := wizardRevision02910(req)
	if v.Reason == "" {
		v.Reason = "connection diagnostics"
	}
	if err := validateManagedSecrets02910(v); err != nil {
		writeError(w, 400, "unsafe or invalid provider configuration")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	probe, err := createManagedProvider02910(ctx, v)
	if err != nil {
		writeJSON(w, 422, map[string]any{"healthy": false, "detail": "live configuration, credential references, mapping or provider health failed"})
		return
	}
	defer closeManaged02910(probe.Connector)
	writeJSON(w, 200, map[string]any{"healthy": true, "metadata": probe.Metadata, "mapping": probe.Mapping, "credentialReferencesVerified": true, "note": "Connectivity proves neither account ownership nor Microsoft Minecraft entitlement"})
}
func (s Server) wizardDraft02910(w http.ResponseWriter, r *http.Request) {
	var req managedWizardRequest02910
	if err := decodeWizardBody02910(w, r, &req); err != nil {
		writeError(w, 400, "invalid request")
		return
	}
	v := wizardRevision02910(req)
	if err := validateManagedSecrets02910(v); err != nil {
		writeError(w, 400, "unsafe or invalid provider configuration")
		return
	}
	store, ok := wizardStore02910(s)
	if !ok {
		writeError(w, 503, "provider management unavailable")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	v.Actor = claims.Sub
	saved, err := store.SaveManagedProviderDraft02910(r.Context(), v)
	if err != nil {
		writeError(w, 503, "provider draft could not be saved")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth-provider:draft", Target: v.ID + ":" + strconv.FormatInt(saved.Revision, 10), CreatedAt: time.Now().UTC()})
	writeJSON(w, 201, saved)
}
func (s Server) wizardActivate02910(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	var req managedActivationRequest02910
	if err := decodeWizardBody02910(w, r, &req); err != nil || req.Revision < 0 || req.ExpectedActiveRevision < 0 || len(strings.TrimSpace(req.Reason)) < 3 || len(req.Reason) > 500 || strings.ContainsAny(req.Reason, "\r\n\x00") {
		writeError(w, 400, "invalid revision or reason")
		return
	}
	store, ok := wizardStore02910(s)
	if !ok {
		writeError(w, 503, "provider management unavailable")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	heads, err := store.ListManagedProviders02910(r.Context())
	if err != nil {
		writeError(w, 503, "provider management unavailable")
		return
	}
	var head *repository.ManagedProviderHead02910
	for i := range heads {
		if heads[i].ID == id {
			head = &heads[i]
			break
		}
	}
	if head == nil {
		writeError(w, 404, "unknown provider")
		return
	}
	if head.ActiveRevision != req.ExpectedActiveRevision {
		writeError(w, 409, "active revision changed; reload before applying")
		return
	}
	// A candidate is tested AGAINST THE LIVE provider before moving the durable
	// pointer. This also checks environment-injected credentials without exposing them.
	if req.Revision != 0 {
		var candidate *repository.ManagedProviderRevision02910
		for i := range head.Revisions {
			if head.Revisions[i].Revision == req.Revision {
				candidate = &head.Revisions[i]
				break
			}
		}
		if candidate == nil {
			writeError(w, 404, "unknown revision")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		probe, probeErr := createManagedProvider02910(ctx, *candidate)
		cancel()
		if probeErr != nil {
			writeError(w, 422, "provider connection or SDK conformance failed; active settings unchanged")
			return
		}
		// Do not allow a database-managed provider to override an env-configured source.
		if _, exists := s.Federation.Connector(id); exists && s.Federation.ManagedRevision(id) == 0 {
			_ = closeManaged02910(probe.Connector)
			writeError(w, 409, "provider is managed by bootstrap configuration")
			return
		}
		_ = closeManaged02910(probe.Connector)
	}
	changed, err := store.ActivateManagedProvider02910(r.Context(), id, req.Revision, req.ExpectedActiveRevision, claims.Sub, strings.TrimSpace(req.Reason))
	if errors.Is(err, repository.ErrManagedProviderConflict02910) {
		writeError(w, 409, "active revision changed; reload before applying")
		return
	}
	if errors.Is(err, repository.ErrManagedProviderMissing02910) {
		writeError(w, 404, "unknown provider or revision")
		return
	}
	if err != nil {
		writeError(w, 503, "activation transaction failed")
		return
	}
	// Load now, not only on the next authentication request. If another node
	// cannot reach the provider its auth middleware fails closed.
	syncErr := s.syncManagedProviders02910(r.Context())
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth-provider:activate", Target: id + ":" + strconv.FormatInt(req.Revision, 10), CreatedAt: time.Now().UTC()})
	if syncErr != nil {
		writeError(w, 503, "active revision committed but runtime could not synchronize; rollback through Admin")
		return
	}
	writeJSON(w, 200, changed)
}

// Current state is based on the actual, running connector (not stored metadata).
// Health error strings are never returned: drivers sometimes include DSNs.
func (s Server) wizardStatus02910(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if err := s.syncManagedProviders02910(ctx); err != nil {
		writeError(w, 503, "managed auth providers cannot be synchronized")
		return
	}
	type health struct {
		ID       string `json:"id"`
		Healthy  bool   `json:"healthy"`
		Revision int64  `json:"revision"`
	}
	records := []health{}
	for _, id := range s.Federation.ManagedIDs() {
		c, ok := s.Federation.Connector(id)
		if !ok {
			continue
		}
		healthCtx, finish := context.WithTimeout(ctx, 3*time.Second)
		err := c.Health(healthCtx)
		finish()
		records = append(records, health{ID: id, Healthy: err == nil, Revision: s.Federation.ManagedRevision(id)})
	}
	writeJSON(w, 200, map[string]any{"items": records})
}
