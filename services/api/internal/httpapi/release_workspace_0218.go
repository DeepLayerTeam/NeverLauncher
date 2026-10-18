package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// Drafts are server-owned records (never client localStorage). Only their owner
// with current project rights may read/write them. Revision is an optimistic CAS.
func (s Server) draftStore0218(w http.ResponseWriter) (repository.ReleaseDraftStore, bool) {
	store, ok := s.Repo.(repository.ReleaseDraftStore)
	if !ok {
		writeError(w, 503, "release drafts unavailable")
		return nil, false
	}
	return store, true
}
func (s Server) draftClaims0218(w http.ResponseWriter, r *http.Request, projectID string) (authClaims, bool) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return claims, false
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", projectID, "project", projectID) {
		return claims, false
	}
	return claims, true
}
func readDraftBody0218(w http.ResponseWriter, r *http.Request) (repository.ReleaseDraft, error) {
	var draft repository.ReleaseDraft
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&draft); err != nil {
		return draft, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return draft, errors.New("expected one JSON object")
	}
	draft.ID = strings.TrimSpace(draft.ID)
	draft.ProjectID = strings.TrimSpace(draft.ProjectID)
	draft.ProfileID = strings.TrimSpace(draft.ProfileID)
	draft.Channel = strings.TrimSpace(draft.Channel)
	draft.Version = strings.TrimSpace(draft.Version)
	draft.PackageID = strings.TrimSpace(draft.PackageID)
	draft.JobID = strings.TrimSpace(draft.JobID)
	return draft, nil
}
func (s Server) draftBinding0218(w http.ResponseWriter, r *http.Request, d repository.ReleaseDraft) bool {
	if d.PackageID != "" {
		lookup, err := s.lookupPackage(d.PackageID)
		if err != nil || lookup.Release.ID != d.PackageID || lookup.Release.ProjectID != d.ProjectID || lookup.Release.ProfileID != d.ProfileID || lookup.Release.Channel != d.Channel || lookup.Release.Version != d.Version || (d.MinecraftVersion != "" && lookup.Release.Manifest.Minecraft.Version != d.MinecraftVersion) || (d.Loader != "" && lookup.Release.Manifest.Minecraft.Loader != d.Loader) {
			writeError(w, 409, "package не соответствует выбранным проекту/профилю/каналу/версии")
			return false
		}
	}
	if d.JobID != "" {
		cp, err := s.durableControlPlane0213()
		if err != nil {
			writeError(w, 503, "job store unavailable")
			return false
		}
		job, err := cp.GetDurableJob(r.Context(), d.JobID)
		if err != nil || job.ProjectID != d.ProjectID || job.Kind != "package-publish" || job.ResourceID != d.PackageID || job.ActorID != d.OwnerID {
			writeError(w, 409, "job не относится к выпуску этого пользователя и пакета")
			return false
		}
	}
	return true
}
func (s Server) draftCreate0218(w http.ResponseWriter, r *http.Request) {
	store, ok := s.draftStore0218(w)
	if !ok {
		return
	}
	d, err := readDraftBody0218(w, r)
	if err != nil {
		writeError(w, 400, "invalid draft: "+err.Error())
		return
	}
	claims, ok := s.draftClaims0218(w, r, d.ProjectID)
	if !ok {
		return
	}
	if _, err := s.Repo.GetProject(d.ProjectID); err != nil {
		writeError(w, 404, "project not found")
		return
	}
	// The ID, owner and revision are not accepted from the browser.
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		writeError(w, 500, "ID allocation failed")
		return
	}
	d.ID = "draft-" + hex.EncodeToString(id[:])
	d.OwnerID = claims.Sub
	d.Revision = 0
	d.CreatedAt = d.CreatedAt.UTC()
	d.UpdatedAt = d.UpdatedAt.UTC()
	if d.Channel == "" {
		d.Channel = "stable"
	}
	if d.Loader == "" {
		d.Loader = "vanilla"
	}
	if d.Step == "" {
		d.Step = "project"
	}
	if d.JobID != "" {
		writeError(w, 400, "new draft cannot reference a job")
		return
	}
	if !s.draftBinding0218(w, r, d) {
		return
	}
	created, err := store.CreateReleaseDraft(r.Context(), d)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, claims.Sub, "release-draft:create", created.ID)
	w.Header().Set("Location", "/api/v1/release-drafts/"+created.ID)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": created})
}
func (s Server) draftList0218(w http.ResponseWriter, r *http.Request) {
	store, ok := s.draftStore0218(w)
	if !ok {
		return
	}
	projectID := r.URL.Query().Get("projectId")
	claims, ok := s.draftClaims0218(w, r, projectID)
	if !ok {
		return
	}
	items, err := store.ListReleaseDrafts(r.Context(), projectID, claims.Sub)
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items}})
}
func (s Server) ownedDraft0218(w http.ResponseWriter, r *http.Request) (repository.ReleaseDraftStore, repository.ReleaseDraft, bool) {
	store, ok := s.draftStore0218(w)
	if !ok {
		return nil, repository.ReleaseDraft{}, false
	}
	d, err := store.GetReleaseDraft(r.Context(), r.PathValue("draftId"))
	if err != nil {
		writeError(w, 404, "draft not found")
		return store, d, false
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return store, d, false
	}
	if d.OwnerID != claims.Sub || !s.authorizeClaims(r, claims, "release:prepare", d.ProjectID, "project", d.ProjectID).Allowed {
		writeError(w, 404, "draft not found")
		return store, d, false
	}
	return store, d, true
}
func (s Server) draftJob0218(w http.ResponseWriter, r *http.Request) {
	_, d, ok := s.ownedDraft0218(w, r)
	if !ok {
		return
	}
	if d.PackageID == "" {
		writeError(w, 404, "draft has no package")
		return
	}
	journal, ok := s.Repo.(repository.OperationJournal)
	if !ok {
		writeError(w, 503, "operation journal unavailable")
		return
	}
	job, err := journal.FindOperationByKey(r.Context(), "package-publish", d.OwnerID, "release-workspace-"+d.ID)
	if err != nil || job.ProjectID != d.ProjectID || job.ActorID != d.OwnerID || job.ResourceID != d.PackageID {
		writeError(w, 404, "no publication operation found for this draft")
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": publicOperation0217(job)})
}
func (s Server) draftGet0218(w http.ResponseWriter, r *http.Request) {
	_, d, ok := s.ownedDraft0218(w, r)
	if ok {
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": d})
	}
}
func (s Server) draftUpdate0218(w http.ResponseWriter, r *http.Request) {
	store, old, ok := s.ownedDraft0218(w, r)
	if !ok {
		return
	}
	d, err := readDraftBody0218(w, r)
	if err != nil {
		writeError(w, 400, "invalid draft: "+err.Error())
		return
	}
	if d.Revision != old.Revision {
		writeError(w, 409, "draft changed in another tab; reload before saving")
		return
	}
	if (d.ProjectID != "" && d.ProjectID != old.ProjectID) || (d.ID != "" && d.ID != old.ID) {
		writeError(w, 409, "draft project and identity are immutable")
		return
	}
	d.ID = old.ID
	d.ProjectID = old.ProjectID
	d.OwnerID = old.OwnerID
	if d.Step == "" {
		d.Step = old.Step
	}
	if !s.draftBinding0218(w, r, d) {
		return
	}
	saved, err := store.UpdateReleaseDraft(r.Context(), d)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, 409, "draft changed in another tab; reload before saving")
		} else {
			writeError(w, 500, err.Error())
		}
		return
	}
	s.audit(r, old.OwnerID, "release-draft:update", d.ID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": saved})
}
func (s Server) draftDelete0218(w http.ResponseWriter, r *http.Request) {
	store, d, ok := s.ownedDraft0218(w, r)
	if !ok {
		return
	}
	if err := store.DeleteReleaseDraft(r.Context(), d.ID, d.OwnerID); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	s.audit(r, d.OwnerID, "release-draft:delete", d.ID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"deleted": true}})
}
