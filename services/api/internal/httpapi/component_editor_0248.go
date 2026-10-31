package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// ComponentEditor mutations are serialized using the same package lock as
// upload/sign. CAS on revision prevents one administrator overwriting another.
// The Backend is the authoritative validator and computes the signed digest.
type componentEditorRequest0248 struct {
	ExpectedRevision uint64                     `json:"expectedRevision"`
	Catalog          model.ComponentCatalog0241 `json:"catalog"`
}
type componentPreviewEntry0248 struct {
	Preset   string   `json:"preset"`
	Selected []string `json:"selected,omitempty"`
	Error    string   `json:"error,omitempty"`
}
type componentPreview0248 struct {
	Valid    bool                        `json:"valid"`
	Digest   string                      `json:"digest"`
	Revision uint64                      `json:"revision"`
	Errors   []string                    `json:"errors"`
	Presets  []componentPreviewEntry0248 `json:"presets"`
}

func editorLookup0248(s Server, packageID string) (packageLookup, error) {
	// Only the canonical package identity is acceptable: version-only aliases
	// are ambiguous across projects and must not select a different release.
	lookup, err := s.lookupPackage(packageID)
	if err != nil {
		return packageLookup{}, err
	}
	if lookup.Release.ID != packageID {
		return packageLookup{}, repository.ErrNotFound
	}
	return lookup, nil
}

func (s Server) componentCatalogGet0248(w http.ResponseWriter, r *http.Request) {
	lookup, err := editorLookup0248(s, r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"packageId": lookup.Release.ID, "projectId": lookup.Release.ProjectID,
		"status": lookup.Release.Status, "manifestSchemaVersion": lookup.Release.Manifest.SchemaVersion,
		"catalog": lookup.Release.Manifest.ComponentCatalog, "files": lookup.Release.Manifest.Files,
	}})
}

func readCatalogRequest0248(w http.ResponseWriter, r *http.Request) (componentEditorRequest0248, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var req componentEditorRequest0248
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		return req, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return req, errors.New("unexpected trailing JSON")
	}
	if req.ExpectedRevision == 0 {
		return req, errors.New("expectedRevision is required")
	}
	if req.Catalog.SchemaVersion != model.ComponentCatalogSchema0245 {
		return req, errors.New("component editor requires signed catalog schema 5.0")
	}
	return req, nil
}

func previewCatalog0248(release model.ReleaseVersion, req componentEditorRequest0248) (model.ComponentCatalog0241, componentPreview0248) {
	cat := model.NewComponentCatalog0245(req.Catalog, req.ExpectedRevision+1)
	report := componentPreview0248{Valid: true, Digest: cat.Digest, Revision: cat.Revision, Errors: []string{}, Presets: []componentPreviewEntry0248{}}
	candidate := release.Manifest
	candidate.ComponentCatalog = &cat
	if release.Manifest.SchemaVersion != model.ManifestSchemaV3 {
		report.Errors = append(report.Errors, "package must be created with Manifest v3")
	} else if err := model.ValidateManifestSchema(candidate); err != nil {
		report.Errors = append(report.Errors, err.Error())
	}
	// Check topology in all explicit presets with the real deterministic graph
	// resolver (not a frontend approximation). Conditions are separately
	// checked at launch against trusted environment/entitlements.
	if len(report.Errors) == 0 {
		for _, name := range append([]string{""}, presetIDs0248(cat)...) {
			entry := componentPreviewEntry0248{Preset: name}
			result, err := model.PreviewCatalogGraph0248(cat, name)
			if err != nil {
				entry.Error = err.Error()
				report.Errors = append(report.Errors, fmt.Sprintf("preset %q: %v", name, err))
			} else {
				entry.Selected = result
			}
			report.Presets = append(report.Presets, entry)
		}
	}
	report.Valid = len(report.Errors) == 0
	return cat, report
}
func presetIDs0248(cat model.ComponentCatalog0241) []string {
	names := make([]string, 0, len(cat.Presets))
	for _, p := range cat.Presets {
		names = append(names, p.ID)
	}
	return names
}

func (s Server) componentCatalogPreview0248(w http.ResponseWriter, r *http.Request) {
	lookup, err := editorLookup0248(s, r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package not found")
		return
	}
	req, err := readCatalogRequest0248(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if lookup.Release.Status != "draft" {
		writeError(w, http.StatusConflict, "catalog can only be edited before signing")
		return
	}
	if lookup.Release.Manifest.ComponentCatalog == nil || lookup.Release.Manifest.ComponentCatalog.Revision != req.ExpectedRevision {
		writeError(w, http.StatusConflict, "catalog changed: reload before editing")
		return
	}
	_, report := previewCatalog0248(lookup.Release, req)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": report})
}

func (s Server) componentCatalogSave0248(w http.ResponseWriter, r *http.Request) {
	// Serialize with package sign, upload and other component changes.
	lookup, unlock, err := s.lockPackageLookupMutation(r.Context(), r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusConflict, "package is busy or missing")
		return
	}
	defer unlock()
	if lookup.Release.ID != r.PathValue("packageId") {
		writeError(w, http.StatusNotFound, "package not found")
		return
	}
	if lookup.Release.Status != "draft" {
		writeError(w, http.StatusConflict, "signed/staged/published package is immutable")
		return
	}
	req, err := readCatalogRequest0248(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if lookup.Release.Manifest.ComponentCatalog == nil || lookup.Release.Manifest.ComponentCatalog.Revision != req.ExpectedRevision {
		writeError(w, http.StatusConflict, "catalog revision changed; reload before editing")
		return
	}
	cat, report := previewCatalog0248(lookup.Release, req)
	if !report.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"message": strings.Join(report.Errors, "; ")}, "preview": report})
		return
	}
	updater, ok := s.Repo.(interface {
		UpdateDraftComponentCatalog0248(string, string, uint64, model.ComponentCatalog0241) (model.ReleaseVersion, error)
	})
	if !ok {
		writeError(w, http.StatusInternalServerError, "catalog repository update unavailable")
		return
	}
	updated, err := updater.UpdateDraftComponentCatalog0248(lookup.Release.ProjectID, lookup.Release.ID, req.ExpectedRevision, cat)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "component-catalog:update", lookup.Release.ID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"catalog": updated.Manifest.ComponentCatalog, "status": updated.Status, "preview": report,
	}})
}
