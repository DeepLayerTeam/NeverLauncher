package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type gravitOptionalPreviewRequest02411 struct {
	ExpectedRevision uint64          `json:"expectedRevision"`
	Source           json.RawMessage `json:"source"`
}

// This is a dry-run transformation of untrusted Gravit data. The output can
// only be committed through the existing component-catalog PUT transaction,
// which recomputes the digest, validates all presets and checks CAS revision.
func (s Server) componentCatalogGravitPreview02411(w http.ResponseWriter, r *http.Request) {
	lookup, err := editorLookup0248(s, r.PathValue("packageId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "package not found")
		return
	}
	if lookup.Release.Status != "draft" || lookup.Release.Manifest.SchemaVersion != model.ManifestSchemaV3 {
		writeError(w, http.StatusConflict, "Gravit migration requires an unsigned Manifest v3 draft")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var req gravitOptionalPreviewRequest02411
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err = d.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var trailing any
	if err = d.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "unexpected trailing data")
		return
	}
	existing := lookup.Release.Manifest.ComponentCatalog
	if existing == nil || req.ExpectedRevision == 0 || req.ExpectedRevision != existing.Revision {
		writeError(w, http.StatusConflict, "catalog revision changed; reload before importing")
		return
	}
	if len(req.Source) == 0 {
		writeError(w, http.StatusBadRequest, "Gravit source is required")
		return
	}
	source := []byte(req.Source)
	if len(source) > 0 && source[0] == '"' {
		var verbatim string
		if err := json.Unmarshal(source, &verbatim); err != nil {
			writeError(w, http.StatusBadRequest, "invalid source string")
			return
		}
		source = []byte(verbatim)
	}
	result, err := model.ConvertGravitOptionalView02411(source, *existing, lookup.Release.Manifest.Files)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, preview := previewCatalog0248(lookup.Release, componentEditorRequest0248{ExpectedRevision: req.ExpectedRevision, Catalog: result.Catalog})
	if len(preview.Errors) != 0 {
		for _, msg := range preview.Errors {
			result.Fields = append(result.Fields, model.GravitFieldResult02210{Field: "catalog", Status: "blocked", Reason: msg})
			result.Summary["blocked"]++
		}
		result.Ready = false
	}
	// Explicitly prohibit silently merging unsupported semantics with a valid
	// candidate. Admin must review and resolve every issue before normal save.
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"migration": result, "preview": preview, "canApply": result.Ready && preview.Valid, "warning": strings.Join(preview.Errors, "; ")}})
}
