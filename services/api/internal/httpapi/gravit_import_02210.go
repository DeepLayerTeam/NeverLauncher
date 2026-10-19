package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type gravitImportRequest02210 struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	LoaderHint   string          `json:"loaderHint"`
	Source       json.RawMessage `json:"source"`
	SourceSHA256 string          `json:"sourceSha256,omitempty"`
	Channel      string          `json:"channel,omitempty"`
	Version      string          `json:"version,omitempty"`
}

// The preview does not mutate the repo. The commit repeats conversion on the
// original source bytes, requires a matching digest, then creates an exclusive
// profile and a private Build Workspace pinned to revision 1.
func (s Server) gravitImport02210(w http.ResponseWriter, r *http.Request) {
	var req gravitImportRequest02210
	if err := readJSON0226(w, r, 1<<20+4096, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	project := r.PathValue("projectId")
	result, err := model.ConvertGravitProfile02210(req.Source, project, req.ID, req.Name, req.LoaderHint)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if r.URL.Path == "" {
		writeError(w, 404, "invalid route")
		return
	}
	// Preview is read-only and includes the source hash and per-field decisions.
	if strings.HasSuffix(r.URL.Path, "/inspect-gravit") {
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": result})
		return
	}
	if !result.Ready {
		writeJSON(w, 422, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"message": "import has blocked or manual fields; resolve them before creating a profile", "code": "gravit-import-not-ready"}, "data": result})
		return
	}
	if req.SourceSHA256 == "" || req.SourceSHA256 != result.SourceSHA256 {
		writeError(w, 409, "sourceSha256 does not match inspected input")
		return
	}
	if req.Version == "" || len(req.Version) > 128 || strings.ContainsAny(req.Version, "/\\\x00\r\n") {
		writeError(w, 400, "new release version required")
		return
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if len(req.Channel) > 128 || strings.ContainsAny(req.Channel, "/\\\x00\r\n") {
		writeError(w, 400, "invalid channel")
		return
	}
	creator, ok := s.Repo.(repository.GravitImportWriter02210)
	if !ok {
		writeError(w, 503, "atomic profile/workspace import unavailable")
		return
	}
	if _, err = s.Repo.GetProject(project); err != nil {
		writeError(w, 404, "project not found")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	if !s.authorizeProjectAction(w, r, claims, "release:prepare", project, "project", project) {
		return
	}
	// Use actual server version, not untrusted source's claimed tooling.
	settings := repository.BuildSettings{Minecraft: result.Settings.Minecraft, Runtime: result.Settings.Runtime, Directories: result.Settings.Directories, FileRules: result.Settings.FileRules, ToolVersions: map[string]string{"neverlauncher-api": s.Version, "gravit-static-import": "0.22.10"}}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		writeError(w, 500, "unable to allocate workspace ID")
		return
	}

	ws := repository.BuildWorkspace{ID: "ws-" + hex.EncodeToString(id[:]), ProjectID: project, OwnerID: claims.Sub, ProfileID: result.Profile.ID, Channel: req.Channel, Version: req.Version, Settings: settings, Files: []repository.BuildFile{}}
	profile, created, err := creator.CreateGravitProfileWorkspace02210(r.Context(), result.Profile, ws)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, 409, "destination profile or workspace already exists")
		} else {
			writeError(w, 400, err.Error())
		}
		return
	}

	s.audit(r, claims.Sub, "profile:import-gravit", project+"/"+profile.ID)
	w.Header().Set("Location", "/api/v1/build-workspaces/"+created.ID)
	writeJSON(w, 201, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"report": result, "profile": profile, "workspace": created}})
}
