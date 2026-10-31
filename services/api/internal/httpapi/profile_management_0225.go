package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type profileCreator0225 interface {
	CreateProfileExclusive0225(model.Profile) (model.Profile, error)
}

type cloneProfileRequest0225 struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	SourceRevision int64  `json:"sourceRevision,omitempty"`
}

type importProfileRequest0225 struct {
	ID     string                    `json:"id"`
	Name   string                    `json:"name"`
	Bundle model.PortableProfile0225 `json:"bundle"`
}

type presetProfileRequest0225 struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	PresetID string `json:"presetId"`
}

func decodeProfileWrite0225(r *http.Request, out any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("only one JSON object is allowed")
	}
	return nil
}

func (s Server) profileSnapshotAt0225(project, id string, revision int64) (model.ProfileSnapshot, error) {
	if revision < 0 {
		return model.ProfileSnapshot{}, errors.New("revision must be positive")
	}
	if revision == 0 {
		return repository.ReadProfileSnapshot(s.Repo, project, id)
	}
	reader, ok := s.Repo.(profileRevisionReader0221)
	if !ok {
		return model.ProfileSnapshot{}, errors.New("profile revision history unavailable")
	}
	history, err := reader.ListProfileRevisions(project, id)
	if err != nil {
		return model.ProfileSnapshot{}, err
	}
	for _, snap := range history {
		if snap.Revision == revision {
			return snap, nil
		}
	}
	return model.ProfileSnapshot{}, repository.ErrNotFound
}

func (s Server) saveNewProfile0225(w http.ResponseWriter, r *http.Request, profile model.Profile, action string) {
	creator, ok := s.Repo.(profileCreator0225)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "exclusive profile creation unavailable")
		return
	}
	saved, err := creator.CreateProfileExclusive0225(profile)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "profile already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), action, saved.ProjectID+"/"+saved.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"profile": saved, "status": "created"}})
}

func (s Server) profileClone0225(w http.ResponseWriter, r *http.Request) {
	var req cloneProfileRequest0225
	if err := decodeProfileWrite0225(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	project, id := r.PathValue("projectId"), r.PathValue("profileId")
	snap, err := s.profileSnapshotAt0225(project, id, req.SourceRevision)
	if err != nil {
		profileReadError0225(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = snap.Spec.Name + " (copy)"
	}
	p, err := model.CreateFromSnapshot0225(snap, project, req.ID, name)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.saveNewProfile0225(w, r, p, "profile:clone")
}

func (s Server) profileExport0225(w http.ResponseWriter, r *http.Request) {
	revision, err := readRevision0225(r.URL.Query().Get("revision"))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	snap, err := s.profileSnapshotAt0225(r.PathValue("projectId"), r.PathValue("profileId"), revision)
	if err != nil {
		profileReadError0225(w, err)
		return
	}
	bundle, err := model.ExportProfile0225(snap)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="profile-r%d.json"`, snap.Revision))
	writeJSON(w, http.StatusOK, bundle)
}

func (s Server) profileImport0225(w http.ResponseWriter, r *http.Request) {
	var req importProfileRequest0225
	if err := decodeProfileWrite0225(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	p, err := model.ImportProfile0225(req.Bundle, r.PathValue("projectId"), req.ID, req.Name)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.saveNewProfile0225(w, r, p, "profile:import")
}

func (s Server) profilePresets0225(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": model.ListProfilePresets0225()})
}

func (s Server) profileFromPreset0225(w http.ResponseWriter, r *http.Request) {
	var req presetProfileRequest0225
	if err := decodeProfileWrite0225(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	p, err := model.CreateFromPreset0225(r.PathValue("projectId"), req.ID, req.Name, req.PresetID)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.saveNewProfile0225(w, r, p, "profile:preset-create")
}

func readRevision0225(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("revision must be positive integer")
	}
	return n, nil
}

func profileReadError0225(w http.ResponseWriter, err error) {
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "profile or revision not found")
		return
	}
	if strings.Contains(err.Error(), "revision") {
		writeError(w, 400, err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func (s Server) profileDiff0225(w http.ResponseWriter, r *http.Request) {
	project, id := r.PathValue("projectId"), r.PathValue("profileId")
	other := strings.TrimSpace(r.URL.Query().Get("againstProfileId"))
	if other == "" {
		other = id
	}
	fromRevision, err := readRevision0225(r.URL.Query().Get("fromRevision"))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	toRevision, err := readRevision0225(r.URL.Query().Get("toRevision"))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if fromRevision == 0 && other == id {
		reader, ok := s.Repo.(profileRevisionReader0221)
		if !ok {
			writeError(w, 503, "profile history unavailable")
			return
		}
		history, err := reader.ListProfileRevisions(project, id)
		if err != nil {
			profileReadError0225(w, err)
			return
		}
		if len(history) > 1 {
			fromRevision = history[len(history)-2].Revision
		} else {
			fromRevision = history[0].Revision
		}
	}
	from, err := s.profileSnapshotAt0225(project, id, fromRevision)
	if err != nil {
		profileReadError0225(w, err)
		return
	}
	to, err := s.profileSnapshotAt0225(project, other, toRevision)
	if err != nil {
		profileReadError0225(w, err)
		return
	}
	diff, err := model.DiffProfile0225(from, to)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, diff)
}
