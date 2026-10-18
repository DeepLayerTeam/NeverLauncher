package httpapi

import (
	"errors"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"net/http"
	"strconv"
)

type profileRevisionReader0221 interface {
	ListProfileRevisions(projectID, profileID string) ([]model.ProfileSnapshot, error)
}

// Public metadata snapshots are the same non-secret fields as GET /profiles.
// A missing requested revision is 404, not a fallback to the mutable head.
func (s Server) profileRevisions0221(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.Repo.(profileRevisionReader0221)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "profile revision store not available")
		return
	}
	versions, err := reader.ListProfileRevisions(r.PathValue("projectId"), r.PathValue("profileId"))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "profile not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rev := r.URL.Query().Get("revision")
	if rev != "" {
		index, err := strconv.ParseInt(rev, 10, 64)
		if err != nil || index < 1 {
			writeError(w, http.StatusBadRequest, "revision must be positive integer")
			return
		}
		for _, version := range versions {
			if version.Revision == index {
				writeJSON(w, http.StatusOK, version)
				return
			}
		}
		writeError(w, http.StatusNotFound, "revision not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions})
}
