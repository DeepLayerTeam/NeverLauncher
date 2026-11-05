package httpapi

import (
	"errors"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"net/http"
	"strconv"
)

type profileRevisionReader0221 interface {
	ListProfileRevisions(projectID, profileID string) ([]model.ProfileSnapshot, error)
}

// Публичные снимки метаданных содержат те же несекретные поля, что GET /profiles.
// Отсутствие запрошенной ревизии даёт 404, а не переход к изменяемому head.
func (s Server) profileRevisions0221(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.Repo.(profileRevisionReader0221)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "Хранилище ревизий профилей недоступно")
		return
	}
	versions, err := reader.ListProfileRevisions(r.PathValue("projectId"), r.PathValue("profileId"))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Профиль не найден")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rev := r.URL.Query().Get("revision")
	if rev != "" {
		index, err := strconv.ParseInt(rev, 10, 64)
		if err != nil || index < 1 {
			writeError(w, http.StatusBadRequest, "Ревизия должна быть положительным целым числом")
			return
		}
		for _, version := range versions {
			if version.Revision == index {
				writeJSON(w, http.StatusOK, version)
				return
			}
		}
		writeError(w, http.StatusNotFound, "Ревизия не найдена")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions})
}
