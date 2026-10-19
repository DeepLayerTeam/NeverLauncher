package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func (s Server) channelHead0228(ctx context.Context, projectID, profileID, channel string) (model.ChannelHead, error) {
	reader, ok := s.Repo.(repository.ChannelHeadReader)
	if !ok {
		return model.ChannelHead{}, errors.New("channel head storage unavailable")
	}
	return reader.GetChannelHead(ctx, projectID, profileID, channel)
}

// Authenticated read endpoint for administrators planning an optimistic publish.
func (s Server) channelHeadGet0228(w http.ResponseWriter, r *http.Request) {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	project := r.PathValue("projectId")
	if !s.authorizeClaims(r, claims, "project:read", project, "project", project).Allowed {
		writeError(w, http.StatusForbidden, "project access denied")
		return
	}
	head, err := s.channelHead0228(r.Context(), project, r.PathValue("profileId"), r.PathValue("channel"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(head.Revision, 10)+`"`)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": head})
}
