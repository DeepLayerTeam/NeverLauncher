package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func (s Server) telemetryEvent(w http.ResponseWriter, r *http.Request) {
	var req telemetryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.ProjectID == "" || req.Event == "" {
		writeError(w, http.StatusBadRequest, "projectId и event обязательны")
		return
	}
	s.Repo.AddTelemetryEvent(model.TelemetryEvent{ProjectID: req.ProjectID, ProfileID: req.ProfileID, LauncherVersion: req.LauncherVersion, ProfileVersion: req.ProfileVersion, Event: req.Event, Status: req.Status, CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted"})
}

func (s Server) crashReport(w http.ResponseWriter, r *http.Request) {
	var req crashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.ProjectID == "" || req.Message == "" {
		writeError(w, http.StatusBadRequest, "projectId и message обязательны")
		return
	}
	s.Repo.AddCrashReport(model.CrashReport{ProjectID: req.ProjectID, ProfileID: req.ProfileID, LauncherVersion: req.LauncherVersion, ProfileVersion: req.ProfileVersion, Message: req.Message, Log: req.Log, CreatedAt: time.Now().UTC()})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted"})
}
