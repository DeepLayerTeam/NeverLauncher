package httpapi

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/eventbus"
)

func (s Server) eventBusStatus0206(w http.ResponseWriter, r *http.Request) {
	if s.EventBus == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "disabled"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "running", "config": s.EventBus.ConfigSummary(), "eventTypes": eventbus.KnownEventTypes()}})
}
func (s Server) eventSubscriptions0206(w http.ResponseWriter, r *http.Request) {
	if s.EventBus == nil {
		writeError(w, http.StatusServiceUnavailable, "event bus disabled")
		return
	}
	items, err := s.EventBus.Subscriptions(r.Context(), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("extensionId"))), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope"))), strings.TrimSpace(r.URL.Query().Get("scopeId")))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items}})
}
func (s Server) eventDeadLetters0206(w http.ResponseWriter, r *http.Request) {
	if s.EventBus == nil {
		writeError(w, http.StatusServiceUnavailable, "event bus disabled")
		return
	}
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	items, err := s.EventBus.DeadLetters(r.Context(), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("extensionId"))), limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"items": items}})
}
func (s Server) logEventError0206(kind string, err error) {
	if err != nil {
		log.Printf("NeverExtensions событие %s ошибка: %v", kind, err)
	}
}

func (s Server) beforeProjectSave0206(r *http.Request, action string, p model.Project) error {
	if s.EventBus == nil {
		return nil
	}
	return s.EventBus.BeforeProjectSave(r.Context(), s.adminActor(r), action, p)
}
func (s Server) projectSaved0206(r *http.Request, action string, p model.Project) {
	if s.EventBus != nil {
		s.logEventError0206("project.saved", s.EventBus.ProjectSaved(r.Context(), s.adminActor(r), action, p))
	}
}
func (s Server) releaseCreated0206(r *http.Request, rel model.ReleaseVersion) {
	if s.EventBus != nil {
		s.logEventError0206("release.created", s.EventBus.ReleaseCreated(r.Context(), s.adminActor(r), rel))
	}
}
func (s Server) beforeReleasePublish0206(r *http.Request, rel model.ReleaseVersion) error {
	if s.EventBus == nil {
		return nil
	}
	return s.EventBus.BeforeReleasePublish(r.Context(), s.adminActor(r), rel)
}
func (s Server) releasePublished0206(r *http.Request, rel model.ReleaseVersion) {
	if s.EventBus != nil {
		s.logEventError0206("release.published", s.EventBus.ReleasePublished(r.Context(), s.adminActor(r), rel))
	}
}
func (s Server) packageEvent0206(r *http.Request, eventType, status string, rel model.ReleaseVersion) {
	if s.EventBus == nil {
		return
	}
	p := eventbus.PackagePayload{Action: eventType, Actor: s.adminActor(r), PackageID: rel.ID, ProjectID: rel.ProjectID, ProfileID: rel.ProfileID, Channel: rel.Channel, Version: rel.Version, Status: status}
	s.logEventError0206(eventType, s.EventBus.PackageEvent(r.Context(), eventType, p))
}
func (s Server) beforePackagePublish0206(r *http.Request, rel model.ReleaseVersion) error {
	if s.EventBus == nil {
		return nil
	}
	return s.EventBus.BeforePackagePublish(r.Context(), eventbus.PackagePayload{Action: "publish", Actor: s.adminActor(r), PackageID: rel.ID, ProjectID: rel.ProjectID, ProfileID: rel.ProfileID, Channel: rel.Channel, Version: rel.Version, Status: rel.Status})
}
func (s Server) beforeStorageWrite0206(r *http.Request, projectID, versionID, path string) error {
	if s.EventBus == nil {
		return nil
	}
	return s.EventBus.BeforeStorageWrite(r.Context(), eventbus.StoragePayload{Action: "write", Actor: s.adminActor(r), ProjectID: projectID, VersionID: versionID, Path: path})
}
func (s Server) storageWritten0206(r *http.Request, f model.FileObject) {
	if s.EventBus != nil {
		s.logEventError0206("storage.file-written", s.EventBus.StorageWritten(r.Context(), eventbus.StoragePayload{Action: "written", Actor: s.adminActor(r), ProjectID: f.ProjectID, VersionID: f.VersionID, Path: f.Path, SHA256: f.SHA256, Size: f.Size}))
	}
}
