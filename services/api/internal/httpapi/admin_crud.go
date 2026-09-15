package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type adminProjectCRUDRequest struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Homepage       string `json:"homepage"`
	Repository     string `json:"repository"`
	DefaultChannel string `json:"defaultChannel"`
}

type adminProfileCRUDRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Loader      string `json:"loader"`
	Preset      string `json:"preset"`
	IsDefault   bool   `json:"isDefault"`
}

type adminChannelCRUDRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protected   bool   `json:"protected"`
}

func (s Server) adminCRUDStatus(w http.ResponseWriter, r *http.Request) {
	projects := s.Repo.ListProjects()
	projectID := queryDefault(r, "project", "")
	if projectID == "" && len(projects) > 0 {
		projectID = projects[0].ID
	}
	profiles, _ := s.Repo.ListProfiles(projectID)
	channels, _ := s.Repo.ListChannels(projectID)
	versions, _ := s.Repo.ListVersions(projectID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"status":        "product-crud-ready",
		"summary":       "Admin UI использует реальные v5 CRUD endpoints для проектов, профилей, каналов и пользователей; write-actions закрыты RBAC и пишут audit events.",
		"counts":        map[string]int{"projects": len(projects), "profiles": len(profiles), "channels": len(channels), "versions": len(versions), "users": len(s.Repo.ListUsers()), "auditEvents": len(s.Repo.ListAuditEvents())},
		"writeEndpoints": []string{
			"POST /api/v1/admin/projects",
			"PATCH /api/v1/admin/projects/{projectId}",
			"POST /api/v1/admin/projects/{projectId}/profiles",
			"PATCH /api/v1/admin/projects/{projectId}/profiles/{profileId}",
			"POST /api/v1/admin/projects/{projectId}/channels",
			"PATCH /api/v1/admin/projects/{projectId}/channels/{channelId}",
			"POST /api/v1/admin/users",
			"PATCH /api/v1/admin/users/{userId}",
			"POST /api/v1/admin/users/{userId}/password",
			"POST /api/v1/admin/users/{userId}/disable",
			"POST /api/v1/admin/users/{userId}/enable",
		},
	}})
}

func (s Server) adminProjectCreate(w http.ResponseWriter, r *http.Request) {
	var req adminProjectCRUDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	project := model.Project{ID: req.ID, Name: req.Name, Description: req.Description, Homepage: req.Homepage, Repository: req.Repository, DefaultChannel: firstNonEmpty(req.DefaultChannel, "stable")}
	saved, err := s.Repo.SaveProject(project)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "project:create", saved.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "project": saved, "status": "created"}})
}

func (s Server) adminProjectUpdate(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectId")
	existing, err := s.Repo.GetProject(projectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	var req adminProjectCRUDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		existing.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Homepage != "" {
		existing.Homepage = req.Homepage
	}
	if req.Repository != "" {
		existing.Repository = req.Repository
	}
	if req.DefaultChannel != "" {
		existing.DefaultChannel = req.DefaultChannel
	}
	saved, err := s.Repo.SaveProject(existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "project:update", saved.ID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "project": saved, "status": "updated"}})
}

func (s Server) adminProfileCreate(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectId")
	var req adminProfileCRUDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	profile := model.Profile{ID: req.ID, ProjectID: projectID, Name: req.Name, Description: req.Description, Loader: firstNonEmpty(req.Loader, "vanilla"), Preset: req.Preset, IsDefault: req.IsDefault}
	saved, err := s.Repo.SaveProfile(profile)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "profile:create", fmt.Sprintf("%s/%s", saved.ProjectID, saved.ID))
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "profile": saved, "status": "created"}})
}

func (s Server) adminProfileUpdate(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectId")
	profileID := r.PathValue("profileId")
	profiles, err := s.Repo.ListProfiles(projectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	var profile model.Profile
	found := false
	for _, item := range profiles {
		if item.ID == profileID {
			profile = item
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "профиль не найден")
		return
	}
	var req adminProfileCRUDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		profile.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != "" {
		profile.Description = req.Description
	}
	if req.Loader != "" {
		profile.Loader = req.Loader
	}
	if req.Preset != "" {
		profile.Preset = req.Preset
	}
	profile.IsDefault = req.IsDefault
	saved, err := s.Repo.SaveProfile(profile)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "profile:update", fmt.Sprintf("%s/%s", saved.ProjectID, saved.ID))
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "profile": saved, "status": "updated"}})
}

func (s Server) adminChannelCreate(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectId")
	var req adminChannelCRUDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	channel := model.ReleaseChannel{ID: req.ID, ProjectID: projectID, Name: firstNonEmpty(req.Name, req.ID), Description: req.Description, Protected: req.Protected}
	saved, err := s.Repo.SaveChannel(channel)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "channel:create", fmt.Sprintf("%s/%s", saved.ProjectID, saved.ID))
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "channel": saved, "status": "created"}})
}

func (s Server) adminChannelUpdate(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectId")
	channelID := r.PathValue("channelId")
	channels, err := s.Repo.ListChannels(projectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "проект не найден")
		return
	}
	var channel model.ReleaseChannel
	found := false
	for _, item := range channels {
		if item.ID == channelID {
			channel = item
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "канал не найден")
		return
	}
	var req adminChannelCRUDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		channel.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != "" {
		channel.Description = req.Description
	}
	channel.Protected = req.Protected
	saved, err := s.Repo.SaveChannel(channel)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, s.adminActor(r), "channel:update", fmt.Sprintf("%s/%s", saved.ProjectID, saved.ID))
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "channel": saved, "status": "updated"}})
}

func (s Server) adminCRUDUserCreate(w http.ResponseWriter, r *http.Request) { s.adminUserCreate(w, r) }
func (s Server) adminCRUDUserUpdate(w http.ResponseWriter, r *http.Request) { s.adminUserUpdate(w, r) }
func (s Server) adminCRUDUserPassword(w http.ResponseWriter, r *http.Request) {
	s.adminUserPassword(w, r)
}
func (s Server) adminCRUDUserDisable(w http.ResponseWriter, r *http.Request) {
	s.adminUserDisable(w, r)
}
func (s Server) adminCRUDUserEnable(w http.ResponseWriter, r *http.Request) { s.adminUserEnable(w, r) }

func (s Server) adminCRUDSmoke(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{
		"schemaVersion": apiContractVersion,
		"toolVersion":   s.Version,
		"status":        "defined-product-smoke",
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"flow":          []string{"login", "create-project", "patch-project", "create-profile", "patch-profile", "create-channel", "patch-channel", "create-user", "disable-user", "enable-user", "audit-review"},
	}})
}
