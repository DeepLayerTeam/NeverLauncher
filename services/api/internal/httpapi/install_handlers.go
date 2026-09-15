package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type installBootstrapAdminRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
	Actor       string `json:"actor"`
}

type installFirstProjectRequest struct {
	ProjectID string `json:"projectId"`
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
	Version   string `json:"version"`
	Actor     string `json:"actor"`
}

func (s Server) installWizard(w http.ResponseWriter, r *http.Request) {
	profile := queryDefault(r, "profile", "single-server-local")
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": installWizardAPI(s.Version, profile)})
}

func (s Server) installProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "profiles": []map[string]any{{"id": "single-server-local", "storage": "local", "components": []string{"api", "admin", "desktop", "postgres"}}, {"id": "single-server-s3", "storage": "s3", "components": []string{"api", "admin", "desktop", "postgres", "s3"}}, {"id": "development", "storage": "local", "components": []string{"api", "admin", "desktop"}}}}})
}

func (s Server) installReadiness(w http.ResponseWriter, r *http.Request) {
	checks := []map[string]any{}
	status := "ready"
	if s.Storage != nil {
		if err := s.Storage.Health(r.Context()); err != nil {
			status = "degraded"
			checks = append(checks, map[string]any{"id": "storage", "status": "failed", "error": err.Error()})
		} else {
			checks = append(checks, map[string]any{"id": "storage", "status": "ready"})
		}
	}
	if health, ok := any(s.Repo).(interface{ Health(context.Context) error }); ok {
		if err := health.Health(r.Context()); err != nil {
			status = "degraded"
			checks = append(checks, map[string]any{"id": "repository", "status": "failed", "error": err.Error()})
		} else {
			checks = append(checks, map[string]any{"id": "repository", "status": "ready"})
		}
	} else {
		checks = append(checks, map[string]any{"id": "repository", "status": "ready", "mode": "in-memory-or-interface-without-health"})
	}
	installationCompleted := false
	bootstrapTokenConsumed := false
	if installState, err := s.installationStateP0(r.Context()); err != nil {
		status = "degraded"
		checks = append(checks, map[string]any{"id": "installation-state", "status": "failed", "error": err.Error()})
	} else {
		installationCompleted = installState.Completed
		bootstrapTokenConsumed = installState.TokenUsedAt.Valid
		stateStatus := "setup-required"
		if installState.Completed {
			stateStatus = "completed"
		} else {
			status = "setup_required"
		}
		checks = append(checks, map[string]any{"id": "installation-state", "status": stateStatus, "installationCompleted": installState.Completed, "bootstrapTokenConsumed": installState.TokenUsedAt.Valid})
	}
	if users := s.Repo.ListUsers(); len(users) > 0 {
		checks = append(checks, map[string]any{"id": "admin-user", "status": "ready", "count": len(users)})
	} else {
		status = "degraded"
		checks = append(checks, map[string]any{"id": "admin-user", "status": "missing"})
	}
	if projects := s.Repo.ListProjects(); len(projects) > 0 {
		checks = append(checks, map[string]any{"id": "first-project", "status": "ready", "count": len(projects)})
	} else {
		status = "degraded"
		checks = append(checks, map[string]any{"id": "first-project", "status": "missing"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "status": status, "installationCompleted": installationCompleted, "bootstrapTokenConsumed": bootstrapTokenConsumed, "checks": checks}})
}

func (s Server) installBootstrapAdmin(w http.ResponseWriter, r *http.Request) {
	var req installBootstrapAdminRequest
	if r.Body == nil || json.NewDecoder(r.Body).Decode(&req) != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	user, err := s.createBootstrapAdminP0(r.Context(), req.Email, req.DisplayName, req.Password, req.Actor, bootstrapTokenFromRequestP0(r))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "userId": user.ID, "email": user.Email, "displayName": user.DisplayName, "status": "admin-created", "bootstrapTokenConsumed": true}})
}

func (s Server) installFirstProject(w http.ResponseWriter, r *http.Request) {
	var req installFirstProjectRequest
	if r.Body == nil || json.NewDecoder(r.Body).Decode(&req) != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	req.ProjectID = firstNonEmpty(strings.TrimSpace(req.ProjectID), "default-project")
	req.ProfileID = firstNonEmpty(strings.TrimSpace(req.ProfileID), "vanilla")
	req.Channel = firstNonEmpty(strings.TrimSpace(req.Channel), "stable")
	req.Version = firstNonEmpty(strings.TrimSpace(req.Version), "0.1.0")
	now := time.Now().UTC()
	project, err := s.Repo.SaveProject(model.Project{ID: req.ProjectID, Name: req.ProjectID, DefaultChannel: req.Channel, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, err = s.Repo.SaveProfile(model.Profile{ID: req.ProfileID, ProjectID: req.ProjectID, Name: req.ProfileID, Loader: "vanilla", IsDefault: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, err = s.Repo.SaveChannel(model.ReleaseChannel{ID: req.Channel, ProjectID: req.ProjectID, Name: req.Channel, Protected: req.Channel == "stable"}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	release, err := s.publishSigned(req.ProjectID, req.ProfileID, req.Channel, req.Version)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err = s.completeInstallationP0(r.Context()); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: fmt.Sprintf("install-project-%d", now.UnixNano()), Actor: firstNonEmpty(s.adminActor(r), req.Actor, "installer"), Action: "install.first-project", Target: release.ID, UserAgent: s.Version, CreatedAt: now})
	writeJSON(w, http.StatusCreated, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "projectId": project.ID, "profileId": req.ProfileID, "channel": req.Channel, "version": release.Version, "releaseId": release.ID, "status": "installation-completed", "installationCompleted": true}})
}

func installWizardAPI(toolVersion, profile string) map[string]any {
	return map[string]any{"schemaVersion": apiContractVersion, "toolVersion": toolVersion, "mode": "production", "profile": profile, "status": "ready", "steps": []map[string]any{{"id": "environment", "required": []string{"NEVERLAUNCHER_DATABASE_DSN", "NEVERLAUNCHER_SQL_DRIVER=pgx"}}, {"id": "storage", "required": []string{"local-or-s3"}}, {"id": "bootstrap-admin", "endpoint": "POST /api/v1/install/bootstrap-admin"}, {"id": "first-project", "endpoint": "POST /api/v1/install/first-project"}, {"id": "readiness", "endpoint": "GET /api/v1/install/readiness"}, {"id": "verify", "command": "nl install verify --backend http://localhost:8080"}}}
}
