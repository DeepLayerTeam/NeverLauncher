package httpapi

import "net/http"

func (s Server) registerProjectRoutesV1(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/projects", s.projects)
	mux.HandleFunc("GET /api/v1/projects/{projectId}", s.project)
	mux.HandleFunc("GET /api/v1/projects/{projectId}/profiles", s.profiles)
	mux.HandleFunc("GET /api/v1/projects/{projectId}/channels", s.channels)
	mux.HandleFunc("GET /api/v1/projects/{projectId}/versions", s.versions)
	mux.HandleFunc("GET /api/v1/projects/{projectId}/files", s.files)
	mux.HandleFunc("GET /api/v1/projects/{projectId}/profiles/{profileId}/manifest", s.manifest)
	mux.HandleFunc("GET /api/v1/files/{projectId}/{version}/{path...}", s.file)
	mux.Handle("POST /api/v1/install/first-project", s.requirePermission("project:write", s.installFirstProject))
	mux.Handle("POST /api/v1/admin/projects", s.requirePermission("project:write", s.adminProjectCreate))
	mux.Handle("PATCH /api/v1/admin/projects/{projectId}", s.requirePermission("project:write", s.adminProjectUpdate))
	mux.Handle("POST /api/v1/admin/projects/{projectId}/profiles", s.requirePermission("project:write", s.adminProfileCreate))
	mux.Handle("PATCH /api/v1/admin/projects/{projectId}/profiles/{profileId}", s.requirePermission("project:write", s.adminProfileUpdate))
	mux.Handle("POST /api/v1/admin/projects/{projectId}/channels", s.requirePermission("project:write", s.adminChannelCreate))
	mux.Handle("PATCH /api/v1/admin/projects/{projectId}/channels/{channelId}", s.requirePermission("project:write", s.adminChannelUpdate))
}
