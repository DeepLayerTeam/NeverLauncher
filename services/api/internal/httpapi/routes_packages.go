package httpapi

import (
	"net/http"
	"time"
)

func (s Server) registerPackageRoutesV1(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/admin/login", s.adminLogin)
	mux.Handle("GET /api/v1/admin/me", s.requirePermission("project:read", s.adminMe))
	mux.Handle("POST /api/v1/admin/logout", s.requirePermission("project:read", s.adminLogout))
	mux.Handle("GET /api/v1/admin/overview", s.requirePermission("project:read", s.adminOverview))
	mux.Handle("GET /api/v1/admin/users", s.requirePermission("users:manage", s.adminUsers))
	mux.Handle("POST /api/v1/admin/users", s.requirePermission("users:manage", s.adminUserCreate))
	mux.Handle("PATCH /api/v1/admin/users/{userId}", s.requireFreshAuth117("users:manage", "phishing-resistant", 5*time.Minute, s.adminUserUpdate))
	mux.Handle("POST /api/v1/admin/users/{userId}/password", s.requirePermission("users:manage", s.adminUserPassword))
	mux.Handle("POST /api/v1/admin/users/{userId}/disable", s.requirePermission("users:manage", s.adminUserDisable))
	mux.Handle("POST /api/v1/admin/users/{userId}/enable", s.requirePermission("users:manage", s.adminUserEnable))
	mux.Handle("GET /api/v1/admin/roles", s.requirePermission("users:manage", s.adminRoles))
	mux.Handle("GET /api/v1/admin/audit", s.requirePermission("audit:read", s.adminAudit))
	mux.Handle("GET /api/v1/admin/storage/health", s.requirePermission("project:read", s.adminStorageHealth))
	mux.Handle("POST /api/v1/admin/projects/{projectId}/publish", s.requireFreshAuth117("release:publish", "mfa", 5*time.Minute, s.adminPublish))
	mux.Handle("POST /api/v1/admin/projects/{projectId}/versions", s.requirePermission("release:prepare", s.adminVersionCreate))
	mux.Handle("PUT /api/v1/admin/projects/{projectId}/versions/{versionId}/manifest", s.requirePermission("release:prepare", s.adminVersionManifestUpdate))
	mux.Handle("POST /api/v1/admin/projects/{projectId}/versions/{versionId}/files", s.requirePermission("file:write", s.adminFileUpload))
	mux.Handle("POST /api/v1/admin/projects/{projectId}/versions/{versionId}/publish", s.requireFreshAuth117("release:publish", "mfa", 5*time.Minute, s.adminVersionPublish))
	mux.Handle("GET /api/v1/admin/projects/{projectId}/export", s.requirePermission("project:read", s.adminProjectExport))
	mux.Handle("POST /api/v1/admin/projects/import", s.requirePermission("project:write", s.adminProjectImport))
	mux.Handle("POST /api/v1/telemetry/events", s.requirePermission("project:read", s.telemetryEvent))
	mux.Handle("POST /api/v1/crash-reports", s.requirePermission("project:read", s.crashReport))
	mux.Handle("POST /api/v1/packages", s.requirePermission("release:prepare", s.packageCreate))
	mux.Handle("GET /api/v1/packages/{packageId}", s.requirePermission("project:read", s.packageGet))
	mux.Handle("POST /api/v1/packages/{packageId}/files", s.requirePermission("file:write", s.packageUploadFile))
	mux.Handle("POST /api/v1/packages/{packageId}/validate", s.requirePermission("release:prepare", s.packageValidate))
	mux.Handle("POST /api/v1/packages/{packageId}/sign", s.requireFreshAuth117("release:prepare", "phishing-resistant", 5*time.Minute, s.packageSign))
	mux.Handle("POST /api/v1/packages/{packageId}/stage", s.requirePermission("release:prepare", s.packageStage))
	mux.Handle("POST /api/v1/packages/{packageId}/smoke-test", s.requirePermission("release:prepare", s.packageSmoke))
	mux.Handle("POST /api/v1/packages/{packageId}/publish", s.requireFreshAuth117("release:publish", "mfa", 5*time.Minute, s.packagePublishProduct))
	mux.Handle("POST /api/v1/channels/{channel}/rollback", s.requireFreshAuth117("release:publish", "mfa", 5*time.Minute, s.channelRollbackProduct))
	mux.Handle("GET /api/v1/storage/delivery-policy", s.requirePermission("project:read", s.storageDeliveryPolicy))
}
