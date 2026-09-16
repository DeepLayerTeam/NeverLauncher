package httpapi

import (
	"net/http"
	"time"
)

func (s Server) registerBridgeRoutesV1(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/minecraft/session", s.requirePermission("profile:launch", s.minecraftSessionExchange119))
	mux.Handle("GET /api/v1/minecraft/profile", s.requirePermission("profile:launch", s.minecraftProfileCurrent119))
	mux.HandleFunc("POST /authserver/authenticate", s.yggdrasilAuthenticate119)
	mux.HandleFunc("POST /authserver/refresh", s.yggdrasilRefresh119)
	mux.HandleFunc("POST /authserver/validate", s.yggdrasilValidate119)
	mux.HandleFunc("POST /authserver/invalidate", s.yggdrasilInvalidate119)
	mux.HandleFunc("POST /authserver/signout", s.yggdrasilSignout119)
	mux.HandleFunc("POST /sessionserver/session/minecraft/join", s.yggdrasilJoin119)
	mux.HandleFunc("GET /sessionserver/session/minecraft/hasJoined", s.yggdrasilHasJoined119)
	mux.HandleFunc("GET /sessionserver/session/minecraft/profile/{uuid}", s.yggdrasilProfile119)
	mux.HandleFunc("GET /api/profiles/minecraft/{username}", s.yggdrasilProfileByName119)
	mux.Handle("GET /api/v1/server-bridge/servers", s.requirePermission("project:read", s.serverBridgeServersList))
	mux.Handle("POST /api/v1/server-bridge/servers/register", s.requirePermission("settings:manage", s.serverBridgeRegister))
	mux.Handle("POST /api/v1/server-bridge/servers/{serverId}/rotate-token", s.requireFreshAuth117("settings:manage", "phishing-resistant", 5*time.Minute, s.serverBridgeRotateToken))
	mux.HandleFunc("POST /api/v1/server-bridge/servers/{serverId}/heartbeat", s.serverBridgeHeartbeat)
	mux.HandleFunc("POST /api/v1/server-bridge/validate-join", s.serverBridgeValidateJoin)
	mux.HandleFunc("POST /api/v1/server-bridge/audit-event", s.serverBridgeAuditEvent)
	mux.Handle("GET /api/v1/server-bridge/diagnostics", s.requirePermission("project:read", s.serverBridgeDiagnostics))
	mux.Handle("GET /api/v1/server-bridge/plugin-manifest", s.requirePermission("project:read", s.serverBridgePluginManifest))
	mux.Handle("GET /api/v1/server-bridge/plugin-compatibility", s.requirePermission("project:read", s.serverBridgePluginCompatibility))
	mux.HandleFunc("POST /api/v1/session/join", s.sessionJoin)
	mux.HandleFunc("GET /api/v1/session/has-joined", s.sessionHasJoined)
	mux.HandleFunc("POST /api/v1/session/has-joined", s.sessionHasJoined)
	mux.HandleFunc("POST /api/v1/session/invalidate", s.sessionInvalidate)
	mux.HandleFunc("POST /api/v1/session/invalidate-all", s.sessionInvalidateAll)
	mux.HandleFunc("GET /api/v1/textures/{uuid}", s.textureGet)
}
