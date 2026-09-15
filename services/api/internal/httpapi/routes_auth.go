package httpapi

import "net/http"

func (s Server) registerAuthRoutesV1(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/v1/auth/refresh", s.authRefresh)
	mux.HandleFunc("POST /api/v1/auth/logout", s.authLogout)
	mux.Handle("GET /api/v1/auth/accounts", s.requirePermission("project:read", s.authAccounts))
	mux.Handle("GET /api/v1/auth/sessions", s.requirePermission("project:read", s.v1AuthSessions))
	mux.Handle("POST /api/v1/auth/sessions/revoke", s.requirePermission("project:read", s.v1AuthRevokeSessions))
	mux.Handle("POST /api/v1/auth/sessions/logout-all", s.requirePermission("project:read", s.v1AuthRevokeSessions))
	mux.HandleFunc("GET /api/v1/auth/capabilities", s.authCapabilities)
	mux.HandleFunc("GET /api/v1/auth/password-policy", s.authPasswordPolicy)
	mux.HandleFunc("GET /api/v1/auth/session-policy", s.authSessionPolicy)
	mux.Handle("GET /api/v1/auth/roles", s.requirePermission("users:manage", s.authRoles))
	mux.Handle("POST /api/v1/auth/totp/enroll", s.requirePermission("project:read", s.authTOTPEnroll))
	mux.Handle("POST /api/v1/auth/totp/verify", s.requirePermission("project:read", s.authTOTPVerify))
	mux.Handle("POST /api/v1/auth/totp/disable", s.requirePermission("project:read", s.authTOTPDisable))
	mux.Handle("POST /api/v1/auth/recovery-codes/regenerate", s.requirePermission("project:read", s.authRecoveryCodesRegenerate))
	mux.HandleFunc("POST /api/v1/auth/recovery-code/consume", s.authRecoveryCodeConsume)
	mux.HandleFunc("POST /api/v1/auth/password-reset/request", s.authPasswordResetRequest)
	mux.HandleFunc("POST /api/v1/auth/password-reset/confirm", s.authPasswordResetConfirm)
	mux.HandleFunc("POST /api/v1/auth/email-verification/request", s.authEmailVerificationRequest)
	mux.HandleFunc("POST /api/v1/auth/email-verification/confirm", s.authEmailVerificationConfirm)
}
