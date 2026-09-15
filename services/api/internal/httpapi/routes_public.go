package httpapi

import "net/http"

func (s Server) registerPublicRoutesV1(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/diagnostics/policy", s.diagnosticsPolicy)
	mux.HandleFunc("POST /api/v1/diagnostics/validate", s.diagnosticsValidate)
	mux.HandleFunc("GET /api/v1/runtime/requirements", s.runtimeRequirements)
	mux.HandleFunc("GET /api/v1/loaders", s.loaders)
	mux.HandleFunc("GET /api/v1/loaders/{loaderId}", s.loader)
	mux.HandleFunc("GET /api/v1/loaders/compatibility", s.loaderCompatibility)
	mux.HandleFunc("GET /api/v1/install/wizard", s.installWizard)
	mux.HandleFunc("GET /api/v1/install/profiles", s.installProfiles)
	mux.HandleFunc("GET /api/v1/install/readiness", s.installReadiness)
	mux.HandleFunc("POST /api/v1/install/bootstrap-admin", s.installBootstrapAdmin)
}
