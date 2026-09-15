package httpapi

import "net/http"

func (s Server) Handler() http.Handler {
	if s.State == nil {
		s.State = NewRuntimeState()
		// Test/development servers created directly in unit tests use the safe
		// in-memory limiter and do not trust forwarded headers by default.
	}
	if s.Federation == nil {
		core, err := NewFederationCore112(s.Repo)
		if err != nil {
			panic("federation core 0.11.2 initialization failed: " + err.Error())
		}
		s.Federation = core
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("GET /metrics", s.metrics)
	s.registerPublicRoutesV1(mux)
	s.registerAuthRoutesV1(mux)
	s.registerProjectRoutesV1(mux)
	s.registerPackageRoutesV1(mux)
	s.registerBridgeRoutesV1(mux)
	s.registerOperationsRoutesV1(mux)
	return withSecurityHeaders(withCORS(withTrustedProxyResolution(s.withRateLimit(logRequests(s.State.Maintenance.withMutationLock(mux))), s.State.TrustedProxies), s.Config.CORSAllowedOrigins))
}
