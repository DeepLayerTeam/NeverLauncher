package httpapi

import (
	"context"
	"net/http"
)

func (s Server) Handler() http.Handler {
	if s.State == nil {
		s.State = NewRuntimeState()
		// Test/development servers created directly in unit tests use the safe
		// in-memory limiter and do not trust forwarded headers by default.
	}
	if s.State.ServerBridge != nil && s.Repo != nil {
		s.State.ServerBridge.configureRepositoryV2(s.Repo)
	}
	if s.Federation == nil {
		core, err := NewFederationCore(context.Background(), s.Repo, s.Config)
		if err != nil {
			panic("federation core initialization failed: " + err.Error())
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
