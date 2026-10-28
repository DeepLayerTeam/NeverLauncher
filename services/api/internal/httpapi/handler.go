package httpapi

import (
	"context"
	"net/http"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/embeddedadmin"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/authorization"
)

func (s Server) Handler() http.Handler {
	if s.State == nil {
		s.State = NewRuntimeState()
		// Тестовые и разработческие серверы, созданные непосредственно в модульных тестах, используют
		// безопасное ограничение частоты в памяти и по умолчанию не доверяют пересылаемым заголовкам.
	}
	if s.Authorization == nil && s.Repo != nil {
		s.Authorization = authorization.New(s.Repo)
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
	mux.Handle("GET /admin", embeddedadmin.Handler())
	mux.Handle("GET /admin/", embeddedadmin.Handler())
	mux.Handle("GET /admin/app.js", embeddedadmin.Handler())
	mux.Handle("GET /admin/app.css", embeddedadmin.Handler())
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("GET /metrics", s.metrics)
	s.registerPublicRoutesV1(mux)
	s.registerAuthRoutesV1(mux)
	s.registerProjectRoutesV1(mux)
	s.registerPackageRoutesV1(mux)
	s.registerBridgeRoutesV1(mux)
	s.registerOperationsRoutesV1(mux)
	s.registerMigrationRoutes0331(mux)
	s.registerMigrationCompatibilityRoutes0332(mux)
	s.registerMigrationInventoryRoutes0333(mux)
	s.registerMigrationIdentityRoutes0334(mux)
	s.registerMigrationAuthRoutes0335(mux)
	s.registerMigrationSecurityRoutes0336(mux)
	s.registerMigrationContentRoutes0337(mux)
	s.registerMigrationModulesRoutes0338(mux)
	s.registerMigrationRehearsalRoutes03310(mux)
	s.registerMigrationCutoverRoutes03311(mux)
	s.registerMigrationRollbackRoutes03312(mux)
	handler := withSecurityHeaders(withCORS(withTrustedProxyResolution(s.withRateLimit(s.withServerBridgeHardening0149(logRequests(s.State.Maintenance.withMutationLock(s.withManagedProviders02910(mux))))), s.State.TrustedProxies), s.Config.CORSAllowedOrigins))
	if s.Capacity != nil {
		return s.Capacity.HTTP.Wrap(handler)
	}
	return handler
}
