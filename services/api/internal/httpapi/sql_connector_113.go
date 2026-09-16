package httpapi

import (
	"context"
	"fmt"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/httpconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector/conformance"
)

const federationSchema114 = "0.11.4"

// NewFederationCore114 builds the production provider registry. Every configured
// provider is opened, health-checked, SDK-conformance checked and registered before
// the API accepts traffic. A broken SQL/HTTP provider therefore fails startup
// instead of silently degrading authentication to another provider.
func NewFederationCore114(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	core := federation.New(repo)
	if err := core.Register(localAuthConnector112{repo: repo}); err != nil {
		return nil, err
	}

	sqlConfigs, err := sqlconnector.LoadConfigs(cfg.AuthSQLProvidersJSON, cfg.AuthSQLProvidersFile)
	if err != nil {
		_ = core.Close()
		return nil, err
	}
	for _, providerConfig := range sqlConfigs {
		normalized, err := sqlconnector.Normalize(providerConfig)
		if err != nil {
			_ = core.Close()
			return nil, err
		}
		connector, err := sqlconnector.New(ctx, providerConfig)
		if err != nil {
			_ = core.Close()
			return nil, err
		}
		if err := registerFederatedConnector(ctx, core, connector, normalized.Provisioning.Mode, normalized.Provisioning.DefaultRole); err != nil {
			_ = connector.Close()
			_ = core.Close()
			return nil, fmt.Errorf("SQL connector registration: %w", err)
		}
	}

	httpConfigs, err := httpconnector.LoadConfigs(cfg.AuthHTTPProvidersJSON, cfg.AuthHTTPProvidersFile)
	if err != nil {
		_ = core.Close()
		return nil, err
	}
	for _, providerConfig := range httpConfigs {
		connector, err := httpconnector.New(ctx, providerConfig)
		if err != nil {
			_ = core.Close()
			return nil, err
		}
		if err := registerFederatedConnector(ctx, core, connector, connector.ProvisioningMode(), connector.DefaultRole()); err != nil {
			_ = connector.Close()
			_ = core.Close()
			return nil, fmt.Errorf("HTTP connector registration: %w", err)
		}
	}
	return core, nil
}

func registerFederatedConnector(ctx context.Context, core *federation.Core, connector interface {
	Metadata() authconnector.Metadata
	Health(context.Context) error
}, provisioningMode, defaultRole string) error {
	report := conformance.Run(ctx, connector)
	if !report.Passed {
		return fmt.Errorf("connector %q failed SDK conformance: %+v", report.ConnectorID, report.Checks)
	}
	policy := federation.ProviderPolicy{AutoProvision: provisioningMode == "jit", DefaultRole: defaultRole}
	return core.RegisterWithPolicy(connector, policy)
}

// NewFederationCore113 remains source-compatible for embedders/tests compiled against
// 0.11.3. It now delegates to the current registry and therefore also loads HTTP
// providers when they are configured.
func NewFederationCore113(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore114(ctx, repo, cfg)
}
