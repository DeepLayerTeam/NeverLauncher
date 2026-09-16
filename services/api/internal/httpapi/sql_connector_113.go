package httpapi

import (
	"context"
	"fmt"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/httpconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/microsoftconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/oidcconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector/conformance"
)

const federationSchema116 = "0.11.6"
const federationSchema115 = federationSchema116
const federationSchema114 = federationSchema116

// NewFederationCore116 builds the production provider registry. Every configured
// provider is opened, health-checked, SDK-conformance checked and registered before
// the API accepts traffic. A broken SQL/HTTP/OIDC provider therefore fails startup
// instead of silently degrading authentication to another provider.
func NewFederationCore116(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
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

	oidcConfigs, err := oidcconnector.LoadConfigs(cfg.AuthOIDCProvidersJSON, cfg.AuthOIDCProvidersFile)
	if err != nil {
		_ = core.Close()
		return nil, err
	}
	for _, providerConfig := range oidcConfigs {
		connector, err := oidcconnector.New(ctx, providerConfig)
		if err != nil {
			_ = core.Close()
			return nil, err
		}
		if err := registerFederatedConnector(ctx, core, connector, connector.ProvisioningMode(), connector.DefaultRole()); err != nil {
			_ = connector.Close()
			_ = core.Close()
			return nil, fmt.Errorf("OIDC connector registration: %w", err)
		}
	}

	microsoftConfigs, err := microsoftconnector.LoadConfigs(cfg.AuthMicrosoftProvidersJSON, cfg.AuthMicrosoftProvidersFile)
	if err != nil {
		_ = core.Close()
		return nil, err
	}
	for _, providerConfig := range microsoftConfigs {
		connector, err := microsoftconnector.New(ctx, providerConfig)
		if err != nil {
			_ = core.Close()
			return nil, err
		}
		if err := registerFederatedConnector(ctx, core, connector, connector.ProvisioningMode(), connector.DefaultRole()); err != nil {
			_ = connector.Close()
			_ = core.Close()
			return nil, fmt.Errorf("Microsoft connector registration: %w", err)
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
	if mapper, ok := connector.(interface{ RoleMappings() map[string]string }); ok {
		policy.RoleMappings = mapper.RoleMappings()
	}
	return core.RegisterWithPolicy(connector, policy)
}

// NewFederationCore115 remains source-compatible for 0.11.5 embedders.
func NewFederationCore115(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore116(ctx, repo, cfg)
}

// NewFederationCore113 remains source-compatible for embedders/tests compiled against
// 0.11.3. It now delegates to the current registry and therefore also loads HTTP
// providers when they are configured.
func NewFederationCore114(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore116(ctx, repo, cfg)
}

func NewFederationCore113(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore116(ctx, repo, cfg)
}
