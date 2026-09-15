package httpapi

import (
	"context"
	"fmt"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlconnector"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector/conformance"
)

const federationSchema113 = "0.11.3"

// NewFederationCore113 builds the actual runtime provider registry. Configured SQL
// providers are opened, health-checked, SDK-conformance checked, and registered
// before the API begins accepting traffic. Invalid/unreachable configured providers
// fail startup instead of silently falling back to local auth.
func NewFederationCore113(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	core := federation.New(repo)
	if err := core.Register(localAuthConnector112{repo: repo}); err != nil {
		return nil, err
	}

	configs, err := sqlconnector.LoadConfigs(cfg.AuthSQLProvidersJSON, cfg.AuthSQLProvidersFile)
	if err != nil {
		return nil, err
	}
	for _, providerConfig := range configs {
		connector, err := sqlconnector.New(ctx, providerConfig)
		if err != nil {
			_ = core.Close()
			return nil, err
		}
		report := conformance.Run(ctx, connector)
		if !report.Passed {
			_ = connector.Close()
			_ = core.Close()
			return nil, fmt.Errorf("SQL connector %q failed SDK conformance: %+v", report.ConnectorID, report.Checks)
		}
		normalized, err := sqlconnector.Normalize(providerConfig)
		if err != nil {
			_ = connector.Close()
			_ = core.Close()
			return nil, err
		}
		policy := federation.ProviderPolicy{AutoProvision: normalized.Provisioning.Mode == "jit", DefaultRole: normalized.Provisioning.DefaultRole}
		if err := core.RegisterWithPolicy(connector, policy); err != nil {
			_ = connector.Close()
			_ = core.Close()
			return nil, err
		}
	}
	return core, nil
}
