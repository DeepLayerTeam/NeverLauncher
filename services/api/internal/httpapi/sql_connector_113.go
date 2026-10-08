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

// NewFederationCore собирает стабильный 0.12+ рабочий провайдер реестр. Каждый настраивать
// провайдер является открытый, работоспособность-проверен, SDK-соответствие проверен и регистрировать до
// API принимает трафик. broken SQL/HTTP/OIDC провайдер поэтому завершается ошибкой запуск
// вместо этого без уведомления degrading аутентификация к другой провайдер.
func NewFederationCore(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	core := federation.New(repo)
	local := localAuthConnector112{repo: repo}
	if report := conformance.Run(ctx, local); !report.Passed {
		return nil, fmt.Errorf("локальный коннектор ошибка SDK соответствие: %+v", report.Checks)
	}
	if err := core.Register(local); err != nil {
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
			return nil, fmt.Errorf("SQL коннектор регистрация: %w", err)
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
			return nil, fmt.Errorf("HTTP коннектор регистрация: %w", err)
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
			return nil, fmt.Errorf("OIDC коннектор регистрация: %w", err)
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
			return nil, fmt.Errorf("Microsoft коннектор регистрация: %w", err)
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
		return fmt.Errorf("коннектор %q ошибка SDK соответствие: %+v", report.ConnectorID, report.Checks)
	}
	policy := federation.ProviderPolicy{AutoProvision: provisioningMode == "jit", DefaultRole: defaultRole}
	if mapper, ok := connector.(interface{ RoleMappings() map[string]string }); ok {
		policy.RoleMappings = mapper.RoleMappings()
	}
	return core.RegisterWithPolicy(connector, policy)
}

// NewFederationCore116 остаётся исходник-compatible для 0.11.6+ embedders.
func NewFederationCore116(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore(ctx, repo, cfg)
}

// NewFederationCore115 остаётся исходник-compatible для 0.11.5 embedders.
func NewFederationCore115(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore(ctx, repo, cfg)
}

// NewFederationCore113 остаётся исходник-compatible для embedders/tests compiled против
// 0.11.3. Это теперь delegates к текущий реестр и поэтому также загружает HTTP
// провайдеры когда они являются настраивать.
func NewFederationCore114(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore(ctx, repo, cfg)
}

func NewFederationCore113(ctx context.Context, repo repository.Repository, cfg config.Config) (*federation.Core, error) {
	return NewFederationCore(ctx, repo, cfg)
}
