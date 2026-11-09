package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/federation"
	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	"gitflic.ru/skif4er/launcher/services/api/internal/localpassword"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

const localConnectorVersion0120 = "1.0.0"

type localAuthConnector112 struct{ repo repository.Repository }

func (c localAuthConnector112) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "local", DisplayName: "Локальная авторизация Launcher", Version: localConnectorVersion0120, Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth, authconnector.CapabilityUserLookup, authconnector.CapabilityEmail, authconnector.CapabilityProfile, authconnector.CapabilityRoles}}
}
func (c localAuthConnector112) Health(ctx context.Context) error {
	if c.repo == nil {
		return errors.New("Хранилище данных недоступно")
	}
	if health, ok := c.repo.(interface{ Health(context.Context) error }); ok {
		return health.Health(ctx)
	}
	return nil
}
func (c localAuthConnector112) AuthenticatePassword(ctx context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	if c.repo == nil {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrUnavailable, "Локальное хранилище недоступно")
	}
	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	if identifier == "" || req.Secret == "" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "Требуются идентификатор и пароль")
	}
	user, err := c.repo.GetUserByEmail(identifier)
	if err != nil {
		// Только имя, допустимое в Minecraft, может определять импортированную
		// учётную запись FileAuth. Для email или других поставщиков аутентификации
		// резервный поиск не выполняется.
		if alias, ok := fileauth.UsernameEmail(req.Identifier); ok {
			candidate, lookupErr := c.repo.GetUserByEmail(alias)
			if lookupErr == nil && (strings.HasPrefix(candidate.ID, "gravit-fileauth-") || strings.HasPrefix(candidate.ID, "gravit-sql-")) && candidate.DisplayName == req.Identifier {
				user, err = candidate, nil
			}
		}
	}
	if err != nil || !localpassword.Verify(req.Secret, user.PasswordHash) {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "Неверные учётные данные")
	}
	if user.Status != "active" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "Локальная учётная запись отключена")
	}
	if localpassword.NeedsRehash(user.PasswordHash) {
		// Пересчитывайте хеш только пароля, прошедшего явно настроенную проверку. Параллельный
		// сброс должен иметь приоритет над старым секретом, а не перезаписываться им.
		replacement, hashErr := localpassword.Hash(req.Secret)
		if hashErr != nil {
			return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrUnavailable, "Не удалось обновить локальный пароль")
		}
		cas, ok := c.repo.(repository.PasswordCAS0295)
		if !ok {
			return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrUnavailable, "Локальное хранилище не поддерживает атомарное обновление пароля")
		}
		changed, casErr := cas.ReplacePasswordIfMatch0295(ctx, user.ID, user.PasswordHash, replacement)
		if casErr != nil {
			return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrUnavailable, "Не удалось обновить локальный пароль")
		}
		if !changed {
			return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "Локальные учётные данные изменились во время аутентификации")
		}
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: user.ID, Email: user.Email, Username: user.Email, DisplayName: user.DisplayName, Roles: []string{user.RoleID}, Claims: map[string]any{"roleId": user.RoleID}}, AuthMethods: []string{"password"}}, nil
}
func (c localAuthConnector112) ResolveIdentity(ctx context.Context, req authconnector.ResolveRequest) (authconnector.Identity, error) {
	if c.repo == nil {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrUnavailable, "Локальное хранилище недоступно")
	}
	user, err := c.repo.GetUser(strings.TrimSpace(req.Subject))
	if err != nil {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "Локальная учётная запись не найдена")
	}
	return authconnector.Identity{Subject: user.ID, Email: user.Email, Username: user.Email, DisplayName: user.DisplayName, Roles: []string{user.RoleID}, Claims: map[string]any{"roleId": user.RoleID}}, nil
}

func (c localAuthConnector112) ResolveProfile(ctx context.Context, req authconnector.ResolveRequest) (authconnector.Profile, error) {
	identity, err := c.ResolveIdentity(ctx, req)
	if err != nil {
		return authconnector.Profile{}, err
	}
	return authconnector.Profile{Subject: identity.Subject, DisplayName: identity.DisplayName}, nil
}

func NewFederationCore112(repo repository.Repository) (*federation.Core, error) {
	core := federation.New(repo)
	if err := core.Register(localAuthConnector112{repo: repo}); err != nil {
		return nil, err
	}
	return core, nil
}

func federationHTTPStatus112(err error) int {
	switch {
	case errors.Is(err, federation.ErrProviderNotFound), errors.Is(err, federation.ErrCapabilityUnsupported):
		return 400
	case errors.Is(err, federation.ErrIdentityNotLinked):
		return 403
	}
	switch authconnector.CodeOf(err) {
	case authconnector.ErrInvalidCredentials:
		return 401
	case authconnector.ErrIdentityDisabled:
		return 403
	case authconnector.ErrUnavailable:
		return 503
	case authconnector.ErrConflict:
		return 409
	default:
		return 500
	}
}

func (s Server) authProviders112(w http.ResponseWriter, r *http.Request) {
	providers := s.Federation.Providers()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	health := s.Federation.Health(ctx)
	healthByID := make(map[string]bool, len(health))
	for _, item := range health {
		healthByID[item.Metadata.ID] = item.Healthy
	}
	routing := s.Federation.Routing()
	items := make([]map[string]any, 0, len(providers))
	for _, provider := range providers {
		items = append(items, map[string]any{"id": provider.ID, "displayName": provider.DisplayName, "version": provider.Version, "capabilities": provider.Capabilities, "healthy": healthByID[provider.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "federationVersion": s.Version, "items": items, "routing": map[string]any{"defaultProvider": routing.DefaultProvider, "requireExplicitProvider": routing.RequireExplicitProvider}}})
}

func (s Server) authIdentities112(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAdminTokenFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	identities := s.Repo.ListAuthIdentities(claims.Sub)
	items := make([]map[string]any, 0, len(identities))
	for _, identity := range identities {
		items = append(items, map[string]any{"id": identity.ID, "provider": identity.Provider, "issuer": identity.Issuer, "subject": identity.Subject, "email": identity.Email, "username": identity.Username, "displayName": identity.DisplayName, "createdAt": identity.CreatedAt, "updatedAt": identity.UpdatedAt, "lastAuthenticatedAt": identity.LastAuthenticatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "items": items}})
}
