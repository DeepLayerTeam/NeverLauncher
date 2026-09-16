package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/federation"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

const federationSchema112 = "0.11.2"

type localAuthConnector112 struct{ repo repository.Repository }

func (c localAuthConnector112) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: "local", DisplayName: "NeverLauncher Local", Version: federationSchema112, Capabilities: []authconnector.Capability{authconnector.CapabilityPasswordAuth, authconnector.CapabilityUserLookup, authconnector.CapabilityEmail, authconnector.CapabilityProfile, authconnector.CapabilityRoles}}
}
func (c localAuthConnector112) Health(ctx context.Context) error {
	if c.repo == nil {
		return errors.New("repository unavailable")
	}
	if health, ok := c.repo.(interface{ Health(context.Context) error }); ok {
		return health.Health(ctx)
	}
	return nil
}
func (c localAuthConnector112) AuthenticatePassword(ctx context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	if c.repo == nil {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrUnavailable, "local repository unavailable")
	}
	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	if identifier == "" || req.Secret == "" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "identifier and password are required")
	}
	user, err := c.repo.GetUserByEmail(identifier)
	if err != nil || !verifyPassword(req.Secret, user.PasswordHash) {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	if user.Status == "disabled" {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "local identity disabled")
	}
	return authconnector.Authentication{Identity: authconnector.Identity{Subject: user.ID, Email: user.Email, Username: user.Email, DisplayName: user.DisplayName, Roles: []string{user.RoleID}, Claims: map[string]any{"roleId": user.RoleID}}, AuthMethods: []string{"password"}}, nil
}
func (c localAuthConnector112) ResolveIdentity(ctx context.Context, req authconnector.ResolveRequest) (authconnector.Identity, error) {
	if c.repo == nil {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrUnavailable, "local repository unavailable")
	}
	user, err := c.repo.GetUser(strings.TrimSpace(req.Subject))
	if err != nil {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "local identity not found")
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
	items := make([]map[string]any, 0, len(providers))
	for _, provider := range providers {
		items = append(items, map[string]any{"id": provider.ID, "displayName": provider.DisplayName, "version": provider.Version, "capabilities": provider.Capabilities, "healthy": healthByID[provider.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "federationVersion": federationSchema114, "items": items}})
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
		items = append(items, map[string]any{"id": identity.ID, "provider": identity.Provider, "subject": identity.Subject, "email": identity.Email, "username": identity.Username, "displayName": identity.DisplayName, "createdAt": identity.CreatedAt, "updatedAt": identity.UpdatedAt, "lastAuthenticatedAt": identity.LastAuthenticatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"schemaVersion": apiContractVersion, "toolVersion": s.Version, "items": items}})
}
