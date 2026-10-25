package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

var (
	ErrProviderNotFound      = errors.New("auth provider not found")
	ErrCapabilityUnsupported = errors.New("auth provider capability unsupported")
	ErrIdentityNotLinked     = errors.New("external identity is not linked to a Never user")
)

type Result struct {
	Provider          authconnector.Metadata
	Identity          model.AuthIdentity
	User              model.User
	AuthMethods       []string
	ProviderToken     string
	ProviderExpiresAt time.Time
}

type ProviderHealth struct {
	Metadata authconnector.Metadata `json:"metadata"`
	Healthy  bool                   `json:"healthy"`
	Error    string                 `json:"error,omitempty"`
}

// Core управляет провайдерами и обязательной границей ExternalIdentity -> канонический
// пользователь Never. Коннекторы аутентифицируют внешние данные, но никогда не
// выдают токены доступа или обновления Never и не обходят политику сеансов.
type ProviderPolicy struct {
	AutoProvision bool
	DefaultRole   string
	RoleMappings  map[string]string
}

type Core struct {
	repo       repository.Repository
	mu         sync.RWMutex
	connectors map[string]authconnector.Connector
	policies   map[string]ProviderPolicy
	routing    RoutingConfig
}

func New(repo repository.Repository) *Core {
	return &Core{repo: repo, connectors: make(map[string]authconnector.Connector), policies: make(map[string]ProviderPolicy)}
}

func (c *Core) Register(connector authconnector.Connector) error {
	return c.RegisterWithPolicy(connector, ProviderPolicy{})
}

func (c *Core) RegisterWithPolicy(connector authconnector.Connector, policy ProviderPolicy) error {
	if connector == nil {
		return errors.New("connector is nil")
	}
	if err := authconnector.ValidateConnector(connector); err != nil {
		return err
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	policy.DefaultRole = strings.TrimSpace(policy.DefaultRole)
	if policy.AutoProvision {
		if policy.DefaultRole == "" {
			policy.DefaultRole = "player"
		}
		roleExists := false
		for _, role := range c.repo.ListRoles() {
			if role.ID == policy.DefaultRole {
				roleExists = true
				break
			}
		}
		if !roleExists {
			return fmt.Errorf("connector %q auto-provision default role %q does not exist", meta.ID, policy.DefaultRole)
		}
	}
	knownRoles := make(map[string]struct{})
	for _, role := range c.repo.ListRoles() {
		knownRoles[role.ID] = struct{}{}
	}
	normalizedMappings := make(map[string]string, len(policy.RoleMappings))
	for externalValue, roleID := range policy.RoleMappings {
		externalValue = strings.TrimSpace(externalValue)
		roleID = strings.TrimSpace(roleID)
		if externalValue == "" || roleID == "" {
			return fmt.Errorf("connector %q contains empty role mapping", meta.ID)
		}
		if _, ok := knownRoles[roleID]; !ok {
			return fmt.Errorf("connector %q role mapping target %q does not exist", meta.ID, roleID)
		}
		normalizedMappings[externalValue] = roleID
	}
	policy.RoleMappings = normalizedMappings
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.connectors[meta.ID]; exists {
		return fmt.Errorf("connector %q already registered", meta.ID)
	}
	c.connectors[meta.ID] = connector
	c.policies[meta.ID] = policy
	return nil
}

func (c *Core) Providers() []authconnector.Metadata {
	c.mu.RLock()
	defer c.mu.RUnlock()
	items := make([]authconnector.Metadata, 0, len(c.connectors))
	for _, connector := range c.connectors {
		items = append(items, authconnector.NormalizedMetadata(connector.Metadata()))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (c *Core) Connector(id string) (authconnector.Connector, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	c.mu.RLock()
	defer c.mu.RUnlock()
	connector, ok := c.connectors[id]
	return connector, ok
}

func (c *Core) ProviderPolicy(id string) ProviderPolicy {
	id = strings.ToLower(strings.TrimSpace(id))
	c.mu.RLock()
	policy := c.policies[id]
	c.mu.RUnlock()
	if len(policy.RoleMappings) != 0 {
		policy.RoleMappings = maps.Clone(policy.RoleMappings)
	}
	return policy
}

func (c *Core) AuthenticatePassword(ctx context.Context, providerID string, request authconnector.PasswordRequest) (Result, error) {
	var routingErr error
	providerID, routingErr = c.RoutePasswordProvider(providerID, request.Identifier)
	if routingErr != nil {
		return Result{}, routingErr
	}
	connector, ok := c.Connector(providerID)
	if !ok {
		return Result{}, ErrProviderNotFound
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	passwordConnector, ok := connector.(authconnector.PasswordAuthenticator)
	if !ok || !authconnector.HasCapability(meta, authconnector.CapabilityPasswordAuth) {
		return Result{}, ErrCapabilityUnsupported
	}
	auth, err := passwordConnector.AuthenticatePassword(ctx, request)
	if err != nil {
		return Result{}, err
	}
	return c.resolveAuthentication(ctx, meta, auth)
}

// LinkPasswordIdentity uses fresh provider credentials solely as proof for an
// explicitly authenticated Never account. Unlike AuthenticatePassword it never
// provisions a user or creates a Never session. No provider fallback is allowed.
func (c *Core) LinkPasswordIdentity(ctx context.Context, userID, providerID string, request authconnector.PasswordRequest) (model.AuthIdentity, authconnector.Authentication, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if err := c.EnsureLinkAllowed(providerID); err != nil {
		return model.AuthIdentity{}, authconnector.Authentication{}, err
	}
	if userID == "" || strings.TrimSpace(request.Identifier) == "" || request.Secret == "" {
		return model.AuthIdentity{}, authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "identity proof requires identifier and password")
	}
	connector, ok := c.Connector(providerID)
	if !ok {
		return model.AuthIdentity{}, authconnector.Authentication{}, ErrProviderNotFound
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	passwordConnector, ok := connector.(authconnector.PasswordAuthenticator)
	if !ok || !authconnector.HasCapability(meta, authconnector.CapabilityPasswordAuth) {
		return model.AuthIdentity{}, authconnector.Authentication{}, ErrCapabilityUnsupported
	}
	proof, err := passwordConnector.AuthenticatePassword(ctx, request)
	if err != nil {
		return model.AuthIdentity{}, authconnector.Authentication{}, err
	}
	if err := authconnector.ValidateAuthentication(proof); err != nil {
		return model.AuthIdentity{}, authconnector.Authentication{}, err
	}
	linked, err := c.LinkAuthenticatedIdentity(userID, providerID, proof)
	if err != nil {
		return model.AuthIdentity{}, authconnector.Authentication{}, err
	}
	return linked, proof, nil
}

func (c *Core) BeginBrowserAuth(ctx context.Context, providerID string, request authconnector.BrowserAuthRequest) (authconnector.BrowserAuthStart, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	connector, ok := c.Connector(providerID)
	if !ok {
		return authconnector.BrowserAuthStart{}, ErrProviderNotFound
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	browserConnector, ok := connector.(authconnector.BrowserAuthenticator)
	if !ok || !authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		return authconnector.BrowserAuthStart{}, ErrCapabilityUnsupported
	}
	return browserConnector.BeginBrowserAuth(ctx, request)
}

func (c *Core) CompleteBrowserAuth(ctx context.Context, providerID string, callback authconnector.BrowserAuthCallback) (Result, error) {
	meta, auth, err := c.CompleteBrowserAuthProof(ctx, providerID, callback)
	if err != nil {
		return Result{}, err
	}
	return c.resolveAuthentication(ctx, meta, auth)
}

// CompleteBrowserAuthProof проверяет внешний браузерный поток без определения
// либо автоматического создания канонического пользователя Never. Это необходимо
// для явной привязки учётной записи: доказательство можно привязать только к
// уже аутентифицированному пользователю Never, выбранному вызывающим кодом.
func (c *Core) CompleteBrowserAuthProof(ctx context.Context, providerID string, callback authconnector.BrowserAuthCallback) (authconnector.Metadata, authconnector.Authentication, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	connector, ok := c.Connector(providerID)
	if !ok {
		return authconnector.Metadata{}, authconnector.Authentication{}, ErrProviderNotFound
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	browserConnector, ok := connector.(authconnector.BrowserAuthenticator)
	if !ok || !authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		return authconnector.Metadata{}, authconnector.Authentication{}, ErrCapabilityUnsupported
	}
	auth, err := browserConnector.CompleteBrowserAuth(ctx, callback)
	if err != nil {
		return authconnector.Metadata{}, authconnector.Authentication{}, err
	}
	if err := authconnector.ValidateAuthentication(auth); err != nil {
		return authconnector.Metadata{}, authconnector.Authentication{}, err
	}
	issuer, err := model.CanonicalAuthIssuer(meta.ID, auth.Identity.Issuer)
	if err != nil {
		return authconnector.Metadata{}, authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrMisconfigured, "invalid authenticated issuer", err)
	}
	auth.Identity.Issuer = issuer
	return meta, auth, nil
}

// RefreshProviderCredential обновляет или перепроверяет внешние учётные данные провайдера.
// Полученный токен провайдера остаётся внутренним и никогда не становится токеном доступа Never.
func (c *Core) RefreshProviderCredential(ctx context.Context, providerID, providerToken, expectedSubject string) (authconnector.Authentication, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	connector, ok := c.Connector(providerID)
	if !ok {
		return authconnector.Authentication{}, ErrProviderNotFound
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	refresher, ok := connector.(authconnector.TokenRefresher)
	if !ok || !authconnector.HasCapability(meta, authconnector.CapabilityTokenRefresh) {
		return authconnector.Authentication{}, ErrCapabilityUnsupported
	}
	auth, err := refresher.Refresh(ctx, providerToken)
	if err != nil {
		return authconnector.Authentication{}, err
	}
	if err := authconnector.ValidateAuthentication(auth); err != nil {
		return authconnector.Authentication{}, err
	}
	if expected := strings.TrimSpace(expectedSubject); expected != "" && auth.Identity.Subject != expected {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrConflict, "provider refresh changed identity subject")
	}
	return auth, nil
}

func (c *Core) resolveAuthentication(ctx context.Context, meta authconnector.Metadata, auth authconnector.Authentication) (Result, error) {
	if err := authconnector.ValidateAuthentication(auth); err != nil {
		return Result{}, err
	}
	auth.Identity.Subject = strings.TrimSpace(auth.Identity.Subject)
	issuer, err := model.CanonicalAuthIssuer(meta.ID, auth.Identity.Issuer)
	if err != nil {
		return Result{}, authconnector.WrapError(authconnector.ErrMisconfigured, "invalid authenticated issuer", err)
	}
	linked, err := c.repo.GetAuthIdentityByIssuer(meta.ID, issuer, auth.Identity.Subject)
	var user model.User
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return Result{}, err
		}
		policy := c.ProviderPolicy(meta.ID)
		if !policy.AutoProvision {
			return Result{}, ErrIdentityNotLinked
		}
		// An unqualified pre-0.29.1 identity must not be silently claimed by
		// a new issuer (even when the email/subject matches). Require an
		// authenticated Never user to explicitly perform browser linking.
		legacyIssuer, _ := model.CanonicalAuthIssuer(meta.ID, "")
		if issuer != legacyIssuer {
			if _, legacyErr := c.repo.GetAuthIdentityByIssuer(meta.ID, legacyIssuer, auth.Identity.Subject); legacyErr == nil {
				return Result{}, ErrIdentityNotLinked
			} else if !errors.Is(legacyErr, repository.ErrNotFound) {
				return Result{}, legacyErr
			}
		}
		auth.Identity.Issuer = issuer
		user, linked, err = c.provisionAuthenticatedIdentity(ctx, meta.ID, policy, auth.Identity)
		if err != nil {
			if errors.Is(err, repository.ErrConflict) {
				return Result{}, authconnector.WrapError(authconnector.ErrConflict, "external identity cannot be provisioned automatically", err)
			}
			return Result{}, err
		}
	} else {
		user, err = c.repo.GetUser(linked.UserID)
		if err != nil {
			return Result{}, err
		}
	}
	if user.ID == "" {
		user, err = c.repo.GetUser(linked.UserID)
		if err != nil {
			return Result{}, err
		}
	}
	if user.Status == "disabled" {
		return Result{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "canonical user is disabled")
	}
	linked.Issuer = issuer
	linked.Email = auth.Identity.Email
	linked.Username = auth.Identity.Username
	linked.DisplayName = auth.Identity.DisplayName
	linked.Claims = cloneClaims(auth.Identity.Claims)
	linked.LastAuthenticatedAt = time.Now().UTC()
	updated, err := c.repo.SaveAuthIdentity(linked)
	if err != nil {
		return Result{}, err
	}
	return Result{Provider: meta, Identity: updated, User: user, AuthMethods: append([]string(nil), auth.AuthMethods...), ProviderToken: auth.ProviderToken, ProviderExpiresAt: auth.ExpiresAt}, nil
}

func (c *Core) provisionAuthenticatedIdentity(ctx context.Context, providerID string, policy ProviderPolicy, identity authconnector.Identity) (model.User, model.AuthIdentity, error) {
	subject := strings.TrimSpace(identity.Subject)
	if subject == "" {
		return model.User{}, model.AuthIdentity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "authenticated identity subject is empty")
	}
	issuer, err := model.CanonicalAuthIssuer(providerID, identity.Issuer)
	if err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	digest := sha256.Sum256([]byte(providerID + "\x00" + issuer + "\x00" + subject))
	stableSuffix := hex.EncodeToString(digest[:12])
	userID := "user-" + providerID + "-" + stableSuffix
	// Email is a mutable claim and may be shared across distinct issuers.
	// Reserve a unique internal login address; the asserted address is saved
	// only on AuthIdentity and is never used for implicit account linking.
	email := stableSuffix + "@identity.invalid"
	displayName := strings.TrimSpace(identity.DisplayName)
	if displayName == "" {
		displayName = strings.TrimSpace(identity.Username)
	}
	if displayName == "" {
		displayName = email
	}
	roleID := policy.DefaultRole
	mappedRoles := map[string]struct{}{}
	for _, externalValue := range append(append([]string(nil), identity.Groups...), identity.Roles...) {
		if mapped, ok := policy.RoleMappings[externalValue]; ok {
			mappedRoles[mapped] = struct{}{}
		}
	}
	if len(mappedRoles) > 1 {
		return model.User{}, model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "external identity matches multiple Never role mappings")
	}
	for mapped := range mappedRoles {
		roleID = mapped
	}
	now := time.Now().UTC()
	return c.repo.SaveFederatedUser(ctx, model.User{
		ID: userID, Email: email, DisplayName: displayName, RoleID: roleID, Status: "active", ProjectRoles: map[string]string{}, CreatedAt: now, UpdatedAt: now,
	}, model.AuthIdentity{
		UserID: userID, Provider: providerID, Issuer: issuer, Subject: subject, Email: identity.Email, Username: identity.Username, DisplayName: identity.DisplayName, Claims: cloneClaims(identity.Claims), LastAuthenticatedAt: now,
	})
}

// LinkAuthenticatedIdentity сохраняет идентичность провайдера только после
// подтверждения его аутентификации вызывающей стороной. Скрытое переназначение
// запрещено: одну пару провайдер/subject нельзя переносить между пользователями Never.
func (c *Core) LinkAuthenticatedIdentity(userID, providerID string, authentication authconnector.Authentication) (model.AuthIdentity, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if err := c.EnsureLinkAllowed(providerID); err != nil {
		return model.AuthIdentity{}, err
	}
	user, err := c.repo.GetUser(userID)
	if err != nil {
		return model.AuthIdentity{}, err
	}
	if user.Status != "active" {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "canonical user cannot link identities")
	}
	if err := authconnector.ValidateAuthentication(authentication); err != nil {
		return model.AuthIdentity{}, err
	}
	identity := authentication.Identity
	identity.Subject = strings.TrimSpace(identity.Subject)
	if identity.Subject == "" {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "authenticated identity subject is empty")
	}
	issuer, err := model.CanonicalAuthIssuer(providerID, identity.Issuer)
	if err != nil {
		return model.AuthIdentity{}, err
	}
	legacyIssuer, _ := model.CanonicalAuthIssuer(providerID, "")
	if issuer != legacyIssuer {
		legacy, legacyErr := c.repo.GetAuthIdentityByIssuer(providerID, legacyIssuer, identity.Subject)
		if legacyErr == nil && legacy.UserID != userID {
			return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "legacy identity belongs to another canonical user")
		}
		if legacyErr != nil && !errors.Is(legacyErr, repository.ErrNotFound) {
			return model.AuthIdentity{}, legacyErr
		}
	}
	existing, err := c.repo.GetAuthIdentityByIssuer(providerID, issuer, identity.Subject)
	if err == nil && existing.UserID != userID {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "identity already linked")
	}
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return model.AuthIdentity{}, err
	}
	return c.repo.SaveAuthIdentity(model.AuthIdentity{UserID: userID, Provider: providerID, Issuer: issuer, Subject: identity.Subject, Email: identity.Email, Username: identity.Username, DisplayName: identity.DisplayName, Claims: cloneClaims(identity.Claims), LastAuthenticatedAt: time.Now().UTC()})
}

// ResolveProviderIdentity reads the configured issuer's subject without linking
// or provisioning a Never account. Response subjects must match the requested
// value; identity data cannot retarget a canonical account.
func (c *Core) ResolveProviderIdentity(ctx context.Context, providerID, subject string) (authconnector.Identity, error) {
	connector, ok := c.Connector(providerID)
	if !ok {
		return authconnector.Identity{}, ErrProviderNotFound
	}
	if !authconnector.HasCapability(connector.Metadata(), authconnector.CapabilityUserLookup) {
		return authconnector.Identity{}, ErrCapabilityUnsupported
	}
	resolver := connector.(authconnector.IdentityResolver)
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "subject is required")
	}
	identity, err := resolver.ResolveIdentity(ctx, authconnector.ResolveRequest{Subject: subject})
	if err != nil {
		return authconnector.Identity{}, err
	}
	if err := authconnector.ValidateIdentity(identity); err != nil {
		return authconnector.Identity{}, err
	}
	if identity.Subject != subject {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrConflict, "provider resolve changed subject")
	}
	return identity, nil
}

// ResolveProviderProfile resolves a profile from its verified provider subject.
func (c *Core) ResolveProviderProfile(ctx context.Context, providerID, subject string) (authconnector.Profile, error) {
	connector, ok := c.Connector(providerID)
	if !ok {
		return authconnector.Profile{}, ErrProviderNotFound
	}
	if !authconnector.HasCapability(connector.Metadata(), authconnector.CapabilityProfile) {
		return authconnector.Profile{}, ErrCapabilityUnsupported
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return authconnector.Profile{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "subject is required")
	}
	profile, err := connector.(authconnector.ProfileResolver).ResolveProfile(ctx, authconnector.ResolveRequest{Subject: subject})
	if err != nil {
		return authconnector.Profile{}, err
	}
	if err := authconnector.ValidateProfile(profile, subject); err != nil {
		return authconnector.Profile{}, err
	}
	return profile, nil
}

func (c *Core) Close() error {
	c.mu.RLock()
	connectors := make([]authconnector.Connector, 0, len(c.connectors))
	for _, connector := range c.connectors {
		connectors = append(connectors, connector)
	}
	c.mu.RUnlock()
	var firstErr error
	for _, connector := range connectors {
		if closer, ok := connector.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (c *Core) Health(ctx context.Context) []ProviderHealth {
	providers := c.Providers()
	result := make([]ProviderHealth, 0, len(providers))
	for _, meta := range providers {
		connector, _ := c.Connector(meta.ID)
		item := ProviderHealth{Metadata: meta, Healthy: true}
		if err := connector.Health(ctx); err != nil {
			item.Healthy = false
			item.Error = err.Error()
		}
		result = append(result, item)
	}
	return result
}

func cloneClaims(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

// RevokeProviderCredential выполняет только выход или отзыв у провайдера. Сеанс Never
// не отзывается; вызывающий код должен инициировать это отдельным явным действием.
func (c *Core) RevokeProviderCredential(ctx context.Context, providerID, subject, providerToken string) error {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	connector, ok := c.Connector(providerID)
	if !ok {
		return ErrProviderNotFound
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	revoker, ok := connector.(authconnector.Revoker)
	if !ok || !authconnector.HasCapability(meta, authconnector.CapabilityTokenRevoke) {
		return ErrCapabilityUnsupported
	}
	subject = strings.TrimSpace(subject)
	providerToken = strings.TrimSpace(providerToken)
	if subject == "" || providerToken == "" {
		return authconnector.NewError(authconnector.ErrInvalidCredentials, "provider subject/token are required for revoke")
	}
	return revoker.Revoke(ctx, authconnector.RevokeRequest{Subject: subject, ProviderToken: providerToken})
}
