package federation

import (
	"context"
	"errors"
	"fmt"
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
	Provider    authconnector.Metadata
	Identity    model.AuthIdentity
	User        model.User
	AuthMethods []string
}

type ProviderHealth struct {
	Metadata authconnector.Metadata `json:"metadata"`
	Healthy  bool                   `json:"healthy"`
	Error    string                 `json:"error,omitempty"`
}

// Core owns provider dispatch and the mandatory ExternalIdentity -> canonical Never
// User resolution boundary. Connectors authenticate external credentials; they never
// mint Never access/refresh tokens and never bypass Never session policy.
type Core struct {
	repo       repository.Repository
	mu         sync.RWMutex
	connectors map[string]authconnector.Connector
}

func New(repo repository.Repository) *Core {
	return &Core{repo: repo, connectors: make(map[string]authconnector.Connector)}
}

func (c *Core) Register(connector authconnector.Connector) error {
	if connector == nil {
		return errors.New("connector is nil")
	}
	meta := authconnector.NormalizedMetadata(connector.Metadata())
	if err := authconnector.ValidateMetadata(meta); err != nil {
		return err
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityPasswordAuth) {
		if _, ok := connector.(authconnector.PasswordAuthenticator); !ok {
			return fmt.Errorf("connector %q advertises password-auth without PasswordAuthenticator", meta.ID)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		if _, ok := connector.(authconnector.BrowserAuthenticator); !ok {
			return fmt.Errorf("connector %q advertises browser-auth without BrowserAuthenticator", meta.ID)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityProfile) {
		if _, ok := connector.(authconnector.ProfileResolver); !ok {
			return fmt.Errorf("connector %q advertises profile without ProfileResolver", meta.ID)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityTokenRefresh) {
		if _, ok := connector.(authconnector.TokenRefresher); !ok {
			return fmt.Errorf("connector %q advertises token-refresh without TokenRefresher", meta.ID)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityUserLookup) {
		if _, ok := connector.(authconnector.IdentityResolver); !ok {
			return fmt.Errorf("connector %q advertises user-lookup without IdentityResolver", meta.ID)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.connectors[meta.ID]; exists {
		return fmt.Errorf("connector %q already registered", meta.ID)
	}
	c.connectors[meta.ID] = connector
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

func (c *Core) AuthenticatePassword(ctx context.Context, providerID string, request authconnector.PasswordRequest) (Result, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if providerID == "" {
		providerID = "local"
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
	auth.Identity.Subject = strings.TrimSpace(auth.Identity.Subject)
	if auth.Identity.Subject == "" {
		return Result{}, authconnector.NewError(authconnector.ErrMisconfigured, "connector returned empty subject")
	}
	linked, err := c.repo.GetAuthIdentity(meta.ID, auth.Identity.Subject)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return Result{}, ErrIdentityNotLinked
		}
		return Result{}, err
	}
	user, err := c.repo.GetUser(linked.UserID)
	if err != nil {
		return Result{}, err
	}
	if user.Status == "disabled" {
		return Result{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "canonical user is disabled")
	}
	linked.Email = auth.Identity.Email
	linked.Username = auth.Identity.Username
	linked.DisplayName = auth.Identity.DisplayName
	linked.Claims = cloneClaims(auth.Identity.Claims)
	linked.LastAuthenticatedAt = time.Now().UTC()
	updated, err := c.repo.SaveAuthIdentity(linked)
	if err != nil {
		return Result{}, err
	}
	return Result{Provider: meta, Identity: updated, User: user, AuthMethods: append([]string(nil), auth.AuthMethods...)}, nil
}

// LinkAuthenticatedIdentity persists a provider identity only after the caller has
// obtained an Authentication proof from that provider. It refuses silent reassignment:
// one provider/subject cannot be moved between Never users.
func (c *Core) LinkAuthenticatedIdentity(userID, providerID string, authentication authconnector.Authentication) (model.AuthIdentity, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if _, ok := c.Connector(providerID); !ok {
		return model.AuthIdentity{}, ErrProviderNotFound
	}
	if _, err := c.repo.GetUser(userID); err != nil {
		return model.AuthIdentity{}, err
	}
	identity := authentication.Identity
	identity.Subject = strings.TrimSpace(identity.Subject)
	if identity.Subject == "" {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "authenticated identity subject is empty")
	}
	existing, err := c.repo.GetAuthIdentity(providerID, identity.Subject)
	if err == nil && existing.UserID != userID {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "identity already linked")
	}
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return model.AuthIdentity{}, err
	}
	return c.repo.SaveAuthIdentity(model.AuthIdentity{UserID: userID, Provider: providerID, Subject: identity.Subject, Email: identity.Email, Username: identity.Username, DisplayName: identity.DisplayName, Claims: cloneClaims(identity.Claims)})
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
