package federation

import (
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

// RefreshLinkedIdentity updates claims of an identity that was linked before
// this operation. It is NOT account linking, so a policy disabling *new*
// linking must not break the normal refresh lifecycle of existing credentials.
// expectedID pins the operation to the exact persisted issuer-scoped identity.
func (c *Core) RefreshLinkedIdentity(userID, providerID, expectedID string, authentication authconnector.Authentication) (model.AuthIdentity, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if _, ok := c.Connector(providerID); !ok {
		return model.AuthIdentity{}, ErrProviderNotFound
	}
	user, err := c.repo.GetUser(userID)
	if err != nil {
		return model.AuthIdentity{}, err
	}
	if user.Status != "active" {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "canonical user is disabled")
	}
	if strings.TrimSpace(expectedID) == "" {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "expected linked identity ID is required")
	}
	if err := authconnector.ValidateAuthentication(authentication); err != nil {
		return model.AuthIdentity{}, err
	}
	identity := authentication.Identity
	identity.Subject = strings.TrimSpace(identity.Subject)
	issuer, err := model.CanonicalAuthIssuer(providerID, identity.Issuer)
	if err != nil {
		return model.AuthIdentity{}, authconnector.WrapError(authconnector.ErrMisconfigured, "invalid authenticated issuer", err)
	}
	linked, err := c.repo.GetAuthIdentityByIssuer(providerID, issuer, identity.Subject)
	if errors.Is(err, repository.ErrNotFound) {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "provider refresh changed or unlinked identity")
	}
	if err != nil {
		return model.AuthIdentity{}, err
	}
	if linked.UserID != userID || linked.ID != expectedID {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "provider refresh changed identity owner")
	}
	linked.Email = identity.Email
	linked.Username = identity.Username
	linked.DisplayName = identity.DisplayName
	linked.Claims = cloneClaims(identity.Claims)
	linked.LastAuthenticatedAt = time.Now().UTC()
	return c.repo.SaveAuthIdentity(linked)
}
