package federation

import (
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

// RefreshLinkedIdentity обновляет утверждения ранее привязанной идентичности. Это
// НЕ привязка аккаунта, поэтому политика запрета НОВЫХ привязок не должна нарушать
// обычное обновление существующих учётных данных. expectedID закрепляет операцию за
// проверенным субъектом.
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
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "Основная учётная запись пользователя отключена")
	}
	if strings.TrimSpace(expectedID) == "" {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "Необходим идентификатор ожидаемой привязанной учётной записи")
	}
	if err := authconnector.ValidateAuthentication(authentication); err != nil {
		return model.AuthIdentity{}, err
	}
	identity := authentication.Identity
	identity.Subject = strings.TrimSpace(identity.Subject)
	issuer, err := model.CanonicalAuthIssuer(providerID, identity.Issuer)
	if err != nil {
		return model.AuthIdentity{}, authconnector.WrapError(authconnector.ErrMisconfigured, "неверный аутентифицированный издатель токена", err)
	}
	linked, err := c.repo.GetAuthIdentityByIssuer(providerID, issuer, identity.Subject)
	if errors.Is(err, repository.ErrNotFound) {
		return model.AuthIdentity{}, authconnector.NewError(authconnector.ErrConflict, "Обновление провайдера изменило или отвязало учётную запись")
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
