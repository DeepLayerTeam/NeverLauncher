package authconnector

import (
	"fmt"
	"reflect"
	"strings"
)

// ValidateConnector — единственная точка допуска регистрации рабочего SDK-
// заявления о возможностях. Информационные сведения (email, группы, роли, текстуры,
// профиль Minecraft) описывают доступные идентификационные данные, а не методы.
func ValidateConnector(connector Connector) error {
	if connector == nil || (reflect.ValueOf(connector).Kind() == reflect.Ptr && reflect.ValueOf(connector).IsNil()) {
		return fmt.Errorf("Коннектор авторизации не задан")
	}
	meta := connector.Metadata()
	if err := ValidateMetadata(meta); err != nil {
		return err
	}
	required := []struct {
		capability  Capability
		implemented bool
	}{
		{CapabilityPasswordAuth, implementsPassword(connector)},
		{CapabilityBrowserAuth, implementsBrowser(connector)},
		{CapabilityTokenRefresh, implementsRefresh(connector)},
		{CapabilityTokenRevoke, implementsRevoke(connector)},
		{CapabilityUserLookup, implementsLookup(connector)},
		{CapabilityProfile, implementsProfile(connector)},
	}
	for _, req := range required {
		if HasCapability(meta, req.capability) && !req.implemented {
			return fmt.Errorf("Коннектор авторизации %q объявляет %q, но не реализует его", meta.ID, req.capability)
		}
	}
	// Плагину запрещено предоставлять методы с учётными данными, которые
	// отсутствуют в метаданных: вызывающий не должен молча пропускать проверку.
	for _, req := range required {
		if req.implemented && !HasCapability(meta, req.capability) {
			return fmt.Errorf("Коннектор авторизации %q реализует %q, но не объявляет его", meta.ID, req.capability)
		}
	}
	return nil
}

func implementsPassword(c Connector) bool { _, ok := c.(PasswordAuthenticator); return ok }
func implementsBrowser(c Connector) bool  { _, ok := c.(BrowserAuthenticator); return ok }
func implementsRefresh(c Connector) bool  { _, ok := c.(TokenRefresher); return ok }
func implementsRevoke(c Connector) bool   { _, ok := c.(Revoker); return ok }
func implementsLookup(c Connector) bool   { _, ok := c.(IdentityResolver); return ok }
func implementsProfile(c Connector) bool  { _, ok := c.(ProfileResolver); return ok }

// ValidateAuthentication применяет одинаковый инвариант идентичности для пароля,
// браузерных и refresh-результатов до привязки или сохранения учётных данных провайдера.
func ValidateAuthentication(auth Authentication) error {
	if err := ValidateIdentity(auth.Identity); err != nil {
		return err
	}
	if len(auth.ProviderToken) > 16384 {
		return NewError(ErrMisconfigured, "Токен провайдера превышает допустимый размер")
	}
	if len(auth.AuthMethods) > 32 {
		return NewError(ErrMisconfigured, "Слишком много методов аутентификации")
	}
	for _, method := range auth.AuthMethods {
		if strings.TrimSpace(method) == "" || len(method) > 64 {
			return NewError(ErrMisconfigured, "Недопустимый метод аутентификации")
		}
	}
	return nil
}

func ValidateIdentity(identity Identity) error {
	if strings.TrimSpace(identity.Subject) == "" || len(identity.Subject) > 512 || len(identity.Issuer) > 2048 ||
		len(identity.Email) > 512 || len(identity.Username) > 512 || len(identity.DisplayName) > 1024 {
		return NewError(ErrMisconfigured, "Провайдер вернул некорректные поля учётной записи")
	}
	if len(identity.Groups) > 256 || len(identity.Roles) > 256 {
		return NewError(ErrMisconfigured, "Провайдер вернул слишком большой список принадлежности учётной записи к группам и ролям")
	}
	return nil
}

func ValidateProfile(profile Profile, expectedSubject string) error {
	if strings.TrimSpace(profile.Subject) == "" || len(profile.Subject) > 512 ||
		(expectedSubject != "" && profile.Subject != expectedSubject) {
		return NewError(ErrMisconfigured, "Идентификатор субъекта профиля не совпадает с ожидаемым")
	}
	return nil
}
