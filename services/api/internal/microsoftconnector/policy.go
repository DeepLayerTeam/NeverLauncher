package microsoftconnector

import (
	"fmt"
	"strings"
)

type microsoftIssuerPolicy struct {
	authorityBase    string
	tenant           string
	tenantMode       string
	allowedTenantIDs map[string]struct{}
}

func (p microsoftIssuerPolicy) ValidateDiscoveryIssuer(_ string, discoveredIssuer string) error {
	discoveredIssuer = strings.TrimSuffix(strings.TrimSpace(discoveredIssuer), "/")
	template := p.authorityBase + "/{tenantid}/v2.0"
	switch p.tenantMode {
	case "common", "organizations":
		if !strings.EqualFold(discoveredIssuer, template) {
			return fmt.Errorf("Издатель в метаданных Microsoft: требуется шаблон, независимый от арендатора, %q", template)
		}
	case "consumers":
		personal := p.authorityBase + "/" + personalMicrosoftTenantID + "/v2.0"
		if !strings.EqualFold(discoveredIssuer, template) && !strings.EqualFold(discoveredIssuer, personal) {
			return fmt.Errorf("Некорректное значение: «издатель метаданных Microsoft для пользовательских учётных записей»")
		}
	case "tenant":
		expected := p.authorityBase + "/" + p.tenant + "/v2.0"
		if !strings.EqualFold(discoveredIssuer, expected) {
			return fmt.Errorf("Несовпадение: «издатель метаданных Microsoft для одного арендатора»")
		}
	default:
		return fmt.Errorf("Некорректное значение: «режим арендатора Microsoft»")
	}
	return nil
}

func (p microsoftIssuerPolicy) ValidateTokenIssuer(discoveredIssuer string, claims map[string]any, signingKeyIssuer string) error {
	tid := strings.ToLower(strings.TrimSpace(stringClaim(claims, "tid")))
	if !validGUID(tid) {
		return fmt.Errorf("Некорректное значение: «поле tid токена идентификации Microsoft отсутствует или»")
	}
	issuer := strings.TrimSuffix(strings.TrimSpace(stringClaim(claims, "iss")), "/")
	expected := p.authorityBase + "/" + tid + "/v2.0"
	if !strings.EqualFold(issuer, expected) {
		return fmt.Errorf("«издатель токена идентификации Microsoft» не совпадает с «tid»")
	}
	switch p.tenantMode {
	case "organizations":
		if tid == personalMicrosoftTenantID {
			return fmt.Errorf("Центр авторизации организации не разрешает личные учётные записи Microsoft")
		}
	case "consumers":
		if tid != personalMicrosoftTenantID {
			return fmt.Errorf("Тенант рабочей или учебной организации не допускается центром учётных записей потребителей")
		}
	case "tenant":
		if tid != p.tenant {
			return fmt.Errorf("Несовпадение: «арендатор токена идентификации Microsoft»")
		}
	}
	if len(p.allowedTenantIDs) > 0 {
		if _, ok := p.allowedTenantIDs[tid]; !ok {
			return fmt.Errorf("Арендатор Microsoft отсутствует в allowedTenantIds")
		}
	}
	instantiatedDiscovery := replaceTenantTemplate(strings.TrimSuffix(strings.TrimSpace(discoveredIssuer), "/"), tid)
	if !strings.EqualFold(instantiatedDiscovery, issuer) {
		return fmt.Errorf("Издатель, найденный в метаданных Microsoft, не соответствует арендатору токена")
	}
	if strings.TrimSpace(signingKeyIssuer) == "" {
		return fmt.Errorf("У ключа подписи Microsoft отсутствуют метаданные издателя")
	}
	instantiatedKeyIssuer := replaceTenantTemplate(strings.TrimSuffix(strings.TrimSpace(signingKeyIssuer), "/"), tid)
	if !strings.EqualFold(instantiatedKeyIssuer, issuer) {
		return fmt.Errorf("«издатель ключа подписи Microsoft» не совпадает с «издатель токена»")
	}
	return nil
}

func replaceTenantTemplate(v, tid string) string {
	v = strings.ReplaceAll(v, "{tenantid}", tid)
	v = strings.ReplaceAll(v, "{tenantId}", tid)
	v = strings.ReplaceAll(v, "{tenantID}", tid)
	return v
}

func stringClaim(claims map[string]any, key string) string {
	v, _ := claims[key].(string)
	return strings.TrimSpace(v)
}
