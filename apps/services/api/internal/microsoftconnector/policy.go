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
			return fmt.Errorf("Microsoft discovery issuer: требуется «tenant-independent template» %q", template)
		}
	case "consumers":
		personal := p.authorityBase + "/" + personalMicrosoftTenantID + "/v2.0"
		if !strings.EqualFold(discoveredIssuer, template) && !strings.EqualFold(discoveredIssuer, personal) {
			return fmt.Errorf("Некорректное значение: «Microsoft consumers discovery issuer»")
		}
	case "tenant":
		expected := p.authorityBase + "/" + p.tenant + "/v2.0"
		if !strings.EqualFold(discoveredIssuer, expected) {
			return fmt.Errorf("Несовпадение: «Microsoft single-tenant discovery issuer»")
		}
	default:
		return fmt.Errorf("Некорректное значение: «Microsoft tenant mode»")
	}
	return nil
}

func (p microsoftIssuerPolicy) ValidateTokenIssuer(discoveredIssuer string, claims map[string]any, signingKeyIssuer string) error {
	tid := strings.ToLower(strings.TrimSpace(stringClaim(claims, "tid")))
	if !validGUID(tid) {
		return fmt.Errorf("Некорректное значение: «Microsoft ID token tid is missing or»")
	}
	issuer := strings.TrimSuffix(strings.TrimSpace(stringClaim(claims, "iss")), "/")
	expected := p.authorityBase + "/" + tid + "/v2.0"
	if !strings.EqualFold(issuer, expected) {
		return fmt.Errorf("«Microsoft ID token issuer» не совпадает с «tid»")
	}
	switch p.tenantMode {
	case "organizations":
		if tid == personalMicrosoftTenantID {
			return fmt.Errorf("Центр авторизации организаций не разрешает личные учётные записи Microsoft")
		}
	case "consumers":
		if tid != personalMicrosoftTenantID {
			return fmt.Errorf("Центр авторизации личных учётных записей не разрешает рабочие или учебные организации")
		}
	case "tenant":
		if tid != p.tenant {
			return fmt.Errorf("Несовпадение: «Microsoft ID token tenant»")
		}
	}
	if len(p.allowedTenantIDs) > 0 {
		if _, ok := p.allowedTenantIDs[tid]; !ok {
			return fmt.Errorf("Организация Microsoft отсутствует в allowedTenantIds")
		}
	}
	instantiatedDiscovery := replaceTenantTemplate(strings.TrimSuffix(strings.TrimSpace(discoveredIssuer), "/"), tid)
	if !strings.EqualFold(instantiatedDiscovery, issuer) {
		return fmt.Errorf("Издатель Microsoft Discovery не соответствует организации в токене")
	}
	if strings.TrimSpace(signingKeyIssuer) == "" {
		return fmt.Errorf("У ключа подписи Microsoft отсутствуют метаданные издателя")
	}
	instantiatedKeyIssuer := replaceTenantTemplate(strings.TrimSuffix(strings.TrimSpace(signingKeyIssuer), "/"), tid)
	if !strings.EqualFold(instantiatedKeyIssuer, issuer) {
		return fmt.Errorf("«Microsoft signing key issuer» не совпадает с «token issuer»")
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
