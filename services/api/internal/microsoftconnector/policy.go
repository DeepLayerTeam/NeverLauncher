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
			return fmt.Errorf("Microsoft обнаружение издатель должен быть tenant-независимый template %q", template)
		}
	case "consumers":
		personal := p.authorityBase + "/" + personalMicrosoftTenantID + "/v2.0"
		if !strings.EqualFold(discoveredIssuer, template) && !strings.EqualFold(discoveredIssuer, personal) {
			return fmt.Errorf("Microsoft consumers обнаружение издатель является недопустимый")
		}
	case "tenant":
		expected := p.authorityBase + "/" + p.tenant + "/v2.0"
		if !strings.EqualFold(discoveredIssuer, expected) {
			return fmt.Errorf("Microsoft единый-tenant обнаружение издатель несоответствие")
		}
	default:
		return fmt.Errorf("Microsoft tenant режим является недопустимый")
	}
	return nil
}

func (p microsoftIssuerPolicy) ValidateTokenIssuer(discoveredIssuer string, claims map[string]any, signingKeyIssuer string) error {
	tid := strings.ToLower(strings.TrimSpace(stringClaim(claims, "tid")))
	if !validGUID(tid) {
		return fmt.Errorf("Microsoft ID токен tid является отсутствующий или недопустимый")
	}
	issuer := strings.TrimSuffix(strings.TrimSpace(stringClaim(claims, "iss")), "/")
	expected := p.authorityBase + "/" + tid + "/v2.0"
	if !strings.EqualFold(issuer, expected) {
		return fmt.Errorf("Microsoft ID токен издатель делает не соответствовать tid")
	}
	switch p.tenantMode {
	case "organizations":
		if tid == personalMicrosoftTenantID {
			return fmt.Errorf("personal Microsoft учётная запись является не разрешён через organizations authority")
		}
	case "consumers":
		if tid != personalMicrosoftTenantID {
			return fmt.Errorf("work/school tenant является не разрешён через consumers authority")
		}
	case "tenant":
		if tid != p.tenant {
			return fmt.Errorf("Microsoft ID токен tenant несоответствие")
		}
	}
	if len(p.allowedTenantIDs) > 0 {
		if _, ok := p.allowedTenantIDs[tid]; !ok {
			return fmt.Errorf("Microsoft tenant является не в allowedTenantIds")
		}
	}
	instantiatedDiscovery := replaceTenantTemplate(strings.TrimSuffix(strings.TrimSpace(discoveredIssuer), "/"), tid)
	if !strings.EqualFold(instantiatedDiscovery, issuer) {
		return fmt.Errorf("Microsoft обнаружение издатель делает не привязывать к токен tenant")
	}
	if strings.TrimSpace(signingKeyIssuer) == "" {
		return fmt.Errorf("Microsoft ключ подписи является отсутствующий издатель метаданные")
	}
	instantiatedKeyIssuer := replaceTenantTemplate(strings.TrimSuffix(strings.TrimSpace(signingKeyIssuer), "/"), tid)
	if !strings.EqualFold(instantiatedKeyIssuer, issuer) {
		return fmt.Errorf("Microsoft ключ подписи издатель делает не соответствовать токен издатель")
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
