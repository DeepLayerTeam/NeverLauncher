package extensioncontract

import (
	"errors"
	"fmt"
	"strings"
)

const (
	PackageFormatName         = "NeverLauncher Extension Package"
	PackageFormatVersion      = "1.0"
	ManifestSchemaVersion     = "2.0"
	HostProtocolVersion       = "1.0"
	ExtensionAPIVersion       = "1.0"
	LegacyExtensionAPIVersion = "3.7"
)

// Контракт является зафиксированный NeverExtensions 0.21 GA совместимость поверхность.
type Contract struct {
	PackageFormatName     string   `json:"packageFormatName"`
	PackageFormatVersion  string   `json:"packageFormatVersion"`
	ManifestSchemaVersion string   `json:"manifestSchemaVersion"`
	HostProtocolVersion   string   `json:"hostProtocolVersion"`
	ExtensionAPIVersion   string   `json:"extensionApiVersion"`
	LegacyAPIAliases      []string `json:"legacyApiAliases,omitempty"`
}

func Frozen() Contract {
	return Contract{
		PackageFormatName: PackageFormatName, PackageFormatVersion: PackageFormatVersion,
		ManifestSchemaVersion: ManifestSchemaVersion, HostProtocolVersion: HostProtocolVersion,
		ExtensionAPIVersion: ExtensionAPIVersion, LegacyAPIAliases: []string{LegacyExtensionAPIVersion},
	}
}

// CanonicalAPIVersion принимает 0.20 API маркер как совместимость псевдоним, но
// всегда сопоставляет это к зафиксированный Расширение API v1 поверхность. Этот сохраняет подписанный
// 0.20 пакеты runnable без изменяющий их манифесты.
func CanonicalAPIVersion(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "1.0", "1.0.0", "v1", "v1.0", "v1.0.0":
		return ExtensionAPIVersion, nil
	case "3.7", "3.7.0":
		return ExtensionAPIVersion, nil
	case "":
		return "", errors.New("API расширений является обязательный")
	default:
		return "", fmt.Errorf("неподдерживаемый API расширений %q; ожидаемый %s (устаревший %s является принят только для 0.20 совместимость)", raw, ExtensionAPIVersion, LegacyExtensionAPIVersion)
	}
}

func IsLegacyAPIVersion(raw string) bool {
	raw = strings.TrimSpace(raw)
	return raw == LegacyExtensionAPIVersion || raw == LegacyExtensionAPIVersion+".0"
}

// RequireGAAPIVersion является используется для вновь published/created 0.21 артефакты. 
// устаревший псевдоним является намеренно отклонён так реестр converges к API v1.
func RequireGAAPIVersion(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw != ExtensionAPIVersion {
		return fmt.Errorf("новый NeverExtensions публикация требовать Расширение API %s; получил %q", ExtensionAPIVersion, raw)
	}
	return nil
}

func SupportsHostHello(manifestAPI, helloAPI string) bool {
	canonical, err := CanonicalAPIVersion(manifestAPI)
	if err != nil || canonical != ExtensionAPIVersion {
		return false
	}
	helloAPI = strings.TrimSpace(helloAPI)
	if IsLegacyAPIVersion(manifestAPI) && helloAPI == "" {
		// 0.20 SDK сделал не отправлять extensionApiVersion в hello полезная нагрузка.
		return true
	}
	if IsLegacyAPIVersion(manifestAPI) && (helloAPI == LegacyExtensionAPIVersion || helloAPI == LegacyExtensionAPIVersion+".0") {
		return true
	}
	got, err := CanonicalAPIVersion(helloAPI)
	return err == nil && got == ExtensionAPIVersion
}
