package extensioncontract

import (
	"errors"
	"fmt"
	"strings"
)

const (
	PackageFormatName         = "Launcher Extension Package"
	PackageFormatVersion      = "1.0"
	ManifestSchemaVersion     = "2.0"
	HostProtocolVersion       = "1.0"
	ExtensionAPIVersion       = "1.0"
	LegacyExtensionAPIVersion = "3.7"
)

// Контракт — зафиксированная поверхность совместимости Extensions 0.21 GA.
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

// CanonicalAPIVersion принимает маркер API 0.20 как совместимый псевдоним,
// но всегда сопоставляет его с фиксированным Extension API v1. Это
// позволяет запускать подписанные пакеты 0.20 без изменения манифестов.
func CanonicalAPIVersion(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "1.0", "1.0.0", "v1", "v1.0", "v1.0.0":
		return ExtensionAPIVersion, nil
	case "3.7", "3.7.0":
		return ExtensionAPIVersion, nil
	case "":
		return "", errors.New("extension api is required")
	default:
		return "", fmt.Errorf("unsupported extension api %q; expected %s (legacy %s is accepted only for 0.20 compatibility)", raw, ExtensionAPIVersion, LegacyExtensionAPIVersion)
	}
}

func IsLegacyAPIVersion(raw string) bool {
	raw = strings.TrimSpace(raw)
	return raw == LegacyExtensionAPIVersion || raw == LegacyExtensionAPIVersion+".0"
}

// RequireGAAPIVersion применяется к новым артефактам 0.21. Старый
// псевдоним намеренно отклоняется, чтобы реестр перешёл на API v1.
func RequireGAAPIVersion(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw != ExtensionAPIVersion {
		return fmt.Errorf("new Extensions publications require Extension API %s; got %q", ExtensionAPIVersion, raw)
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
		// SDK 0.20 не передавали extensionApiVersion в hello.
		return true
	}
	if IsLegacyAPIVersion(manifestAPI) && (helloAPI == LegacyExtensionAPIVersion || helloAPI == LegacyExtensionAPIVersion+".0") {
		return true
	}
	got, err := CanonicalAPIVersion(helloAPI)
	return err == nil && got == ExtensionAPIVersion
}
