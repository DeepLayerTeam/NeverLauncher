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

// Contract is the frozen NeverExtensions 0.21 GA compatibility surface.
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

// CanonicalAPIVersion accepts the 0.20 API marker as a compatibility alias, but
// always maps it to the frozen Extension API v1 surface. This keeps signed
// 0.20 packages runnable without mutating their manifests.
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

// RequireGAAPIVersion is used for newly published/created 0.21 artifacts. The
// legacy alias is intentionally rejected so the registry converges to API v1.
func RequireGAAPIVersion(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw != ExtensionAPIVersion {
		return fmt.Errorf("new NeverExtensions publications require Extension API %s; got %q", ExtensionAPIVersion, raw)
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
		// 0.20 SDKs did not send extensionApiVersion in the hello payload.
		return true
	}
	if IsLegacyAPIVersion(manifestAPI) && (helloAPI == LegacyExtensionAPIVersion || helloAPI == LegacyExtensionAPIVersion+".0") {
		return true
	}
	got, err := CanonicalAPIVersion(helloAPI)
	return err == nil && got == ExtensionAPIVersion
}
