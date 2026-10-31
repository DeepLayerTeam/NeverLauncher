package authconnector

import (
	"fmt"
	"reflect"
	"strings"
)

// ValidateConnector is the single registration gate for the SDK's operational
// capability claims. Informational claims (email, groups, roles, textures,
// Minecraft profile) describe available identity data rather than methods.
func ValidateConnector(connector Connector) error {
	if connector == nil || (reflect.ValueOf(connector).Kind() == reflect.Ptr && reflect.ValueOf(connector).IsNil()) {
		return fmt.Errorf("auth connector is nil")
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
			return fmt.Errorf("auth connector %q advertises %q without implementation", meta.ID, req.capability)
		}
	}
	// A plugin is not permitted to expose credential-bearing methods that are
	// missing from metadata: the caller must silently skip enforcement.
	for _, req := range required {
		if req.implemented && !HasCapability(meta, req.capability) {
			return fmt.Errorf("auth connector %q implements %q without declaring it", meta.ID, req.capability)
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

// ValidateAuthentication enforces the same identity invariant for password,
// browser and refresh results, before linking or writing provider credentials.
func ValidateAuthentication(auth Authentication) error {
	if err := ValidateIdentity(auth.Identity); err != nil {
		return err
	}
	if len(auth.ProviderToken) > 16384 {
		return NewError(ErrMisconfigured, "provider token exceeds size limit")
	}
	if len(auth.AuthMethods) > 32 {
		return NewError(ErrMisconfigured, "too many authentication methods")
	}
	for _, method := range auth.AuthMethods {
		if strings.TrimSpace(method) == "" || len(method) > 64 {
			return NewError(ErrMisconfigured, "invalid authentication method")
		}
	}
	return nil
}

func ValidateIdentity(identity Identity) error {
	if strings.TrimSpace(identity.Subject) == "" || len(identity.Subject) > 512 || len(identity.Issuer) > 2048 ||
		len(identity.Email) > 512 || len(identity.Username) > 512 || len(identity.DisplayName) > 1024 {
		return NewError(ErrMisconfigured, "provider returned invalid identity fields")
	}
	if len(identity.Groups) > 256 || len(identity.Roles) > 256 {
		return NewError(ErrMisconfigured, "provider returned oversized identity memberships")
	}
	return nil
}

func ValidateProfile(profile Profile, expectedSubject string) error {
	if strings.TrimSpace(profile.Subject) == "" || len(profile.Subject) > 512 ||
		(expectedSubject != "" && profile.Subject != expectedSubject) {
		return NewError(ErrMisconfigured, "provider profile subject mismatch")
	}
	return nil
}
