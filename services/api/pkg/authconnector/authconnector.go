package authconnector

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Capability declares a concrete connector feature. Capabilities are executable
// promises: conformance validation rejects a connector that advertises a feature
// without implementing the corresponding interface.
type Capability string

const (
	CapabilityPasswordAuth     Capability = "password-auth"
	CapabilityBrowserAuth      Capability = "browser-auth"
	CapabilityTokenRefresh     Capability = "token-refresh"
	CapabilityTokenRevoke      Capability = "token-revoke"
	CapabilityUserLookup       Capability = "user-lookup"
	CapabilityProfile          Capability = "profile"
	CapabilityTextures         Capability = "textures"
	CapabilityGroups           Capability = "groups"
	CapabilityRoles            Capability = "roles"
	CapabilityEmail            Capability = "email"
	CapabilityMinecraftProfile Capability = "minecraft-profile"
)

type Metadata struct {
	ID           string       `json:"id"`
	DisplayName  string       `json:"displayName"`
	Version      string       `json:"version"`
	Capabilities []Capability `json:"capabilities"`
}

type Identity struct {
	Subject     string         `json:"subject"`
	Email       string         `json:"email,omitempty"`
	Username    string         `json:"username,omitempty"`
	DisplayName string         `json:"displayName,omitempty"`
	Groups      []string       `json:"groups,omitempty"`
	Roles       []string       `json:"roles,omitempty"`
	Claims      map[string]any `json:"claims,omitempty"`
}

type PasswordRequest struct {
	Identifier string
	Secret     string
}

type Authentication struct {
	Identity      Identity
	AuthMethods   []string
	ProviderToken string
	ExpiresAt     time.Time
}

type ResolveRequest struct {
	Subject string
}

type BrowserAuthRequest struct {
	RedirectURI   string
	State         string
	Nonce         string
	PKCEChallenge string
}

type BrowserAuthStart struct {
	AuthorizationURL string
	State            string
	ExpiresAt        time.Time
}

type BrowserAuthCallback struct {
	RedirectURI  string
	Code         string
	State        string
	Nonce        string
	PKCEVerifier string
}

type Profile struct {
	Subject       string         `json:"subject"`
	DisplayName   string         `json:"displayName,omitempty"`
	AvatarURL     string         `json:"avatarUrl,omitempty"`
	MinecraftUUID string         `json:"minecraftUuid,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

type LinkRequest struct {
	Subject string
}

type RevokeRequest struct {
	Subject       string
	ProviderToken string
}

// Connector is the mandatory base interface for every authentication connector.
type Connector interface {
	Metadata() Metadata
	Health(context.Context) error
}

type PasswordAuthenticator interface {
	Connector
	AuthenticatePassword(context.Context, PasswordRequest) (Authentication, error)
}

type IdentityResolver interface {
	Connector
	ResolveIdentity(context.Context, ResolveRequest) (Identity, error)
}

type BrowserAuthenticator interface {
	Connector
	BeginBrowserAuth(context.Context, BrowserAuthRequest) (BrowserAuthStart, error)
	CompleteBrowserAuth(context.Context, BrowserAuthCallback) (Authentication, error)
}

type ProfileResolver interface {
	Connector
	ResolveProfile(context.Context, ResolveRequest) (Profile, error)
}

type IdentityLinker interface {
	Connector
	LinkIdentity(context.Context, LinkRequest) (Identity, error)
}

type TokenRefresher interface {
	Connector
	Refresh(context.Context, string) (Authentication, error)
}

type Revoker interface {
	Connector
	Revoke(context.Context, RevokeRequest) error
}

type ErrorCode string

const (
	ErrInvalidCredentials ErrorCode = "invalid_credentials"
	ErrIdentityDisabled   ErrorCode = "identity_disabled"
	ErrUnsupported        ErrorCode = "unsupported"
	ErrUnavailable        ErrorCode = "unavailable"
	ErrMisconfigured      ErrorCode = "misconfigured"
	ErrConflict           ErrorCode = "conflict"
	ErrIdentityNotFound   ErrorCode = "identity_not_found"
)

type Error struct {
	Code      ErrorCode
	Message   string
	Temporary bool
	Cause     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error { return e.Cause }

func NewError(code ErrorCode, message string) error {
	return &Error{Code: code, Message: message}
}

func WrapError(code ErrorCode, message string, cause error) error {
	return &Error{Code: code, Message: message, Cause: cause}
}

func CodeOf(err error) ErrorCode {
	var connectorErr *Error
	if errors.As(err, &connectorErr) {
		return connectorErr.Code
	}
	return ""
}

func HasCapability(meta Metadata, capability Capability) bool {
	for _, item := range meta.Capabilities {
		if item == capability {
			return true
		}
	}
	return false
}

func ValidateMetadata(meta Metadata) error {
	meta.ID = strings.TrimSpace(meta.ID)
	if meta.ID == "" {
		return fmt.Errorf("connector id is required")
	}
	if strings.ToLower(meta.ID) != meta.ID {
		return fmt.Errorf("connector id %q must be lowercase", meta.ID)
	}
	for _, r := range meta.ID {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("connector id %q contains unsupported character %q", meta.ID, r)
		}
	}
	if strings.TrimSpace(meta.DisplayName) == "" {
		return fmt.Errorf("connector %q displayName is required", meta.ID)
	}
	if strings.TrimSpace(meta.Version) == "" {
		return fmt.Errorf("connector %q version is required", meta.ID)
	}
	seen := make(map[Capability]struct{}, len(meta.Capabilities))
	for _, capability := range meta.Capabilities {
		if strings.TrimSpace(string(capability)) == "" {
			return fmt.Errorf("connector %q contains empty capability", meta.ID)
		}
		if _, ok := seen[capability]; ok {
			return fmt.Errorf("connector %q contains duplicate capability %q", meta.ID, capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func NormalizedMetadata(meta Metadata) Metadata {
	out := meta
	out.ID = strings.TrimSpace(strings.ToLower(out.ID))
	out.DisplayName = strings.TrimSpace(out.DisplayName)
	out.Version = strings.TrimSpace(out.Version)
	out.Capabilities = append([]Capability(nil), out.Capabilities...)
	sort.Slice(out.Capabilities, func(i, j int) bool { return out.Capabilities[i] < out.Capabilities[j] })
	return out
}
