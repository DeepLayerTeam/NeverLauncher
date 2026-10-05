package model

import "time"

// ExtensionPermissionGrant is an explicit administrator approval for one
// permission requested by an extension manifest. Requested permissions alone
// never authorize a capability.
type ExtensionPermissionGrant struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	Permission  string    `json:"permission"`
	GrantedBy   string    `json:"grantedBy"`
	Reason      string    `json:"reason,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ExtensionPermissionDiff is the security decision material for install/update.
type ExtensionPermissionDiff struct {
	ExtensionID     string   `json:"extensionId"`
	FromVersion     string   `json:"fromVersion,omitempty"`
	ToVersion       string   `json:"toVersion"`
	Scope           string   `json:"scope"`
	ScopeID         string   `json:"scopeId,omitempty"`
	Requested       []string `json:"requested"`
	Granted         []string `json:"granted"`
	Effective       []string `json:"effective"`
	Missing         []string `json:"missing"`
	Added           []string `json:"added"`
	Removed         []string `json:"removed"`
	AddedNotGranted []string `json:"addedNotGranted"`
}

// ExtensionSecret stores ciphertext only. Plaintext is exposed exclusively by
// the authenticated capability broker and is never serialized by admin APIs.
type ExtensionSecret struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	Name        string    `json:"name"`
	Ciphertext  []byte    `json:"-"`
	Nonce       []byte    `json:"-"`
	KeyVersion  string    `json:"keyVersion"`
	UpdatedBy   string    `json:"updatedBy"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ExtensionSecretMetadata is safe for REST/CLI listing.
type ExtensionSecretMetadata struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId,omitempty"`
	Name        string    `json:"name"`
	KeyVersion  string    `json:"keyVersion"`
	UpdatedBy   string    `json:"updatedBy"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}
