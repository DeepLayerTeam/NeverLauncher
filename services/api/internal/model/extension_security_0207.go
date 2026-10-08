package model

import "time"

// ExtensionPermissionGrant является явный администратор approval для один
// разрешение запрошенный через расширение манифест. Запрошенный разрешения alone
// никогда авторизовать возможность.
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

// ExtensionPermissionDiff является безопасность решение материал для install/update.
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

// ExtensionSecret хранит ciphertext только. Открытый текст является предоставлять exclusively через
// аутентифицировать возможность broker и является никогда сериализованный через администратор APIs.
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

// ExtensionSecretMetadata является безопасный для REST/CLI список.
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
