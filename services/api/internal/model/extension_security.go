package model

import "time"

// ExtensionPermissionGrant — явное одобрение
// администратором одного разрешения из манифеста.
// Сами запросы прав не разрешают возможность.
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

// ExtensionPermissionDiff — данные для решения о безопасности установки или обновления.
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

// ExtensionSecret хранит только шифротекст. Открытое значение выдаётся исключительно
// аутентифицированным брокером возможностей и никогда не сериализуется административными API.
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

// ExtensionSecretMetadata безопасны для вывода списков REST/CLI.
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
