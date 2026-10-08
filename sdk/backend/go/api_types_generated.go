// Код сгенерирован scripts/sdk/generate-types.py из канонических компонентов OpenAPI; НЕ РЕДАКТИРОВАТЬ.
package neverextensions

type CreateVersionRequest struct {
	ProfileId string `json:"profileId,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Version   string `json:"version"`
}

type DesktopExtensionRPCRequest0209 struct {
	Protocol string         `json:"protocol"`
	Id       string         `json:"id"`
	Method   string         `json:"method"`
	Params   map[string]any `json:"params,omitempty"`
}

type ExtensionCLIInvokeRequest0209 struct {
	Scope   string   `json:"scope"`
	ScopeId string   `json:"scopeId,omitempty"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

type ExtensionLifecycleWrite struct {
	Version string `json:"version,omitempty"`
	Channel string `json:"channel,omitempty"`
	Scope   string `json:"scope,omitempty"`
	ScopeId string `json:"scopeId,omitempty"`
}

type ExtensionPermissionGrantWrite struct {
	Version    string `json:"version,omitempty"`
	Scope      string `json:"scope,omitempty"`
	ScopeId    string `json:"scopeId,omitempty"`
	Permission string `json:"permission"`
	Reason     string `json:"reason,omitempty"`
}

type ExtensionRegistryChannelWrite struct {
	Version string `json:"version"`
}

type ExtensionRegistryInstallWrite struct {
	Scope   string `json:"scope,omitempty"`
	ScopeId string `json:"scopeId,omitempty"`
}

type ExtensionRegistryPublisherKeyWrite struct {
	PublicKeyBase64 string `json:"publicKeyBase64"`
	Active          bool   `json:"active,omitempty"`
}

type ExtensionRegistryPublisherWrite struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active,omitempty"`
}

type ExtensionRegistryYankWrite struct {
	Reason string `json:"reason"`
}

type ExtensionSecretWrite struct {
	Scope       string `json:"scope,omitempty"`
	ScopeId     string `json:"scopeId,omitempty"`
	ValueBase64 string `json:"valueBase64"`
}

type FreeFormObject map[string]any
