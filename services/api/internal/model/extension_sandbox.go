package model

// ExtensionSandboxPolicy покрывается подписью Ed25519 канонического манифеста
// расширения и идентичностью пакета .nlext. isolated может запускаться только
// реализацией песочницы ОС, а не объявлением в манифесте. trusted означает запуск
// без ограничений, а не метку подтверждённой надёжности.
type ExtensionSandboxPolicy struct {
	Version              string   `json:"version"`
	Mode                 string   `json:"mode"`                      // trusted, isolated
	FilesystemRead       []string `json:"filesystemRead,omitempty"`  // grants: package, shared:<name>
	FilesystemWrite      []string `json:"filesystemWrite,omitempty"` // grants: scratch, shared:<name>
	NetworkOutbound      []string `json:"networkOutbound,omitempty"` // host:port destinations
	Secrets              []string `json:"secrets,omitempty"`         // scoped broker secret names
	MaxProcesses         int      `json:"maxProcesses,omitempty"`
	MaxMemoryBytes       int64    `json:"maxMemoryBytes,omitempty"`
	MaxCPUPercent        int      `json:"maxCpuPercent,omitempty"`
	TimeoutSeconds       int      `json:"timeoutSeconds,omitempty"`
	MaxRequestsPerSecond int      `json:"maxRequestsPerSecond,omitempty"` // 0 — значение хоста по умолчанию 64; меньшее значение ужесточает ограничение
	MaxOutputBytes       int64    `json:"maxOutputBytes,omitempty"`       // 0 — значение хоста по умолчанию 8 МиБ; включает журналы и ответы IPC
}
