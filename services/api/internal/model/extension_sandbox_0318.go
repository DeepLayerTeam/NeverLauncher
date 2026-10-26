package model

// ExtensionSandboxPolicy is covered by the Ed25519 signature of the canonical
// extension manifest and the .nlext package identity. "isolated" can only be
// launched by an OS sandbox implementation, never by manifest declaration.
// Trusted means unconfined execution, not an assurance label.
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
	MaxRequestsPerSecond int      `json:"maxRequestsPerSecond,omitempty"` // 0 -> host default 64; lower is stricter
	MaxOutputBytes       int64    `json:"maxOutputBytes,omitempty"`       // 0 -> host default 8MiB; includes logs and IPC replies
}
