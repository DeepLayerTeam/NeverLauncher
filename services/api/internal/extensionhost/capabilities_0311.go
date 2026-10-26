package extensionhost

import (
	"runtime"
)

type Capability0311 struct {
	State      string `json:"state"` // detected, blocked, unknown, unsupported
	ReasonCode string `json:"reasonCode"`
}

type IsolationDiagnostics0311 struct {
	Platform              string         `json:"platform"`
	Architecture          string         `json:"architecture"`
	Identity              Capability0311 `json:"identity"`
	Namespaces            Capability0311 `json:"namespaces"`
	NoNewPrivileges       Capability0311 `json:"noNewPrivileges"`
	Seccomp               Capability0311 `json:"seccomp"`
	CgroupsV2             Capability0311 `json:"cgroupsV2"`
	Landlock              Capability0311 `json:"landlock"`
	AppContainer          Capability0311 `json:"appContainer"`
	JobObjects            Capability0311 `json:"jobObjects"`
	AppSandbox            Capability0311 `json:"appSandbox"`
	Enforced              bool           `json:"enforced"`
	IsolationStatus       string         `json:"isolationStatus"`
	ReasonCodes           []string       `json:"reasonCodes"`
	EffectiveRestrictions []string       `json:"effectiveRestrictions"`
}

// Host isolation is not yet implemented. Never infer sandbox enforcement from
// kernel feature detection or a package signature; this report is computed
// from read-only checks on the real host at request time.
func DiagnoseIsolation0311() IsolationDiagnostics0311 {
	u := Capability0311{"unsupported", "not-applicable"}
	d := IsolationDiagnostics0311{
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		Identity: u, Namespaces: u, NoNewPrivileges: u, Seccomp: u, CgroupsV2: u,
		Landlock: u, AppContainer: u, JobObjects: u, AppSandbox: u,
		Enforced: false, IsolationStatus: "unsupported",
		ReasonCodes:           []string{"extension-os-sandbox-not-enforced"},
		EffectiveRestrictions: []string{"host-rpc-permission-checks", "sanitized-environment", "protocol-bounds"},
	}
	probePlatformIsolation0311(&d)
	return d
}

func (s *Supervisor) IsolationDiagnostics0311() IsolationDiagnostics0311 {
	return DiagnoseIsolation0311()
}
