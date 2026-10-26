//go:build !linux

package extensionhost

import "runtime"

func probePlatformIsolation0311(d *IsolationDiagnostics0311) {
	switch runtime.GOOS {
	case "windows":
		d.AppContainer = Capability0311{"unknown", "appcontainer-token-not-created"}
		d.JobObjects = Capability0311{"unknown", "job-confinement-not-applied"}
	case "darwin":
		d.AppSandbox = Capability0311{"unknown", "signed-sandbox-helper-not-provisioned"}
	}
	d.ReasonCodes = append(d.ReasonCodes, "network-and-filesystem-not-confined", "process-tree-not-confined")
}
