//go:build !linux

package extensionhost

import (
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/macossandbox"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/windowssandbox"
	"runtime"
)

func probePlatformIsolation0311(d *IsolationDiagnostics0311) {
	switch runtime.GOOS {
	case "windows":
		if err := windowssandbox.Available(); err != nil {
			d.AppContainer = Capability0311{"blocked", "appcontainer-API-unavailable"}
			d.JobObjects = Capability0311{"blocked", "job-object-API-unavailable"}
		} else {
			d.AppContainer = Capability0311{"detected", "AppContainer-capable-not-yet-enforced"}
			d.JobObjects = Capability0311{"detected", "Job-Objects-capable-not-yet-enforced"}
		}
	case "darwin":
		if err := macossandbox.Available(); err != nil {
			d.AppSandbox = Capability0311{"blocked", "signed-sandbox-helper-missing-invalid-or-overprivileged"}
		} else {
			d.AppSandbox = Capability0311{"detected", "signed-helper-verified-enforcement-requires-per-process-launch"}
		}
	}
	if runtime.GOOS == "windows" {
		d.ReasonCodes = append(d.ReasonCodes, "per-extension-AppContainer-status-required-for-enforcement")
	} else {
		d.ReasonCodes = append(d.ReasonCodes, "network-and-filesystem-not-confined", "process-tree-not-confined")
	}
}
