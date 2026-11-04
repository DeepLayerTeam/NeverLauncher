package trustbaseline

import (
	"os"
	"runtime"
)

type Capability struct {
	State      string `json:"state"` // present, absent, unknown, unsupported
	ReasonCode string `json:"reasonCode"`
}

type DeviceDiagnostics struct {
	Platform                 string     `json:"platform"`
	Architecture             string     `json:"architecture"`
	TPMDevice                Capability `json:"tpmDevice"`
	RemoteProvenanceVerifier Capability `json:"remoteProvenanceVerifier"`
	MeasuredBootVerifier     Capability `json:"measuredBootVerifier"`
	StandardProfile          string     `json:"standardProfile"`
	StrictProfile            string     `json:"strictProfile"`
	Notes                    []string   `json:"notes"`
}

// DiagnoseHost makes only unprivileged, non-mutating observations of this
// machine. Backend host TPM presence is NOT evidence about a remote client.
// probeTPMNode0311 does not open TPM key material or contact the chip.
// A file or a symlink masquerading as /dev/tpm* is not a TPM capability.
func probeTPMNode0311(path string) (present bool, missing bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, os.IsNotExist(err)
	}
	m := info.Mode()
	return m&os.ModeDevice != 0 && m&os.ModeCharDevice != 0, false
}

func DiagnoseHost() DeviceDiagnostics {
	d := DeviceDiagnostics{
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		TPMDevice:                Capability{"unknown", "no-portable-tpm-device-probe"},
		RemoteProvenanceVerifier: Capability{"unsupported", "remote-hardware-verifier-unavailable"},
		MeasuredBootVerifier:     Capability{"unsupported", "pcr-quote-verifier-unavailable"},
		StandardProfile:          "available-with-verified-device-session",
		StrictProfile:            "unavailable-without-verified-provenance-and-guard",
		Notes:                    []string{"This is the server host, not the player's device; TPM presence does not verify any remote key."},
	}
	switch runtime.GOOS {
	case "linux":
		rmPresent, rmMissing := probeTPMNode0311("/dev/tpmrm0")
		tpmPresent, tpmMissing := probeTPMNode0311("/dev/tpm0")
		if rmPresent || tpmPresent {
			d.TPMDevice = Capability{"present", "tpm-character-device-visible-unverified"}
		} else if rmMissing && tpmMissing {
			d.TPMDevice = Capability{"absent", "tpm-character-device-not-visible"}
		} else {
			d.TPMDevice = Capability{"unknown", "tpm-node-not-a-character-device-or-inaccessible"}
		}
	case "darwin":
		d.TPMDevice = Capability{"unsupported", "tpm-device-not-applicable-to-macos"}
		d.Notes = append(d.Notes, "Secure Enclave key generation and App Attest availability do not establish remote provenance for an arbitrary device key.")
	case "windows":
		d.Notes = append(d.Notes, "Windows TPM provisioning and key attestation require native device-side evidence; server cannot infer them from a provider label.")
	}
	return d
}
