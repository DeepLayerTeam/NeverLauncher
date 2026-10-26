package trustbaseline

import (
	"strings"
	"testing"
	"time"
)

func TestMacOSSecureEnclaveLabelsNeverGrantRemoteProvenance0316(t *testing.T) {
	now := time.Now().UTC()
	for _, platform := range []string{"darwin", "macos", "Mac OS X", "MacIntel", "MacPPC", "Macintosh"} {
		device := testDevice0311(now)
		device.Platform = platform
		device.HardwareProvider = "MacOsSecureEnclave"
		device.KeyAlgorithm = "p256"
		device.KeyBinding = "hardware"
		device.RemoteHardwareProvenance = "verified" // forged legacy DB state
		assessment := Evaluate(device, true, now)
		if assessment.RemoteHardwareProvenance != "not-verified" || assessment.ProfileDecisions[Standard].Result != Allow || assessment.ProfileDecisions[Strict].Result != Deny {
			t.Fatalf("local Mac key upgraded remote assurance: %+v", assessment)
		}
		strict := assessment.ProfileDecisions[Strict]
		if !contains0311(strict.ReasonCodes, "macos-app-attest-not-bound-to-device-identity") || !strings.Contains(strict.RecoveryAction, "passkey") {
			t.Fatalf("unhelpful Mac strict denial: %+v", strict)
		}
	}
}
