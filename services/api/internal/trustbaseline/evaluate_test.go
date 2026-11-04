package trustbaseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func testDevice0311(now time.Time) model.TrustedDevice {
	return model.TrustedDevice{
		ID: "device-a", Status: "active", TrustState: "verified",
		KeyAlgorithm: "p256", KeyBinding: "hardware", HardwareProvider: "TPM 2.0",
		KeyFingerprint:           strings.Repeat("a", 64),
		RemoteHardwareProvenance: "verified", // potentially forged legacy DB value
		AttestationState:         "verified", AttestationMethod: "challenge-response-v1",
		AttestedAt: now.Add(-time.Minute), AttestationExpiresAt: now.Add(time.Hour),
	}
}

func TestLegacyHardwareClaimCannotGrantStrict0311(t *testing.T) {
	now := time.Now().UTC()
	d := testDevice0311(now)
	result := Evaluate(d, true, now)
	if result.RemoteHardwareProvenance != "not-verified" || result.LocalHardwareBinding != "client-reported" {
		t.Fatalf("upgrade from client claim: %+v", result)
	}
	if result.ProfileDecisions[Standard].Result != Allow {
		t.Fatalf("standard should allow a verified bound session: %+v", result)
	}
	strict := result.ProfileDecisions[Strict]
	if strict.Result != Deny || !contains0311(strict.ReasonCodes, "remote-hardware-verifier-unavailable") || !contains0311(strict.ReasonCodes, "guard-runtime-evidence-unavailable") {
		t.Fatalf("strict improperly granted: %+v", strict)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), `"remoteHardwareProvenance":"verified"`) {
		t.Fatalf("verified claim leaked: %s", raw)
	}
}
func contains0311(items []string, code string) bool {
	for _, x := range items {
		if x == code {
			return true
		}
	}
	return false
}

func TestStandardRequiresVerifiedBinding0311(t *testing.T) {
	now := time.Now().UTC()
	d := testDevice0311(now)
	cases := []struct {
		name   string
		mutate func(*model.TrustedDevice)
		bound  bool
		reason string
	}{
		{"foreign session", func(*model.TrustedDevice) {}, false, "session-device-binding-missing"},
		{"revoked", func(d *model.TrustedDevice) { d.Status = "revoked" }, true, "device-not-verified"},
		{"not verified", func(d *model.TrustedDevice) { d.TrustState = "pending" }, true, "device-not-verified"},
		{"empty fingerprint", func(d *model.TrustedDevice) { d.KeyFingerprint = "" }, true, "device-not-verified"},
		{"unknown algorithm", func(d *model.TrustedDevice) { d.KeyAlgorithm = "rsa" }, true, "device-not-verified"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			copy := d
			c.mutate(&copy)
			got := Evaluate(copy, c.bound, now).ProfileDecisions[Standard]
			if got.Result != Deny || !contains0311(got.ReasonCodes, c.reason) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
func TestExpiredLegacyChallengeCannotBecomeRemoteEvidence0311(t *testing.T) {
	now := time.Now().UTC()
	d := testDevice0311(now)
	d.AttestationExpiresAt = now.Add(-time.Second)
	got := Evaluate(d, true, now)
	if !got.EvidenceExpiresAt.IsZero() || !contains0311(got.ReasonCodes, "challenge-response-expired-or-invalid") || got.ProfileDecisions[Strict].Result != Deny {
		t.Fatalf("expired accepted: %+v", got)
	}
	// Loss of TPM must not lock a user out of the standard profile.
	d.KeyBinding = "software"
	d.HardwareProvider = ""
	d.AttestationState = "unattested"
	got = Evaluate(d, true, now)
	if got.ProfileDecisions[Standard].Result != Allow || got.ProfileDecisions[Strict].Result != Deny {
		t.Fatalf("no TPM recovery: %+v", got)
	}
}
func TestDeviceHostDiagnosticDoesNotClaimRemoteAttestation0311(t *testing.T) {
	d := DiagnoseHost()
	if d.Platform == "" || d.RemoteProvenanceVerifier.State != "unsupported" || d.MeasuredBootVerifier.State != "unsupported" || d.StrictProfile == "" {
		t.Fatalf("unsafe diagnostic: %+v", d)
	}
}

func TestMacOSStrictRefusalDoesNotDependOnBackendOS0311(t *testing.T) {
	now := time.Now().UTC()
	d := testDevice0311(now)
	d.Platform = "macos"
	strict := Evaluate(d, true, now).ProfileDecisions[Strict]
	if strict.Result != Deny || !contains0311(strict.ReasonCodes, "macos-device-key-provenance-unsupported") {
		t.Fatalf("bad remote macOS diagnostics %+v", strict)
	}
}

func TestFakeTPMNodeDetected0311(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "tpmrm0")
	if err := os.WriteFile(fake, []byte("not a tpm"), 0600); err != nil {
		t.Fatal(err)
	}
	if present, missing := probeTPMNode0311(fake); present || missing {
		t.Fatalf("regular file can spoof TPM: %v %v", present, missing)
	}
	link := filepath.Join(dir, "tpm0")
	if err := os.Symlink(fake, link); err == nil {
		if present, missing := probeTPMNode0311(link); present || missing {
			t.Fatalf("symlink can spoof TPM")
		}
	}
	if present, missing := probeTPMNode0311(filepath.Join(dir, "absent")); present || !missing {
		t.Fatal("missing device misdetected")
	}
}
