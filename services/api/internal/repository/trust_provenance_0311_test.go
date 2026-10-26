package repository

import (
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestLegacyProvenanceDowngradedOnDeviceWrite0311(t *testing.T) {
	original := model.TrustedDevice{
		ID: "dev-a", UserID: "user-a", Name: "Hardware claim", PublicKey: "base64-key", KeyFingerprint: "sha256-key",
		Status: "active", TrustState: "verified", KeyAlgorithm: "p256", KeyBinding: "hardware", HardwareProvider: "fake-tpm",
		RemoteHardwareProvenance: "verified", Assurance: "proof-of-possession",
	}
	normalized, err := normalizeTrustedDevice0121(original)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.RemoteHardwareProvenance != "not-verified" {
		t.Fatalf("legacy self-asserted provenance elevated: %+v", normalized)
	}
	original.RemoteHardwareProvenance = "unknown-with-malicious-value"
	if _, err := normalizeTrustedDevice0121(original); err == nil {
		t.Fatal("malformed provenance should be rejected")
	}
}
