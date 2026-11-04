package httpapi

import "testing"

func TestDeviceTrustRelease0130Contract(t *testing.T) {
	payload := deviceTrustReleasePayload0130("0.13.0")
	if payload["status"] != "released" || payload["releaseVersion"] != "0.13.0" || payload["schemaMigration"] != deviceTrustSchemaMigration0130 || payload["schemaFrozen"] != true {
		t.Fatalf("unexpected release payload: %#v", payload)
	}
	enforcement, ok := payload["enforcement"].(map[string]any)
	if !ok || enforcement["sessionDeviceBinding"] != true || enforcement["deviceBoundRefresh"] != true || enforcement["riskActions"] != true || enforcement["minecraftServerBridge"] != true || enforcement["permanentRevocation"] != true {
		t.Fatalf("release enforcement is incomplete: %#v", payload["enforcement"])
	}
	attestation, ok := payload["attestation"].(map[string]any)
	if !ok || attestation["vendorProvenance"] != "not-remotely-verified" || attestation["authorizationBoost"] != false {
		t.Fatalf("attestation boundary drifted: %#v", payload["attestation"])
	}
	certification, ok := payload["releaseCertification"].(map[string]any)
	if !ok || certification["required"] != true || certification["policy"] != "exact-commit-public-device-trust-matrix" {
		t.Fatalf("release certification is not mandatory: %#v", payload["releaseCertification"])
	}
}

func TestDeviceTrustRelease0130IsNotClaimedBy01210(t *testing.T) {
	if got := deviceTrustReleasePayload0130("0.12.10")["status"]; got != "pre-release" {
		t.Fatalf("0.12.10 unexpectedly claims Device Trust Release: %v", got)
	}
}
