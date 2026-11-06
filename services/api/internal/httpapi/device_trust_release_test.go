package httpapi

import "testing"

func TestDeviceTrustRelease0130Contract(t *testing.T) {
	payload := deviceTrustReleasePayload0130("0.13.0")
	if payload["status"] != "released" || payload["releaseVersion"] != "0.13.0" || payload["schemaMigration"] != deviceTrustSchemaMigration0130 || payload["schemaFrozen"] != true {
		t.Fatalf("Неожиданные данные релиза: %#v", payload)
	}
	enforcement, ok := payload["enforcement"].(map[string]any)
	if !ok || enforcement["sessionDeviceBinding"] != true || enforcement["deviceBoundRefresh"] != true || enforcement["riskActions"] != true || enforcement["minecraftServerBridge"] != true || enforcement["permanentRevocation"] != true {
		t.Fatalf("Применение ограничений релиза выполнено не полностью: %#v", payload["enforcement"])
	}
	attestation, ok := payload["attestation"].(map[string]any)
	if !ok || attestation["vendorProvenance"] != "not-remotely-verified" || attestation["authorizationBoost"] != false {
		t.Fatalf("Изменились границы доверия аттестации: %#v", payload["attestation"])
	}
	certification, ok := payload["releaseCertification"].(map[string]any)
	if !ok || certification["required"] != true || certification["policy"] != "exact-commit-public-device-trust-matrix" {
		t.Fatalf("Сертификация релиза не является обязательной: %#v", payload["releaseCertification"])
	}
}

func TestDeviceTrustRelease0130IsNotClaimedBy01210(t *testing.T) {
	if got := deviceTrustReleasePayload0130("0.12.10")["status"]; got != "pre-release" {
		t.Fatalf("Версия 0.12.10 неожиданно заявляет поддержку Device Trust Release: %v", got)
	}
}
