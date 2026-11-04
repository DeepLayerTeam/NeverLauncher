package httpapi

import (
	"strconv"
	"strings"
)

const (
	deviceTrustReleaseVersion0130  = "0.13.0"
	deviceTrustSchemaMigration0130 = "0018_device_trust_stabilization_01210"
)

func versionAtLeast0130(value string) bool {
	parts := strings.SplitN(strings.TrimSpace(value), ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 0 || minor >= 13
}

func deviceTrustReleasePayload0130(version string) map[string]any {
	status := "pre-release"
	if versionAtLeast0130(version) {
		status = "released"
	}
	return map[string]any{
		"status":          status,
		"releaseVersion":  deviceTrustReleaseVersion0130,
		"runtimeVersion":  version,
		"schemaMigration": deviceTrustSchemaMigration0130,
		"schemaFrozen":    true,
		"enforcement": map[string]any{
			"sessionDeviceBinding":  true,
			"deviceBoundRefresh":    true,
			"riskActions":           true,
			"minecraftServerBridge": true,
			"permanentRevocation":   true,
		},
		"keyLifecycle": map[string]any{
			"rotation":                      "dual-proof",
			"recovery":                      "phishing-resistant-step-up+new-key-proof",
			"stagedReplacement":             true,
			"permanentFingerprintTombstone": true,
		},
		"attestation": map[string]any{
			"protocol":           "challenge-response-v1",
			"vendorProvenance":   "not-remotely-verified",
			"authorizationBoost": false,
		},
		"releaseCertification": map[string]any{
			"required": true,
			"policy":   "exact-commit-public-device-trust-matrix",
			"artifacts": []string{
				"DEVICE_TRUST_TARGETS.json",
				"DEVICE_TRUST_MATRIX.json",
				"DEVICE_TRUST_CERTIFICATION.json",
			},
		},
	}
}
