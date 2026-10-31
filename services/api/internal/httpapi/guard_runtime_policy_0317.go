package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// The policy is operator-controlled server configuration, not a client manifest.
// ModuleSetSHA256 is an exact approved module set; JavaMajor pins the runtime
// family. Optional code/hook hashes can further narrow a deployment.
type guardRuntimeProfile0317 struct {
	JavaMajor       uint32 `json:"javaMajor"`
	ModuleSetSHA256 string `json:"moduleSetSha256"`
	CodeSetSHA256   string `json:"codeSetSha256,omitempty"`
	HookSetSHA256   string `json:"hookSetSha256,omitempty"`
}

func guardRuntimePolicyRequired0317(version string) bool {
	var major, minor, patch int
	if _, err := fmt.Sscanf(strings.TrimSpace(version), "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	return major > 0 || minor > 31 || (minor == 31 && patch >= 7)
}

func normalizeGuardRuntimeProfiles0317(input []guardRuntimeProfile0317) ([]guardRuntimeProfile0317, error) {
	if len(input) > 32 {
		return nil, errors.New("too many Guard runtime profiles (max 32)")
	}
	out := make([]guardRuntimeProfile0317, 0, len(input))
	seen := make(map[string]bool, len(input))
	for _, profile := range input {
		switch profile.JavaMajor {
		case 8, 16, 17, 21, 25:
		default:
			return nil, errors.New("unsupported Java major in Guard runtime policy")
		}
		profile.ModuleSetSHA256 = strings.ToLower(strings.TrimSpace(profile.ModuleSetSHA256))
		profile.CodeSetSHA256 = strings.ToLower(strings.TrimSpace(profile.CodeSetSHA256))
		profile.HookSetSHA256 = strings.ToLower(strings.TrimSpace(profile.HookSetSHA256))
		if !isSHA256Hex0134(profile.ModuleSetSHA256) {
			return nil, errors.New("moduleSetSha256 must be a SHA-256 digest")
		}
		if profile.CodeSetSHA256 != "" && !isSHA256Hex0134(profile.CodeSetSHA256) {
			return nil, errors.New("codeSetSha256 must be a SHA-256 digest")
		}
		if profile.HookSetSHA256 != "" && !isSHA256Hex0134(profile.HookSetSHA256) {
			return nil, errors.New("hookSetSha256 must be a SHA-256 digest")
		}
		key := fmt.Sprintf("%d:%s:%s:%s", profile.JavaMajor, profile.ModuleSetSHA256, profile.CodeSetSHA256, profile.HookSetSHA256)
		if seen[key] {
			return nil, errors.New("duplicate runtime profile")
		}
		seen[key] = true
		out = append(out, profile)
	}
	return out, nil
}

// Hashes all effective profiles in their declared order. A policy replacement
// (even under the same release version) revokes already issued join tickets.
func guardRuntimePolicyDigest0317(profiles []guardRuntimeProfile0317) string {
	if len(profiles) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Launcher Guard Runtime Policy v1\n")
	for _, p := range profiles {
		fmt.Fprintf(&b, "%d:%s:%s:%s\n", p.JavaMajor, p.ModuleSetSHA256, p.CodeSetSHA256, p.HookSetSHA256)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func guardRuntimeMatches0317(profiles []guardRuntimeProfile0317, javaMajor uint32, moduleHash, codeHash, hookHash string) bool {
	for _, p := range profiles {
		if p.JavaMajor != javaMajor || !hmac.Equal([]byte(p.ModuleSetSHA256), []byte(moduleHash)) {
			continue
		}
		if p.CodeSetSHA256 != "" && !hmac.Equal([]byte(p.CodeSetSHA256), []byte(codeHash)) {
			continue
		}
		if p.HookSetSHA256 != "" && !hmac.Equal([]byte(p.HookSetSHA256), []byte(hookHash)) {
			continue
		}
		return true
	}
	return false
}

func verifyGuardRuntimePolicy0317(policy guardReleasePolicy0134, platform string, evidence guardContinuousEvidence01810) (string, error) {
	kind, err := guardPlatformKind0140(platform)
	if err != nil {
		return "", err
	}
	if kind != "windows" {
		return "", errors.New("continuous Guard runtime verification requires Windows")
	}
	profiles := policy.RuntimeProfiles[kind]
	if len(profiles) == 0 {
		return "", errors.New("Windows Guard runtime allowlist is not configured")
	}
	if !guardRuntimeMatches0317(profiles, evidence.JavaMajor, evidence.ModuleSetSHA256, evidence.CodeSetSHA256, evidence.HookSetSHA256) {
		return "", errors.New("Java version or runtime module/code/hook set is not approved")
	}
	return guardRuntimePolicyDigest0317(profiles), nil
}

func validGuardProcessID0317(value string) bool {
	if len(value) == 0 || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

// Revalidated after atomic one-time ticket consumption; evidence cannot survive
// root/device/key/session/policy revocation. A user-mode device signature is
// evidence of possession, NOT independently measured runtime integrity.
func (s Server) recheckContinuousGuardTicket0317(claims authClaims, ticket model.DeviceChallenge, now time.Time) error {
	if !validGuardProcessID0317(metadataString0121(ticket.Metadata, "processId")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "moduleSetSha256")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "codeSetSha256")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "hookSetSha256")) ||
		!isSHA256Hex0134(metadataString0121(ticket.Metadata, "jvmStateSha256")) {
		return errors.New("Continuous Guard ticket runtime evidence malformed")
	}
	major, err := strconv.ParseUint(metadataString0121(ticket.Metadata, "javaMajor"), 10, 32)
	if err != nil || major == 0 {
		return errors.New("Continuous Guard ticket Java version invalid")
	}
	device, err := s.Repo.GetTrustedDevice(claims.Sub, claims.TrustedDeviceID)
	if err != nil || device.Status != "active" || device.TrustState != "verified" {
		return errors.New("Continuous Guard trusted device revoked or unavailable")
	}
	state, _ := effectiveDeviceAttestation0124(device, now)
	if state != "verified" {
		return errors.New("Continuous Guard device attestation expired")
	}
	// Prevent stale or previously verified device keys from surviving recovery.
	if metadataString0121(ticket.Metadata, "deviceKeyFingerprint") != device.KeyFingerprint || device.KeyFingerprint == "" {
		return errors.New("Continuous Guard device key rotated or revoked")
	}
	version := metadataString0121(ticket.Metadata, "launcherVersion")
	policies, err := s.guardReleasePolicies0134()
	if err != nil {
		return errors.New("Continuous Guard release policy unavailable")
	}
	policy, ok := policies[version]
	if !ok {
		return errors.New("Continuous Guard release revoked")
	}
	allowed, _, err := policy.allowsArtifactPair0140(device.Platform, metadataString0121(ticket.Metadata, "guardSha256"), metadataString0121(ticket.Metadata, "launcherSha256"))
	if err != nil || !allowed {
		return errors.New("Continuous Guard artifact release revoked")
	}
	evidence := guardContinuousEvidence01810{
		JavaMajor:       uint32(major),
		ModuleSetSHA256: metadataString0121(ticket.Metadata, "moduleSetSha256"),
		CodeSetSHA256:   metadataString0121(ticket.Metadata, "codeSetSha256"),
		HookSetSHA256:   metadataString0121(ticket.Metadata, "hookSetSha256"),
	}
	digest, err := verifyGuardRuntimePolicy0317(policy, device.Platform, evidence)
	if err != nil {
		return fmt.Errorf("Continuous Guard runtime policy revoked: %w", err)
	}
	if digest == "" || !hmac.Equal([]byte(digest), []byte(metadataString0121(ticket.Metadata, "runtimePolicySha256"))) {
		return errors.New("Continuous Guard runtime policy changed after attestation")
	}
	// Repository-backed ticket TTL is authoritative; no process assurance is
	// extended by client time or by an older hardware root assessment.
	if ticket.CreatedAt.After(now.Add(guardAttestationClockSkew0134)) || !ticket.ExpiresAt.After(now) {
		return errors.New("Continuous Guard ticket expired or from the future")
	}
	return nil
}
