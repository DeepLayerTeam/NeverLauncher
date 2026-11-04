package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const validationAudience0346 = "launcher-api/validation-evidence/0.34.7"
const validationPurpose0346 = "staged-package-runtime-verification"

// This is a pinned, operator-managed set of REQUIRED execution targets. There
// are no globs, optional defaults, or wildcard SHA values. It is not supplied
// by the runner and cannot be edited by changing a submitted evidence JSON.
// A target may be updated only by updating the Backend configuration; changes
// invalidate all earlier signatures through the matrix digest.
type validationTarget0346 struct {
	ID                   string `json:"id"`
	ProjectID            string `json:"projectId"`
	ProfileID            string `json:"profileId"`
	Channel              string `json:"channel"`
	Version              string `json:"version"`
	ManifestSHA256       string `json:"manifestSha256"`
	ArtifactSHA256       string `json:"artifactSha256"`
	ResolvedPlanSHA256   string `json:"resolvedPlanSha256"`
	SourceSHA            string `json:"sourceSha"`
	BuildSHA             string `json:"buildSha"`
	JavaSHA256           string `json:"javaSha256"`
	JavaVersion          string `json:"javaVersion"`
	OS                   string `json:"os"`
	Arch                 string `json:"arch"`
	Loader               string `json:"loader"`
	InstallAdapterSHA256 string `json:"installAdapterSha256"`
	GuardMode            string `json:"guardMode"`
	GuardPolicySHA256    string `json:"guardPolicySha256"`
	ServerBridgeSHA256   string `json:"serverBridgeSha256"`
	ServerPluginVersion  string `json:"serverPluginVersion"`
	Preset               string `json:"preset"`
	AuthenticationMode   string `json:"authenticationMode"`
}

func validTarget0346(t validationTarget0346) error {
	if !validationPreset0348.MatchString(t.Preset) {
		return errors.New("invalid configured preset selection")
	}
	if t.AuthenticationMode != "official" && t.AuthenticationMode != "custom" {
		return errors.New("required target must declare real authentication mode")
	}
	for _, v := range []string{t.ID, t.ProjectID, t.ProfileID, t.Channel, t.Version, t.JavaVersion, t.OS, t.Arch, t.Loader, t.GuardMode, t.ServerPluginVersion, t.AuthenticationMode} {
		if !validationToken0345.MatchString(v) {
			return errors.New("invalid configured target identity")
		}
	}
	for _, v := range []string{t.ManifestSHA256, t.ArtifactSHA256, t.ResolvedPlanSHA256, t.BuildSHA, t.JavaSHA256, t.InstallAdapterSHA256, t.GuardPolicySHA256, t.ServerBridgeSHA256} {
		if !validationHex0345.MatchString(v) {
			return errors.New("missing/invalid target SHA-256 pin")
		}
	}
	if !(validationHex0345.MatchString(t.SourceSHA) || (len(t.SourceSHA) == 40 && strings.Trim(t.SourceSHA, "0123456789abcdef") == "")) {
		return errors.New("invalid source pin")
	}
	return nil
}
func configuredTargets0346(raw string, release model.ReleaseVersion, manifestSHA, artifactSHA string) ([]validationTarget0346, string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, "", errors.New("runtime target policy is not configured")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var all []validationTarget0346
	if err := decoder.Decode(&all); err != nil {
		return nil, "", fmt.Errorf("invalid target policy: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, "", errors.New("trailing or invalid target policy JSON")
	}
	if len(all) == 0 || len(all) > 128 {
		return nil, "", errors.New("invalid target policy size")
	}
	relevant := make([]validationTarget0346, 0)
	ids := map[string]bool{}
	for _, t := range all {
		if err := validTarget0346(t); err != nil {
			return nil, "", err
		}
		key := t.ProjectID + "/" + t.ProfileID + "/" + t.Channel + "/" + t.Version + "/" + t.ID
		if ids[key] {
			return nil, "", errors.New("duplicate target ID")
		}
		ids[key] = true
		if t.ProjectID == release.ProjectID && t.ProfileID == release.ProfileID && t.Channel == release.Channel && t.Version == release.Version {
			if t.ManifestSHA256 != manifestSHA || t.ArtifactSHA256 != artifactSHA {
				return nil, "", errors.New("configured target points at a different staged snapshot")
			}
			relevant = append(relevant, t)
		}
	}
	if len(relevant) == 0 {
		return nil, "", errors.New("no required runtime targets for this package/version")
	}
	if err := validateComponentMatrix0348(release.Manifest, relevant); err != nil {
		return nil, "", err
	}
	sort.Slice(relevant, func(i, j int) bool { return relevant[i].ID < relevant[j].ID })
	canonical, err := json.Marshal(relevant)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(append([]byte("Launcher/required-validation-targets/0.34.6\x00"), canonical...))
	return relevant, hex.EncodeToString(digest[:]), nil
}
func matchingTarget0346(p validationPayload0345, t validationTarget0346) bool {
	return p.TargetID == t.ID && p.PackageVersion == t.Version && p.ManifestSHA256 == t.ManifestSHA256 && p.ArtifactSHA256 == t.ArtifactSHA256 && p.ResolvedPlanSHA256 == t.ResolvedPlanSHA256 && p.SourceSHA == t.SourceSHA && p.BuildSHA == t.BuildSHA && p.JavaSHA256 == t.JavaSHA256 && p.JavaVersion == t.JavaVersion && p.OS == t.OS && p.Arch == t.Arch && p.Loader == t.Loader && p.InstallAdapterSHA256 == t.InstallAdapterSHA256 && p.GuardMode == t.GuardMode && p.GuardPolicySHA256 == t.GuardPolicySHA256 && p.ServerBridgeSHA256 == t.ServerBridgeSHA256 && p.ServerPluginVersion == t.ServerPluginVersion && p.Preset == t.Preset && p.AuthenticationMode == t.AuthenticationMode
}
func validationKeyFingerprint0346(key string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return "", errors.New("validation trust key unavailable")
	}
	h := sha256.Sum256(decoded)
	return hex.EncodeToString(h[:]), nil
}

type validationFreshnessStore0346 interface {
	SaveValidationChallenge0346(context.Context, model.ValidationChallenge0346) error
	GetValidationChallenge0346(context.Context, string) (model.ValidationChallenge0346, error)
	IsValidationKeyRevoked0346(context.Context, string) (bool, error)
	RevokeValidationKey0346(context.Context, string, string, string) error
}

func validateFreshness0346(ctx context.Context, store validationFreshnessStore0346, p validationPayload0345, now time.Time, accepting bool) error {
	if p.Audience != validationAudience0346 || p.Purpose != validationPurpose0346 {
		return errors.New("wrong evidence audience or purpose")
	}
	challenge, err := store.GetValidationChallenge0346(ctx, p.RunID)
	if err != nil {
		return errors.New("no backend-issued attestation challenge")
	}
	if p.RunNonce != challenge.Nonce || p.PackageID != challenge.PackageID || p.ManifestSHA256 != challenge.ManifestSHA256 || p.ArtifactSHA256 != challenge.ArtifactSHA256 || p.TargetMatrixSHA256 != challenge.TargetMatrixSHA256 {
		return errors.New("attestation challenge/snapshot/target policy mismatch")
	}
	issued, err := time.Parse(time.RFC3339Nano, p.IssuedAt)
	if err != nil || !issued.Equal(challenge.IssuedAt) {
		return errors.New("invalid signed challenge issue time")
	}
	expires, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.After(issued.Add(24*time.Hour)) || !now.Before(expires) {
		return errors.New("attestation evidence expired or invalid")
	}
	if (accepting && !now.Before(challenge.ExpiresAt)) || now.Before(challenge.IssuedAt.Add(-5*time.Minute)) {
		return errors.New("attestation challenge expired or not yet issued")
	}
	started, err := time.Parse(time.RFC3339Nano, p.StartedAt)
	if err != nil || started.Before(challenge.IssuedAt.Add(-5*time.Minute)) || started.After(challenge.ExpiresAt) {
		return errors.New("execution not within authorized challenge")
	}
	ended, err := time.Parse(time.RFC3339Nano, p.FinishedAt)
	if err != nil || ended.After(challenge.ExpiresAt.Add(5*time.Minute)) || ended.After(now.Add(5*time.Minute)) {
		return errors.New("execution finished outside challenge")
	}
	revoked, err := store.IsValidationKeyRevoked0346(ctx, p.SignerKeyID)
	if err != nil {
		return fmt.Errorf("key revocation store unavailable: %w", err)
	}
	if revoked {
		return errors.New("validation attestation signer revoked")
	}
	return nil
}

// Emergency revocation is durable and monotonic. The private signing key is
// not returned, and a revoked fingerprint cannot be unrevoked by this API.
func (s Server) validationKeyRevoke0346(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(validationFreshnessStore0346)
	if !ok {
		writeError(w, 503, "validation revocation store unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req struct {
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
	}
	if err := dec.Decode(&req); err != nil {
		writeError(w, 400, "invalid revocation request")
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeError(w, 400, "invalid revocation trailing bytes")
		return
	}
	if !validationHex0345.MatchString(req.Fingerprint) || len(strings.TrimSpace(req.Reason)) < 8 || len(req.Reason) > 512 {
		writeError(w, 400, "invalid fingerprint or revocation reason")
		return
	}
	actor := s.adminActor(r)
	if err := store.RevokeValidationKey0346(r.Context(), req.Fingerprint, actor, req.Reason); err != nil {
		writeError(w, 503, "could not durably revoke signer")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: actor, Action: "validation-attestation:key-revoked", Target: req.Fingerprint, ReasonCode: "emergency-validation-signer-revocation-0346", CreatedAt: time.Now().UTC()})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": map[string]any{"fingerprint": req.Fingerprint, "revoked": true}})
}
