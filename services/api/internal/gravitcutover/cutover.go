// Package gravitcutover contains the strict inputs for MIG11 route changes.
// Source-side writer fencing is external; a local database claim never proves it.
package gravitcutover

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var scope = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Stage struct {
	ProfileID            string `json:"profileId"`
	Channel              string `json:"channel"`
	ReleaseID            string `json:"releaseId"`
	ExpectedHeadRevision int64  `json:"expectedHeadRevision"`
	StageID              string `json:"stageId"`
}
type Activate struct {
	ProfileID        string `json:"profileId"`
	Channel          string `json:"channel"`
	ExpectedRevision int64  `json:"expectedRevision"`
	// A reference and SHA-256 for separately retained operational evidence that
	// the old Gravit writer was actually stopped/fenced. Not a Never assertion.
	SourceFenceReference        string `json:"sourceFenceReference"`
	SourceFenceEvidenceSHA256   string `json:"sourceFenceEvidenceSha256"`
	CurrentSourceSnapshotSHA256 string `json:"currentSourceSnapshotSha256"`
}
type Route struct {
	RunID               string `json:"runId"`
	ProjectID           string `json:"projectId"`
	ProfileID           string `json:"profileId"`
	Channel             string `json:"channel"`
	StageID             string `json:"stageId"`
	ReleaseID           string `json:"releaseId"`
	ReleaseVersion      string `json:"releaseVersion"`
	TargetDigest        string `json:"targetDigest"`
	BaselineRevision    int64  `json:"baselineRevision"`
	BaselineReleaseID   string `json:"baselineReleaseId"`
	BaselineVersion     string `json:"baselineVersion"`
	BaselineDigest      string `json:"baselineDigest"`
	State               string `json:"state"`
	Revision            int64  `json:"revision"`
	ActivatedRevision   *int64 `json:"activatedRevision,omitempty"`
	FenceReference      string `json:"fenceReference,omitempty"`
	FenceEvidenceSHA256 string `json:"fenceEvidenceSha256,omitempty"`
}

func ValidateStage(s Stage) error {
	if !scope.MatchString(s.ProfileID) || !scope.MatchString(s.Channel) || len(s.ReleaseID) < 1 || len(s.ReleaseID) > 256 || strings.ContainsAny(s.ReleaseID, "\x00\r\n") || s.ExpectedHeadRevision < 0 || len(s.StageID) < 16 || len(s.StageID) > 128 {
		return errors.New("invalid cutover stage scope, release, revision or rehearsal")
	}
	return nil
}
func ValidateActivation(a Activate) error {
	if !scope.MatchString(a.ProfileID) || !scope.MatchString(a.Channel) || a.ExpectedRevision < 1 || len(a.SourceFenceReference) < 8 || len(a.SourceFenceReference) > 256 || strings.ContainsAny(a.SourceFenceReference, "\r\n\x00") || !digest.MatchString(a.SourceFenceEvidenceSHA256) || !digest.MatchString(a.CurrentSourceSnapshotSHA256) {
		return errors.New("invalid cutover activation/fencing evidence")
	}
	return nil
}

// VerifyRelease checks actual Ed25519 bytes and the CURRENT Never signing
// root; a self-signed legacy Gravit manifest cannot be selected as a target.
func VerifyRelease(m model.Manifest, trusted ed25519.PublicKey) (string, error) {
	if err := model.ValidateManifestSchema(m); err != nil {
		return "", err
	}
	if m.Signature == nil || !strings.EqualFold(m.Signature.Algorithm, "Ed25519") {
		return "", errors.New("signed Never release required")
	}
	pub, err := hex.DecodeString(m.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.PublicKey(pub).Equal(trusted) {
		return "", errors.New("release signer is not the current Never trusted key")
	}
	sig, err := hex.DecodeString(m.Signature.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", errors.New("invalid release signature")
	}
	bare := m
	bare.Signature = nil
	raw, err := json.Marshal(bare)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, raw, sig) {
		return "", errors.New("release signature verification failed")
	}
	all, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(all)
	return hex.EncodeToString(sum[:]), nil
}
