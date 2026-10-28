package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// This evaluator runs on the API host, not the runner. An evidence record is
// counted only if its signature, audience, challenge, key, exact target,
// immutable content and every mandatory execution stage still verify.
// The database independently checks these saved rows again inside the head
// transaction. Legacy runtime evidence has no path into this evaluator.
type stableCoverage03411 struct {
	Required       int                    `json:"required"`
	Verified       int                    `json:"verified"`
	MatrixSHA256   string                 `json:"matrixSha256,omitempty"`
	SourceSHA      string                 `json:"sourceSha,omitempty"`
	TargetCoverage map[string]bool        `json:"targetCoverage"`
	TargetBlockers map[string]string      `json:"targetBlockers"`
	Runs           map[string]string      `json:"-"`
	Targets        []validationTarget0346 `json:"-"`
	Eligible       bool                   `json:"stablePublishEligible"`
}

func (s Server) evaluateStableRelease03411(ctx context.Context, lookup packageLookup) stableCoverage03411 {
	c := stableCoverage03411{TargetCoverage: map[string]bool{}, TargetBlockers: map[string]string{}, Runs: map[string]string{}}
	block := func(reason string) stableCoverage03411 { c.TargetBlockers["release"] = reason; return c }
	if !repository.IsStableChannel0341(lookup.Release.Channel) {
		return block("not a stable release")
	}
	md, e := manifestDigest0212(lookup.Release.Manifest)
	if e != nil {
		return block("cannot digest release manifest")
	}
	fd, e := artifactDigest0212(lookup.Files)
	if e != nil {
		return block("cannot digest staged files")
	}
	targets, matrix, e := configuredTargets0346(s.Config.ValidationRequiredTargetsJSON0346, lookup.Release, md, fd)
	if e != nil {
		return block("required target policy: " + e.Error())
	}
	// A release may have platform-specific build digests, but every target
	// must originate from one exact source revision. Mixed-source evidence
	// cannot certify a single staged release (including promotion/rollback).
	source, consistent := stableSourceConsistency0350(targets)
	if !consistent {
		return block("required targets use different source revisions")
	}
	c.SourceSHA = source
	c.Targets = targets
	c.MatrixSHA256 = matrix
	c.Required = len(targets)
	for _, t := range targets {
		c.TargetCoverage[t.ID] = false
		c.TargetBlockers[t.ID] = "missing signed matching runtime attestation"
	}
	if !validationHex0345.MatchString(s.Config.ValidationTrustedRunnerImageSHA2560345) {
		return block("trusted OCI runner image not pinned")
	}
	if _, e = validationKeyFingerprint0346(s.Config.ValidationAttestationPublicKey0345); e != nil {
		return block("trusted attestation public key missing")
	}
	if sig := lookup.Release.Manifest.Signature; sig != nil {
		a, ae := base64.RawURLEncoding.DecodeString(s.Config.ValidationAttestationPublicKey0345)
		b, be := hex.DecodeString(sig.PublicKey)
		if ae != nil || be != nil || bytes.Equal(a, b) {
			return block("attestor and release signing keys must be distinct")
		}
	}
	if s.verifyManifestSignature(lookup.Release.Manifest) != nil || !manifestFilesMatch0212(lookup.Release.Manifest, lookup.Files) {
		return block("release signature or signed files invalid")
	}
	check, e := s.Repo.LatestIntegrityCheck(ctx, lookup.Release.ID)
	if e != nil || check.Result != "passed" || check.ManifestDigest != md || check.ArtifactDigest != fd {
		return block("fresh manifest/files integrity PASS missing")
	}
	attestations, ok := s.Repo.(validationAttestationRepository0345)
	if !ok {
		return block("trusted attestation repository unavailable")
	}
	fresh, ok := s.Repo.(validationFreshnessStore0346)
	if !ok {
		return block("key revocation/challenge repository unavailable")
	}
	records, e := attestations.ListValidationAttestations0345(ctx, lookup.Release.ID)
	if e != nil {
		return block("attestation records unavailable: " + e.Error())
	}
	runs, e := attestations.ListStagedRuns0342(ctx, lookup.Release.ID)
	if e != nil {
		return block("recorded execution runs unavailable")
	}
	runIndex := make(map[string]int, len(runs))
	for i := range runs {
		runIndex[runs[i].RunID] = i
	}
	now := time.Now().UTC()
	for _, record := range records {
		var signed signedValidation0345
		if e := decodeStoredEvidence03411(record.Evidence, &signed.Evidence); e != nil {
			continue
		}
		signed.Signature = record.Signature
		p := signed.Evidence
		if p.RunID != record.RunID || p.PackageID != record.PackageID || p.ManifestSHA256 != md || p.ArtifactSHA256 != fd || p.TargetMatrixSHA256 != matrix || p.RunnerImageSHA256 != s.Config.ValidationTrustedRunnerImageSHA2560345 {
			continue
		}
		if e := verifyValidation0345(signed, s.Config.ValidationAttestationPublicKey0345); e != nil {
			continue
		}
		if e := validateFreshness0346(ctx, fresh, p, now, false); e != nil {
			continue
		}
		index, found := runIndex[p.RunID]
		if !found || matchObservation0345(p, runs[index]) != nil {
			continue
		}
		for _, t := range targets {
			if c.TargetCoverage[t.ID] || !matchingTarget0346(p, t) {
				continue
			}
			c.TargetCoverage[t.ID] = true
			c.Runs[t.ID] = p.RunID
			delete(c.TargetBlockers, t.ID)
			c.Verified++
		}
	}
	c.Eligible = c.Verified == c.Required && c.Required > 0 && len(c.TargetBlockers) == 0
	return c
}

func decodeStoredEvidence03411(raw []byte, p *validationPayload0345) error {
	// Reject records with non-canonical, unknown fields as well as invalid JSON.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(p); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("invalid attestation trailing data")
	}
	return nil
}

// Called immediately before irrevocable publication. The permit is scoped to
// one package+snapshot, expires in five minutes, and is consumed by the SQL
// channel-head trigger. There is no API for setting certification manually.
func (s Server) issueStablePermit03411(ctx context.Context, lookup packageLookup) (string, stableCoverage03411, error) {
	coverage := s.evaluateStableRelease03411(ctx, lookup)
	if !coverage.Eligible {
		if e := s.saveValidationDecision03412(ctx, lookup.Release.ID, "", "stable-gate", "blocked",
			"required-targets-incomplete", safeValidationDecisionDigest03412(coverage.TargetBlockers)); e != nil {
			return "", coverage, errors.New("stable runtime gate audit unavailable")
		}
		return "", coverage, fmt.Errorf("stable runtime gate denied: %v", coverage.TargetBlockers)
	}
	issuer, ok := s.Repo.(interface {
		IssueStableRuntimePermit03411(context.Context, repository.StableRuntimePermit03411) (string, error)
	})
	if !ok {
		return "", coverage, errors.New("stable SQL permit issuer unavailable")
	}
	md, _ := manifestDigest0212(lookup.Release.Manifest)
	fd, _ := artifactDigest0212(lookup.Files)
	targetsRaw, e := json.Marshal(coverage.Targets)
	if e != nil {
		return "", coverage, e
	}
	token, e := issuer.IssueStableRuntimePermit03411(ctx, repository.StableRuntimePermit03411{
		PackageID: lookup.Release.ID, ProjectID: lookup.Release.ProjectID, ManifestSHA256: md,
		ArtifactSHA256: fd, MatrixSHA256: coverage.MatrixSHA256, TargetsJSON: targetsRaw, Runs: coverage.Runs,
	})
	if e != nil {
		return "", coverage, e
	}
	// Eligibility is recorded, but a permit alone NEVER establishes a publish.
	if e = s.saveValidationDecision03412(ctx, lookup.Release.ID, "", "stable-gate", "eligible",
		"checked-before-commit", safeValidationDecisionDigest03412(coverage.Runs)); e != nil {
		return "", coverage, errors.New("stable runtime gate audit unavailable")
	}
	return token, coverage, nil
}

// All targets of one release must be built from the same source revision.
func stableSourceConsistency0350(targets []validationTarget0346) (string, bool) {
	if len(targets) == 0 {
		return "", false
	}
	source := targets[0].SourceSHA
	if source == "" {
		return "", false
	}
	for _, target := range targets[1:] {
		if target.SourceSHA != source {
			return "", false
		}
	}
	return source, true
}
