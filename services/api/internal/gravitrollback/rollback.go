// Package gravitrollback implements fail-closed MIG12 reconciliation. It does
// not import or overwrite Minecraft worlds, SQL plugins, or Gravit databases.
package gravitrollback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	gr "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitrehearsal"
)

const Format = "never/gravit-rollback/v1"

var sha = regexp.MustCompile(`^[a-f0-9]{64}$`)
var id = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)

type PlanInput struct {
	ProfileID        string `json:"profileId"`
	Channel          string `json:"channel"`
	ExpectedRevision int64  `json:"expectedRevision"`
	// This snapshot MUST be collected after production writers have been
	// externally fenced; it is not proof that they are stopped.
	Current           gr.Snapshot `json:"current"`
	EvidenceReference string      `json:"evidenceReference"`
	EvidenceSHA256    string      `json:"evidenceSha256"`
	// Required only if the Never state has diverged from MIG10. The operator
	// must FIRST reconcile changed data into the fenced Gravit destination.
	ReconciledSource             *gr.Snapshot `json:"reconciledSource,omitempty"`
	ReconciliationEvidenceSHA256 string       `json:"reconciliationEvidenceSha256,omitempty"`
}
type CommitInput struct {
	ProfileID          string `json:"profileId"`
	Channel            string `json:"channel"`
	ExpectedRevision   int64  `json:"expectedRevision"`
	PlanSHA256         string `json:"planSha256"`
	SourceWriterFenced bool   `json:"sourceWriterFenced"`
	NeverWriterFenced  bool   `json:"neverWriterFenced"`
	// Fresh independently exported state, captured immediately before commit.
	Current                      gr.Snapshot  `json:"current"`
	CurrentEvidenceSHA256        string       `json:"currentEvidenceSha256"`
	ReconciledSource             *gr.Snapshot `json:"reconciledSource,omitempty"`
	ReconciliationEvidenceSHA256 string       `json:"reconciliationEvidenceSha256,omitempty"`
}
type Result struct {
	Format                       string   `json:"format"`
	RunID                        string   `json:"runId"`
	ProfileID                    string   `json:"profileId"`
	Channel                      string   `json:"channel"`
	State                        string   `json:"state"`
	RouteRevision                int64    `json:"routeRevision"`
	CurrentSnapshotSHA256        string   `json:"currentSnapshotSha256"`
	BaselineSnapshotSHA256       string   `json:"baselineSnapshotSha256"`
	ReconciledSourceSHA256       string   `json:"reconciledSourceSha256,omitempty"`
	ReconciliationEvidenceSHA256 string   `json:"reconciliationEvidenceSha256,omitempty"`
	Mode                         string   `json:"mode"`
	EvidenceReference            string   `json:"evidenceReference"`
	EvidenceSHA256               string   `json:"evidenceSha256"`
	PlanSHA256                   string   `json:"planSha256"`
	Blockers                     []string `json:"blockers"`
	Ready                        bool     `json:"ready"`
}

func ValidatePlan(p PlanInput) error {
	if !id.MatchString(p.ProfileID) || !id.MatchString(p.Channel) || p.ExpectedRevision < 1 || len(p.EvidenceReference) < 8 || len(p.EvidenceReference) > 256 || strings.ContainsAny(p.EvidenceReference, "\r\n\x00") || !sha.MatchString(p.EvidenceSHA256) {
		return errors.New("invalid rollback scope, revision or evidence")
	}
	return nil
}
func ValidateCommit(c CommitInput) error {
	if !id.MatchString(c.ProfileID) || !id.MatchString(c.Channel) || c.ExpectedRevision < 1 || !sha.MatchString(c.PlanSHA256) || !c.SourceWriterFenced || !c.NeverWriterFenced || !sha.MatchString(c.CurrentEvidenceSHA256) {
		return errors.New("rollback commit requires matching plan and both independently fenced writers")
	}
	return nil
}

// Compare uses the same domain-specific semantic validation as MIG10. This
// catches player UUID/inventory/rights/economy/skins and world/loader/optionals
// even when JSON entry order or formatting differs. No changed state is lost.
func Compare(input PlanInput, rehearsal gr.Report, runID string) (Result, error) {
	if err := ValidatePlan(input); err != nil {
		return Result{}, err
	}
	checked, err := gr.Evaluate(rehearsal)
	if err != nil || !checked.Ready || checked.RunID != runID {
		return Result{}, errors.New("verified MIG10 baseline required")
	}
	currentDigest, err := gr.SnapshotDigest(input.Current)
	if err != nil {
		return Result{}, err
	}
	test := rehearsal
	test.Target = input.Current
	test.TargetSnapshotSHA256 = currentDigest
	compared, err := gr.Evaluate(test)
	if err != nil {
		return Result{}, fmt.Errorf("invalid current snapshot: %w", err)
	}
	blockers := append([]string{}, compared.Blockers...)
	// Count + source identities must remain intact. New players after cutover
	// are allowed only if they are verifiably represented on BOTH sides.
	if len(input.Current.Players) != len(rehearsal.Target.Players) {
		blockers = append(blockers, "player population changed")
	}
	mode := "unchanged"
	sourceDigest := ""
	if len(blockers) > 0 && input.ReconciledSource != nil {
		if !sha.MatchString(input.ReconciliationEvidenceSHA256) {
			return Result{}, errors.New("reconciliation evidence SHA-256 required")
		}
		sourceDigest, err = gr.SnapshotDigest(*input.ReconciledSource)
		if err != nil {
			return Result{}, err
		}
		// Never -> externally reconciled Gravit, with all live writers fenced.
		pair := rehearsal
		pair.Source = *input.ReconciledSource
		pair.Target = input.Current
		pair.SourceSnapshotSHA256 = sourceDigest
		pair.TargetSnapshotSHA256 = currentDigest
		verified, e := gr.Evaluate(pair)
		if e != nil {
			return Result{}, fmt.Errorf("invalid reconciled source snapshot: %w", e)
		}
		if verified.Ready {
			blockers = nil
			mode = "reconciled"
		} else {
			blockers = append(blockers, "source reconciliation differs from destination")
			blockers = append(blockers, verified.Blockers...)
		}
	}
	sort.Strings(blockers)
	b, err := gr.SnapshotDigest(rehearsal.Target)
	if err != nil {
		return Result{}, err
	}
	result := Result{Format: Format, RunID: runID, ProfileID: input.ProfileID, Channel: input.Channel, State: "evaluated", RouteRevision: input.ExpectedRevision, CurrentSnapshotSHA256: currentDigest, BaselineSnapshotSHA256: b, EvidenceReference: input.EvidenceReference, EvidenceSHA256: input.EvidenceSHA256, ReconciledSourceSHA256: sourceDigest, ReconciliationEvidenceSHA256: input.ReconciliationEvidenceSHA256, Mode: mode, Blockers: blockers, Ready: len(blockers) == 0}
	// Plan hash binds the exact authority-to-source remerging evidence.
	raw, _ := json.Marshal(struct {
		Format, RunID, ProfileID, Channel, Mode                                                string
		Revision                                                                               int64
		Baseline, Current, EvidenceRef, EvidenceHash, ReconciledSource, ReconciliationEvidence string
	}{Format, runID, input.ProfileID, input.Channel, mode, input.ExpectedRevision, b, currentDigest, input.EvidenceReference, input.EvidenceSHA256, sourceDigest, input.ReconciliationEvidenceSHA256})
	sum := sha256.Sum256(raw)
	result.PlanSHA256 = hex.EncodeToString(sum[:])
	return result, nil
}

// ValidSHA256 validates externally retained evidence hash metadata.
func ValidSHA256(v string) bool { return sha.MatchString(v) }
