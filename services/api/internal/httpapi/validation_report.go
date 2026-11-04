package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type validationAuditStore03412 interface {
	SaveValidationAttempt03412(context.Context, model.ValidationAttempt03412) error
	ListValidationAttempts03412(context.Context, string, int64, int) ([]model.ValidationAttempt03412, error)
}

func digestValidationAttempt03412(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// Deliberately no free-form reason or detail in the immutable audit. All
// secret-bearing data stays out of this table. A failed insert is visible to
// the caller; stable certification fails closed when auditing is unavailable.
func (s Server) saveValidationDecision03412(ctx context.Context, pkg, run, kind, outcome, reason, digest string) error {
	store, ok := s.Repo.(validationAuditStore03412)
	if !ok {
		return repository.ErrNotFound
	}
	if len(run) > 160 || !validationToken0345.MatchString(run) {
		run = ""
	}
	return store.SaveValidationAttempt03412(ctx, model.ValidationAttempt03412{
		PackageID: pkg, RunID: run, Kind: kind, Outcome: outcome, ReasonCode: reason, PayloadSHA256: digest,
	})
}

type validationEvidenceSummary03412 struct {
	RunID          string    `json:"runId"`
	TargetID       string    `json:"targetId,omitempty"`
	SchemaVersion  string    `json:"schemaVersion,omitempty"`
	EvidenceSHA256 string    `json:"evidenceSha256"`
	ReceivedAt     time.Time `json:"receivedAt"`
	ExpiresAt      string    `json:"expiresAt,omitempty"`
	Status         string    `json:"status"`
}

func (s Server) validationReport03412(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(validationAuditStore03412)
	if !ok {
		writeError(w, 503, "validation audit unavailable")
		return
	}
	pkg := r.PathValue("packageId")
	lookup, err := s.lookupPackage(pkg)
	if err != nil {
		writeError(w, 404, "package not found")
		return
	}
	before := int64(0)
	if v := r.URL.Query().Get("before"); v != "" {
		before, err = strconv.ParseInt(v, 10, 64)
		if err != nil || before <= 0 {
			writeError(w, 400, "invalid audit cursor")
			return
		}
	}
	page, err := store.ListValidationAttempts03412(r.Context(), pkg, before, 101)
	if err != nil {
		writeError(w, 503, "validation audit read failed")
		return
	}
	more := len(page) > 100
	if more {
		page = page[:100]
	}
	next := int64(0)
	if more {
		next = page[len(page)-1].ID
	}
	runStore, ok := s.Repo.(stagedRunWriter0342)
	if !ok {
		writeError(w, 503, "execution reports unavailable")
		return
	}
	runQuery := r.URL.Query().Get("runId")
	var runs []model.StagedRuntimeRun0342
	if runQuery != "" {
		if !validationToken0345.MatchString(runQuery) {
			writeError(w, 400, "invalid run identity")
			return
		}
		history, ok := s.Repo.(interface {
			GetValidationRun03412(context.Context, string, string) (model.StagedRuntimeRun0342, error)
		})
		if !ok {
			writeError(w, 503, "run history unavailable")
			return
		}
		v, err := history.GetValidationRun03412(r.Context(), pkg, runQuery)
		if err != nil {
			writeError(w, 404, "run not found")
			return
		}
		runs = []model.StagedRuntimeRun0342{v}
	} else {
		runs, err = runStore.ListStagedRuns0342(r.Context(), pkg)
		if err != nil {
			writeError(w, 503, "execution reports unavailable")
			return
		}
	}
	for i := range runs {
		var stages map[string]stagedStep0342
		if json.Unmarshal(runs[i].Stages, &stages) != nil {
			continue
		}
		for name, step := range stages {
			step.Detail = redactValidationDetail03412(step.Detail)
			stages[name] = step
		}
		runs[i].Stages, _ = json.Marshal(stages)
	}
	attestStore, ok := s.Repo.(validationAttestationRepository0345)
	if !ok {
		writeError(w, 503, "attestations unavailable")
		return
	}
	var attestations []model.ValidationAttestation0345
	if runQuery != "" {
		history, ok := s.Repo.(interface {
			GetValidationEvidence03412(context.Context, string, string) (model.ValidationAttestation0345, error)
		})
		if !ok {
			writeError(w, 503, "evidence history unavailable")
			return
		}
		value, getErr := history.GetValidationEvidence03412(r.Context(), pkg, runQuery)
		if getErr == nil {
			attestations = []model.ValidationAttestation0345{value}
		} else if getErr != repository.ErrNotFound {
			writeError(w, 503, "evidence history unavailable")
			return
		}
	} else {
		attestations, err = attestStore.ListValidationAttestations0345(r.Context(), pkg)
		if err != nil {
			writeError(w, 503, "attestations unavailable")
			return
		}
	}
	fresh, hasFresh := s.Repo.(validationFreshnessStore0346)
	byRun := make(map[string]model.StagedRuntimeRun0342, len(runs))
	for _, run := range runs {
		byRun[run.RunID] = run
	}
	runHistory, canLoadRun := s.Repo.(interface {
		GetValidationRun03412(context.Context, string, string) (model.StagedRuntimeRun0342, error)
	})
	evidence := make([]validationEvidenceSummary03412, 0, len(attestations))
	now := time.Now().UTC()
	for _, attestation := range attestations {
		summary := validationEvidenceSummary03412{RunID: attestation.RunID,
			EvidenceSHA256: digestValidationAttempt03412(attestation.Evidence), ReceivedAt: attestation.ReceivedAt, Status: "invalid"}
		var payload validationPayload0345
		if decodeStoredEvidence03411(attestation.Evidence, &payload) == nil {
			summary.TargetID = payload.TargetID
			summary.SchemaVersion = payload.SchemaVersion
			summary.ExpiresAt = payload.ExpiresAt
			// The recent-runs list is bounded; fetch exact historical runs
			// when independently checking older signed attestations.
			if _, found := byRun[payload.RunID]; !found && canLoadRun {
				if prior, e := runHistory.GetValidationRun03412(r.Context(), pkg, payload.RunID); e == nil {
					byRun[payload.RunID] = prior
				}
			}
			signed := signedValidation0345{Evidence: payload, Signature: attestation.Signature}
			if verifyValidation0345(signed, s.Config.ValidationAttestationPublicKey0345) == nil {
				md, me := manifestDigest0212(lookup.Release.Manifest)
				fd, fe := artifactDigest0212(lookup.Files)
				switch {
				case me != nil || fe != nil || payload.PackageID != pkg || payload.PackageVersion != lookup.Release.Version || payload.ManifestSHA256 != md || payload.ArtifactSHA256 != fd:
					summary.Status = "snapshot-mismatch"
				case !hasFresh:
					summary.Status = "unavailable"
				case validateFreshness0346(r.Context(), fresh, payload, now, false) != nil:
					summary.Status = "stale-or-revoked"
				case byRun[payload.RunID].RunID == "" || matchObservation0345(payload, byRun[payload.RunID]) != nil:
					summary.Status = "observation-mismatch"
				default:
					summary.Status = "signature-and-execution-verified"
				}
			}
		}
		evidence = append(evidence, summary)
	}
	coverage := stableCoverage03411{TargetCoverage: map[string]bool{}, TargetBlockers: map[string]string{}}
	if repository.IsStableChannel0341(lookup.Release.Channel) {
		coverage = s.evaluateStableRelease03411(r.Context(), lookup)
	}
	policyLevel := "trusted-runtime"
	if !repository.IsStableChannel0341(lookup.Release.Channel) {
		policyLevel = "integrity"
		if policy, e := s.Repo.GetProjectValidationPolicy(r.Context(), lookup.Release.ProjectID); e == nil {
			policyLevel = policy.RequiredLevel
		}
	}
	// Audit entries provide a replayable chronology, never an eligibility flag.
	// The only stable eligibility source is the live Backend runtime evaluator.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"packageId": pkg, "policy": map[string]any{"requiredLevel": policyLevel},
		"attempts": page, "nextBefore": next, "hasMore": more,
		"runs": runs, "evidence": evidence, "coverage": coverage,
		"manualCertificationAllowed": false,
	}})
}

func safeValidationDecisionDigest03412(value any) string {
	raw, _ := json.Marshal(value)
	return digestValidationAttempt03412(raw)
}

func validationDecisionReason03412(err error) string {
	if err == nil {
		return "unspecified"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "expired"), strings.Contains(msg, "freshness"), strings.Contains(msg, "time"):
		return "stale-evidence"
	case strings.Contains(msg, "signature"), strings.Contains(msg, "signer"), strings.Contains(msg, "key"):
		return "untrusted-signature"
	case strings.Contains(msg, "nonce"), strings.Contains(msg, "replay"), strings.Contains(msg, "already"):
		return "replay-or-challenge"
	case strings.Contains(msg, "target"), strings.Contains(msg, "preset"), strings.Contains(msg, "java"):
		return "target-mismatch"
	case strings.Contains(msg, "run"), strings.Contains(msg, "stage"), strings.Contains(msg, "execution"):
		return "execution-mismatch"
	default:
		return "validation-rejected"
	}
}
