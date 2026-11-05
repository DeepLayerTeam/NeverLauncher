// Package gravitrollback реализует согласование MIG12 с отказом при ошибке. Он не
// импортирует и не перезаписывает миры Minecraft, плагины SQL или базы Gravit.
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

	gr "gitflic.ru/skif4er/launcher/services/api/internal/gravitrehearsal"
)

const Format = "never/gravit-rollback/v1"

var sha = regexp.MustCompile(`^[a-f0-9]{64}$`)
var id = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)

type PlanInput struct {
	ProfileID        string `json:"profileId"`
	Channel          string `json:"channel"`
	ExpectedRevision int64  `json:"expectedRevision"`
	// Этот снимок ОБЯЗАТЕЛЬНО собирается после внешнего разграничения
	// промышленных записывающих процессов; сам по себе он не доказывает их
	// остановку.
	Current           gr.Snapshot `json:"current"`
	EvidenceReference string      `json:"evidenceReference"`
	EvidenceSHA256    string      `json:"evidenceSha256"`
	// Требуется только при расхождении состояния Never с MIG10. Оператор обязан
	// СНАЧАЛА согласовать изменённые данные с изолированным назначением Gravit.
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
	// Свежий независимо экспортированный снимок, полученный непосредственно перед
	// фиксацией.
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
		return errors.New("Некорректное значение: «rollback scope, revision or evidence»")
	}
	return nil
}
func ValidateCommit(c CommitInput) error {
	if !id.MatchString(c.ProfileID) || !id.MatchString(c.Channel) || c.ExpectedRevision < 1 || !sha.MatchString(c.PlanSHA256) || !c.SourceWriterFenced || !c.NeverWriterFenced || !sha.MatchString(c.CurrentEvidenceSHA256) {
		return errors.New("Для «rollback commit» требуется «matching plan and both independently fenced writers»")
	}
	return nil
}

// Compare использует ту же доменную семантическую проверку, что MIG10. Она
// обнаруживает UUID игроков, инвентарь, права, экономику, текстуры, миры, загрузчики
// и необязательные компоненты даже при разном порядке JSON или форматировании.
// Изменения состояния не теряются.
func Compare(input PlanInput, rehearsal gr.Report, runID string) (Result, error) {
	if err := ValidatePlan(input); err != nil {
		return Result{}, err
	}
	checked, err := gr.Evaluate(rehearsal)
	if err != nil || !checked.Ready || checked.RunID != runID {
		return Result{}, errors.New("Требуется: «verified MIG10 baseline»")
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
		return Result{}, fmt.Errorf("Некорректное значение: «current snapshot»: %w", err)
	}
	blockers := append([]string{}, compared.Blockers...)
	// Количество и идентичности источника должны сохраняться. Новые игроки после
	// переключения допустимы только при достоверном представлении на ОБЕИХ
	// сторонах.
	if len(input.Current.Players) != len(rehearsal.Target.Players) {
		blockers = append(blockers, "player population changed")
	}
	mode := "unchanged"
	sourceDigest := ""
	if len(blockers) > 0 && input.ReconciledSource != nil {
		if !sha.MatchString(input.ReconciliationEvidenceSHA256) {
			return Result{}, errors.New("Требуется: «reconciliation evidence SHA-256»")
		}
		sourceDigest, err = gr.SnapshotDigest(*input.ReconciledSource)
		if err != nil {
			return Result{}, err
		}
		// Never → внешне согласованный Gravit, при изоляции всех живых записывающих
		// процессов.
		pair := rehearsal
		pair.Source = *input.ReconciledSource
		pair.Target = input.Current
		pair.SourceSnapshotSHA256 = sourceDigest
		pair.TargetSnapshotSHA256 = currentDigest
		verified, e := gr.Evaluate(pair)
		if e != nil {
			return Result{}, fmt.Errorf("Некорректное значение: «reconciled source snapshot»: %w", e)
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
	// Хеш плана связывает точные доказательства повторного объединения полномочий
	// с источником.
	raw, _ := json.Marshal(struct {
		Format, RunID, ProfileID, Channel, Mode                                                string
		Revision                                                                               int64
		Baseline, Current, EvidenceRef, EvidenceHash, ReconciledSource, ReconciliationEvidence string
	}{Format, runID, input.ProfileID, input.Channel, mode, input.ExpectedRevision, b, currentDigest, input.EvidenceReference, input.EvidenceSHA256, sourceDigest, input.ReconciliationEvidenceSHA256})
	sum := sha256.Sum256(raw)
	result.PlanSHA256 = hex.EncodeToString(sum[:])
	return result, nil
}

// ValidSHA256 проверяет метаданные хеша доказательств, хранящихся отдельно.
func ValidSHA256(v string) bool { return sha.MatchString(v) }
