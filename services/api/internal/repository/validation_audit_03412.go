package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func validValidationAttempt03412(e model.ValidationAttempt03412) bool {
	return strings.TrimSpace(e.PackageID) != "" && len(e.PackageID) <= 160 && len(e.RunID) <= 160 &&
		(e.Kind == "staged-report" || e.Kind == "attestation" || e.Kind == "stable-gate") &&
		(e.Outcome == "recorded" || e.Outcome == "accepted" || e.Outcome == "rejected" || e.Outcome == "blocked" || e.Outcome == "eligible") &&
		len(e.ReasonCode) > 0 && len(e.ReasonCode) <= 96 && isAuditReason03412(e.ReasonCode) && validHexAudit03412(e.PayloadSHA256)
}
func isAuditReason03412(v string) bool {
	for _, b := range []byte(v) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.') {
			return false
		}
	}
	return true
}
func validHexAudit03412(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, b := range []byte(v) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func (r *MemoryRepository) SaveValidationAttempt03412(_ context.Context, e model.ValidationAttempt03412) error {
	if !validValidationAttempt03412(e) {
		return errors.New("invalid validation attempt")
	}
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	e.ID = int64(len(r.validationAttempts03412) + 1)
	r.validationAttempts03412 = append(r.validationAttempts03412, e)
	return nil
}
func (r *MemoryRepository) ListValidationAttempts03412(_ context.Context, packageID string, before int64, limit int) ([]model.ValidationAttempt03412, error) {
	r.validationMu.Lock()
	defer r.validationMu.Unlock()
	out := make([]model.ValidationAttempt03412, 0)
	for i := len(r.validationAttempts03412) - 1; i >= 0; i-- {
		e := r.validationAttempts03412[i]
		if e.PackageID == packageID && (before == 0 || e.ID < before) {
			out = append(out, e)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
func (r *SQLRepository) SaveValidationAttempt03412(ctx context.Context, e model.ValidationAttempt03412) error {
	if err := r.check(); err != nil {
		return err
	}
	if !validValidationAttempt03412(e) {
		return errors.New("invalid validation attempt")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.db.QueryRowContext(ctx, `INSERT INTO validation_attempt_events_03412(package_id,run_id,kind,outcome,reason_code,payload_sha256) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, e.PackageID, e.RunID, e.Kind, e.Outcome, e.ReasonCode, e.PayloadSHA256).Scan(&e.ID)
}
func (r *SQLRepository) ListValidationAttempts03412(ctx context.Context, pkg string, before int64, limit int) ([]model.ValidationAttempt03412, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit < 1 || limit > 100 {
		return nil, errors.New("invalid audit page size")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,package_id,run_id,kind,outcome,reason_code,payload_sha256,created_at FROM validation_attempt_events_03412 WHERE package_id=$1 AND ($2::bigint=0 OR id<$2) ORDER BY id DESC LIMIT $3`, pkg, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.ValidationAttempt03412, 0)
	for rows.Next() {
		var e model.ValidationAttempt03412
		if err = rows.Scan(&e.ID, &e.PackageID, &e.RunID, &e.Kind, &e.Outcome, &e.ReasonCode, &e.PayloadSHA256, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
