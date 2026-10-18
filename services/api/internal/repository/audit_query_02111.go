package repository

import (
	"context"
	"fmt"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"strings"
	"time"
)

type AuditQuery struct {
	Search        string
	Actor         string
	Action        string
	Target        string
	CorrelationID string
	ReasonCode    string
	JobID         string
	From          time.Time
	To            time.Time
	Limit         int
	Offset        int
}
type AuditQueryResult struct {
	Items  []model.AuditEvent `json:"items"`
	Total  int                `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}
type AuditQueryStore interface {
	QueryAudit(context.Context, AuditQuery) (AuditQueryResult, error)
}

func matchesAudit02111(e model.AuditEvent, q AuditQuery) bool {
	has := func(field, term string) bool { return strings.Contains(strings.ToLower(field), strings.ToLower(term)) }
	if q.Search != "" && !has(strings.Join([]string{e.ID, e.Actor, e.Action, e.Target, e.CorrelationID, e.ReasonCode, e.JobID}, " "), q.Search) {
		return false
	}
	if !has(e.Actor, q.Actor) || !has(e.Action, q.Action) || !has(e.Target, q.Target) || !has(e.CorrelationID, q.CorrelationID) || !has(e.ReasonCode, q.ReasonCode) || !has(e.JobID, q.JobID) {
		return false
	}
	if !q.From.IsZero() && e.CreatedAt.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && e.CreatedAt.After(q.To) {
		return false
	}
	return true
}
func (r *MemoryRepository) QueryAudit(_ context.Context, q AuditQuery) (AuditQueryResult, error) {
	items := r.ListAuditEvents()
	filtered := make([]model.AuditEvent, 0)
	for _, e := range items {
		if matchesAudit02111(e, q) {
			filtered = append(filtered, e)
		}
	}
	out := AuditQueryResult{Items: []model.AuditEvent{}, Total: len(filtered), Limit: q.Limit, Offset: q.Offset}
	if q.Offset < len(filtered) {
		end := q.Offset + q.Limit
		if end > len(filtered) {
			end = len(filtered)
		}
		out.Items = filtered[q.Offset:end]
	}
	return out, nil
}
func (r *SQLRepository) QueryAudit(ctx context.Context, q AuditQuery) (AuditQueryResult, error) {
	if err := r.check(); err != nil {
		return AuditQueryResult{}, err
	}
	// WHERE is parameterized; search input never enters SQL syntax.
	where := ` WHERE ($1='' OR actor ILIKE '%'||$1||'%') AND ($2='' OR action ILIKE '%'||$2||'%') AND ($3='' OR target ILIKE '%'||$3||'%') AND ($4='' OR correlation_id ILIKE '%'||$4||'%') AND ($5='' OR reason_code ILIKE '%'||$5||'%') AND ($6='' OR job_id ILIKE '%'||$6||'%') AND ($7::timestamptz IS NULL OR created_at >= $7) AND ($8::timestamptz IS NULL OR created_at <= $8) AND ($9='' OR concat_ws(' ',id,actor,action,target,correlation_id,reason_code,job_id) ILIKE '%'||$9||'%')`
	var from, to any
	if !q.From.IsZero() {
		from = q.From
	}
	if !q.To.IsZero() {
		to = q.To
	}
	args := []any{q.Actor, q.Action, q.Target, q.CorrelationID, q.ReasonCode, q.JobID, from, to, q.Search}
	var out AuditQueryResult
	out.Limit = q.Limit
	out.Offset = q.Offset
	out.Items = []model.AuditEvent{}
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`+where, args...).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id,actor,action,target,ip,user_agent,created_at,correlation_id,reason_code,job_id FROM audit_events`+where+` ORDER BY created_at DESC,id DESC LIMIT $10 OFFSET $11`, append(args, q.Limit, q.Offset)...)
	if err != nil {
		return out, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e model.AuditEvent
		err = rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.IP, &e.UserAgent, &e.CreatedAt, &e.CorrelationID, &e.ReasonCode, &e.JobID)
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, e)
	}
	return out, rows.Err()
}
