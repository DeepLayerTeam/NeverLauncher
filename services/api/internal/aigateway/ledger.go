package aigateway

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const LockDDL = `CREATE TABLE IF NOT EXISTS ai_budget_months (month TEXT PRIMARY KEY, serial BIGINT NOT NULL DEFAULT 0)`
const RequestDDL = `CREATE TABLE IF NOT EXISTS ai_requests (id TEXT PRIMARY KEY, month TEXT NOT NULL, user_id TEXT NOT NULL, model TEXT NOT NULL, started_at BIGINT NOT NULL, reserved_micro BIGINT NOT NULL CHECK(reserved_micro > 0), charged_micro BIGINT NOT NULL CHECK(charged_micro >= 0), input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0, state TEXT NOT NULL CHECK(state IN ('reserved','completed','incomplete','uncertain')), FOREIGN KEY(month) REFERENCES ai_budget_months(month))`
const IndexDDL = `CREATE INDEX IF NOT EXISTS ai_requests_month_user ON ai_requests(month,user_id,started_at)`
const RateIndexDDL = `CREATE INDEX IF NOT EXISTS ai_requests_user_started ON ai_requests(user_id,started_at)`

type Executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type Transaction func(context.Context, func(Executor) error) error

type Ledger struct{ Write, Read Transaction }
type Usage struct {
	Requests          int64 `json:"requests"`
	ChargedMicroUSD   int64 `json:"chargedMicroUsd"`
	UncertainRequests int64 `json:"uncertainRequests"`
	InputTokens       int64 `json:"inputTokens"`
	OutputTokens      int64 `json:"outputTokens"`
}
type Reservation struct {
	ID, User, Month, Model string
	Started                int64
	Amount                 int64
}

var ErrBudget = errors.New("AI budget exhausted")
var ErrRate = errors.New("AI request rate exceeded")

func NewSQLLedger(db *sql.DB) *Ledger {
	return &Ledger{Write: func(ctx context.Context, fn func(Executor) error) error {
		tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = fn(tx); e != nil {
			return e
		}
		return tx.Commit()
	}, Read: func(ctx context.Context, fn func(Executor) error) error { return fn(db) }}
}
func InitSchema(ctx context.Context, e Executor) error {
	for _, ddl := range []string{LockDDL, RequestDDL, IndexDDL, RateIndexDDL} {
		if _, err := e.ExecContext(ctx, ddl); err != nil {
			return err
		}
	}
	return nil
}
func monthLock(ctx context.Context, e Executor, month string) error {
	if _, err := e.ExecContext(ctx, `INSERT INTO ai_budget_months(month) VALUES($1) ON CONFLICT(month) DO NOTHING`, month); err != nil {
		return err
	}
	// Both PG row-level locks and SQLite BEGIN IMMEDIATE serialize reservations.
	_, err := e.ExecContext(ctx, `UPDATE ai_budget_months SET serial=serial WHERE month=$1`, month)
	return err
}
func (l *Ledger) Reserve(ctx context.Context, r Reservation, c Config) error {
	return l.Write(ctx, func(e Executor) error {
		// Lock previous month as well to serialize rolling rate across UTC midnight.
		previous := time.Unix(r.Started, 0).UTC().AddDate(0, 0, -1).Format("2006-01")
		if previous != r.Month {
			if err := monthLock(ctx, e, previous); err != nil {
				return err
			}
		}
		if err := monthLock(ctx, e, r.Month); err != nil {
			return err
		}
		var global, personal, recent int64
		if err := e.QueryRowContext(ctx, `SELECT COALESCE(SUM(charged_micro),0) FROM ai_requests WHERE month=$1`, r.Month).Scan(&global); err != nil {
			return err
		}
		if err := e.QueryRowContext(ctx, `SELECT COALESCE(SUM(charged_micro),0) FROM ai_requests WHERE month=$1 AND user_id=$2`, r.Month, r.User).Scan(&personal); err != nil {
			return err
		}
		if global > c.GlobalBudget-r.Amount || personal > c.UserBudget-r.Amount {
			return ErrBudget
		}
		if err := e.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_requests WHERE user_id=$1 AND started_at>$2`, r.User, r.Started-60).Scan(&recent); err != nil {
			return err
		}
		if recent >= c.UserRPM {
			return ErrRate
		}
		_, err := e.ExecContext(ctx, `INSERT INTO ai_requests(id,month,user_id,model,started_at,reserved_micro,charged_micro,state) VALUES($1,$2,$3,$4,$5,$6,$6,'reserved')`, r.ID, r.Month, r.User, r.Model, r.Started, r.Amount)
		return err
	})
}
func (l *Ledger) Finish(ctx context.Context, r Reservation, state string, input, output, charge int64) error {
	return l.Write(ctx, func(e Executor) error {
		if err := monthLock(ctx, e, r.Month); err != nil {
			return err
		}
		result, err := e.ExecContext(ctx, `UPDATE ai_requests SET state=$1,input_tokens=$2,output_tokens=$3,charged_micro=$4 WHERE id=$5 AND month=$6 AND state='reserved'`, state, input, output, charge, r.ID, r.Month)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("AI reservation is missing or settled")
		}
		return nil
	})
}
func (l *Ledger) Usage(ctx context.Context, month, user string) (u Usage, err error) {
	err = l.Read(ctx, func(e Executor) error {
		return e.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(charged_micro),0),COALESCE(SUM(CASE WHEN state IN ('reserved','uncertain') THEN 1 ELSE 0 END),0),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0) FROM ai_requests WHERE month=$1 AND ($2='' OR user_id=$2)`, month, user).Scan(&u.Requests, &u.ChargedMicroUSD, &u.UncertainRequests, &u.InputTokens, &u.OutputTokens)
	})
	return
}
