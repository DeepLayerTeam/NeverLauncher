package repository

import (
	"context"

	"gitflic.ru/skif4er/launcher/services/api/internal/aigateway"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func (r *SQLRepository) AILedger(ctx context.Context) (*aigateway.Ledger, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	l := aigateway.NewSQLLedger(r.db)
	_, err := l.Usage(ctx, "2000-01", "") // Fail closed if the migration is missing.
	if err != nil {
		return nil, err
	}
	return l, nil
}
func (r *SQLiteHTTPRepository0372) AILedger(ctx context.Context) (*aigateway.Ledger, error) {
	wrap := func(f func(context.Context, func(sqlitedurable.Executor) error) error) aigateway.Transaction {
		return func(ctx context.Context, fn func(aigateway.Executor) error) error {
			return f(ctx, func(e sqlitedurable.Executor) error { return fn(e) })
		}
	}
	l := &aigateway.Ledger{Write: wrap(r.store.Write), Read: wrap(r.store.Read)}
	if err := l.Write(ctx, func(e aigateway.Executor) error { return aigateway.InitSchema(ctx, e) }); err != nil {
		return nil, err
	}
	return l, nil
}
