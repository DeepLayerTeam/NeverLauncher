package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func isDurableAction(s string) bool {
	switch s {
	case "job-enqueue", "job-get", "job-claim", "job-complete", "job-fail", "job-renew", "job-attempts",
		"scope-acquire", "scope-renew", "scope-release",
		"outbox-enqueue", "outbox-get", "outbox-claim", "outbox-complete", "outbox-fail", "outbox-renew":
		return true
	}
	return false
}

// Secrets (lease tokens) are supplied from a private 0600 input JSON file, not
// argv. Output containing a lease token must be redirected to a private file.
func runDurableAction(args []string) int {
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	db := flags.String("db", "", "existing SQLite DB")
	input := flags.String("input", "", "0600 JSON command input")
	timeout := flags.Duration("timeout", 20*time.Second, "operation timeout")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *db == "" || *input == "" || *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "--db and --input 0600 JSON are required")
		return 2
	}
	var req struct {
		Job          model.DurableJob           `json:"job"`
		Event        model.DurableOutboxEvent   `json:"event"`
		ID           string                     `json:"id"`
		Kind         string                     `json:"kind"`
		Worker       string                     `json:"worker"`
		Token        string                     `json:"token"`
		Owner        string                     `json:"owner"`
		Scope        string                     `json:"scope"`
		Fence        int64                      `json:"fence"`
		Status       string                     `json:"status"`
		Error        string                     `json:"error"`
		Result       json.RawMessage            `json:"result"`
		Limit        int                        `json:"limit"`
		TTLSeconds   int                        `json:"ttlSeconds"`
		RetrySeconds int                        `json:"retrySeconds"`
		Outbox       []model.DurableOutboxEvent `json:"outbox"`
	}
	if err := readPrivateJSON(*input, &req); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	r, err := sqlitecore.OpenExisting(ctx, sqlitedurable.Options{Path: *db})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer r.Close()
	ttl := time.Duration(req.TTLSeconds) * time.Second
	retry := time.Duration(req.RetrySeconds) * time.Second
	if req.TTLSeconds == 0 {
		ttl = 30 * time.Second
	}
	if req.Limit == 0 {
		req.Limit = 1
	}
	var output any
	switch action {
	case "job-enqueue":
		var j model.DurableJob
		var created bool
		j, created, err = r.EnqueueDurableJob(ctx, req.Job, 0)
		output = map[string]any{"job": j, "created": created}
	case "job-get":
		output, err = r.GetDurableJob(ctx, req.ID)
	case "job-attempts":
		output, err = r.ListOperationAttempts(ctx, req.ID)
	case "job-claim":
		output, err = r.LeaseDurableJobs(ctx, req.Kind, req.Worker, req.Limit, ttl)
	case "job-renew":
		output, err = r.RenewDurableJob(ctx, req.ID, req.Token, ttl)
	case "job-complete":
		output, err = r.CompleteJobWithOutbox(ctx, req.ID, req.Token, req.Result, req.Outbox)
	case "job-fail":
		output, err = r.FailDurableJob(ctx, req.ID, req.Token, req.Error, retry)
	case "scope-acquire":
		output, err = r.AcquireDurableScopeLease(ctx, req.Scope, req.Owner, ttl)
	case "scope-renew":
		output, err = r.RenewDurableScopeLease(ctx, req.Scope, req.Token, ttl)
	case "scope-release":
		err = r.ReleaseDurableScopeLease(ctx, req.Scope, req.Token)
		output = map[string]any{"released": err == nil}
	case "outbox-enqueue":
		var v model.DurableOutboxEvent
		var created bool
		v, created, err = r.EnqueueOutboxEvent(ctx, req.Event)
		output = map[string]any{"event": v, "created": created}
	case "outbox-get":
		output, err = r.GetOutboxEvent(ctx, req.ID)
	case "outbox-claim":
		output, err = r.ClaimOutboxEvents(ctx, req.Worker, req.Limit, ttl)
	case "outbox-renew":
		output, err = r.RenewOutboxEvent(ctx, req.ID, req.Token, ttl)
	case "outbox-complete":
		err = r.CompleteOutboxEvent(ctx, req.ID, req.Token)
		output = map[string]any{"completed": err == nil}
	case "outbox-fail":
		err = r.FailOutboxEvent(ctx, req.ID, req.Token, req.Error, retry)
		output = map[string]any{"failed": err == nil}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "durable operation failed closed:", err)
		return 1
	}
	if err = json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
