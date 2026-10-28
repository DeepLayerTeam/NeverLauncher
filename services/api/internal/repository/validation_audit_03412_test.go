package repository

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestV12AuditChronologyAndReplay03412(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryRepository("https://example.test")
	raw, _ := json.Marshal(map[string]any{"startup": map[string]any{"status": "failed", "detail": "--accessToken topsecret --username player@example.com"}})
	run := model.StagedRuntimeRun0342{RunID: "attempt-1", PackageID: "pkg", ProjectID: "project", ManifestSHA256: strings.Repeat("a", 64), ArtifactSHA256: strings.Repeat("b", 64), Stages: raw, StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now()}
	if err := r.SaveStagedRun0342(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveStagedRun0342(ctx, run); err == nil {
		t.Fatal("replay overwrote execution observation")
	}
	runs, err := r.ListStagedRuns0342(ctx, "pkg")
	if err != nil || len(runs) != 1 {
		t.Fatalf("run lost: %v", err)
	}
	if strings.Contains(string(runs[0].Stages), "topsecret") || strings.Contains(string(runs[0].Stages), "player@example.com") {
		t.Fatal("raw secrets persisted in execution stages")
	}
	if err := r.SaveValidationAttempt03412(ctx, model.ValidationAttempt03412{PackageID: "pkg", RunID: "attempt-1", Kind: "attestation", Outcome: "rejected", ReasonCode: "untrusted-signature", PayloadSHA256: strings.Repeat("f", 64)}); err != nil {
		t.Fatal(err)
	}
	events, err := r.ListValidationAttempts03412(ctx, "pkg", 0, 100)
	if err != nil || len(events) != 2 || events[0].Outcome != "rejected" || events[1].Outcome != "recorded" {
		t.Fatalf("append-only events wrong: %+v %v", events, err)
	}
	prior, err := r.ListValidationAttempts03412(ctx, "pkg", events[0].ID, 100)
	if err != nil || len(prior) != 1 || prior[0].ID != events[1].ID {
		t.Fatal("audit cursor is not stable")
	}
	if err := r.SaveValidationAttempt03412(ctx, model.ValidationAttempt03412{PackageID: "pkg", Kind: "stable-gate", Outcome: "eligible", ReasonCode: "secret token", PayloadSHA256: strings.Repeat("f", 64)}); err == nil {
		t.Fatal("arbitrary diagnostic accepted as audit reason")
	}
}
func TestV12ConcurrentAttemptAppendNoLoss03412(t *testing.T) {
	r := NewMemoryRepository("https://example.test")
	const workers = 40
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := r.SaveValidationAttempt03412(context.Background(), model.ValidationAttempt03412{PackageID: "pkg", Kind: "stable-gate", Outcome: "blocked", ReasonCode: "required-targets-incomplete", PayloadSHA256: strings.Repeat("0", 64)}); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	events, err := r.ListValidationAttempts03412(context.Background(), "pkg", 0, 100)
	if err != nil || len(events) != workers {
		t.Fatalf("lost events during race: %d %v", len(events), err)
	}
	for index, event := range events {
		if event.ID != int64(workers-index) {
			t.Fatal("non-monotonic audit sequence")
		}
	}
}
