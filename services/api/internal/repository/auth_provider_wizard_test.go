package repository

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestManagedProviderRevisionsAndRollbacks02910(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryRepository("http://example.test")
	v := ManagedProviderRevision02910{ID: "company", Kind: "oidc", Config: []byte(`{"id":"company"}`), Reason: "Initial rollout", Actor: "admin"}
	if err := ValidateManagedProviderDraft02910(v); err != nil {
		t.Fatal(err)
	}
	first, err := r.SaveManagedProviderDraft02910(ctx, v)
	if err != nil || first.Revision != 1 {
		t.Fatalf("first revision: %+v %v", first, err)
	}
	second, err := r.SaveManagedProviderDraft02910(ctx, v)
	if err != nil || second.Revision != 2 {
		t.Fatalf("second revision: %+v %v", second, err)
	}
	if _, err = r.ActivateManagedProvider02910(ctx, "company", 1, 0, "admin", "Initial rollout"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ActivateManagedProvider02910(ctx, "company", 2, 0, "admin", "Stale writer"); !errors.Is(err, ErrManagedProviderConflict02910) {
		t.Fatalf("expected CAS conflict: %v", err)
	}
	if _, err = r.ActivateManagedProvider02910(ctx, "company", 2, 1, "admin", "Move to second"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ActivateManagedProvider02910(ctx, "company", 1, 2, "admin", "Rollback broken provider"); err != nil {
		t.Fatal(err)
	}
	active, err := r.ListActiveManagedProviders02910(ctx)
	if err != nil || len(active) != 1 || active[0].Revision != 1 {
		t.Fatalf("rollback runtime: %+v %v", active, err)
	}
	if _, err = r.ActivateManagedProvider02910(ctx, "company", 0, 1, "admin", "Disable provider"); err != nil {
		t.Fatal(err)
	}
	active, err = r.ListActiveManagedProviders02910(ctx)
	if err != nil || len(active) != 0 {
		t.Fatalf("provider remains active: %+v %v", active, err)
	}
}
func TestManagedProviderConcurrentCAS02910(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryRepository("http://example.test")
	for i := 0; i < 2; i++ {
		_, err := r.SaveManagedProviderDraft02910(ctx, ManagedProviderRevision02910{ID: "shared", Kind: "sql", Config: []byte(`{"id":"shared"}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	for i := int64(1); i <= 2; i++ {
		go func(rev int64) {
			defer wg.Done()
			_, err := r.ActivateManagedProvider02910(ctx, "shared", rev, 0, "admin", "test")
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrManagedProviderConflict02910):
			conflict++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("CAS outcomes: success=%d conflict=%d", success, conflict)
	}
}
func TestManagedProviderRejectsUnsafeMetadata02910(t *testing.T) {
	for _, v := range []ManagedProviderRevision02910{
		{ID: "local", Kind: "oidc", Config: []byte(`{}`), Reason: "valid reason"},
		{ID: "oidc", Kind: "password-fallback", Config: []byte(`{}`), Reason: "valid reason"},
		{ID: "oidc", Kind: "oidc", Config: []byte(`{"id":"x"}`), Reason: "X"},
		{ID: strings.Repeat("a", 65), Kind: "sql", Config: []byte(`{}`), Reason: "valid reason"},
	} {
		if err := ValidateManagedProviderDraft02910(v); err == nil {
			t.Fatalf("unsafe draft accepted: %+v", v)
		}
	}
}
