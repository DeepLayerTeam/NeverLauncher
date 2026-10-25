package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// Uses the real pgx PostgreSQL driver under CI, including transaction fencing.
func TestLiveManagedProviderCAS02910(t *testing.T) {
	dsn := os.Getenv("NEVERLAUNCHER_PROVIDER_WIZARD_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("configure test PostgreSQL DSN")
	}
	r := NewPostgresRepository(dsn, "https://launcher.example.test")
	store, ok := r.(ManagedProviderStore02910)
	if !ok {
		t.Fatal("repository has no managed provider store")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id := "wizard-test-02910"
	v, err := store.SaveManagedProviderDraft02910(ctx, ManagedProviderRevision02910{ID: id, Kind: "sql", Config: []byte(`{"id":"wizard-test-02910","dsnEnv":"TEST_PROVIDER_DSN"}`), Actor: "test", Reason: "Integration regression"})
	if err != nil {
		t.Fatal(err)
	}
	heads, err := store.ListManagedProviders02910(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var current int64
	for _, h := range heads {
		if h.ID == id {
			current = h.ActiveRevision
		}
	}
	if _, err = store.ActivateManagedProvider02910(ctx, id, v.Revision, current, "test", "Promote candidate"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActivateManagedProvider02910(ctx, id, 0, current, "test", "Stale revision"); !errors.Is(err, ErrManagedProviderConflict02910) {
		t.Fatalf("expected CAS conflict, got %v", err)
	}
	if _, err = store.ActivateManagedProvider02910(ctx, id, 0, v.Revision, "test", "Disable after test"); err != nil {
		t.Fatal(err)
	}
	active, err := r.(ActiveManagedProviderReader02910).ListActiveManagedProviders02910(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range active {
		if entry.ID == id {
			t.Fatal("test provider remains active")
		}
	}
}
