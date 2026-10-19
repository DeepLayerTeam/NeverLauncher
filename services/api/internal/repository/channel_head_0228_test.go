package repository

import (
	"context"
	"errors"
	"testing"
)

func TestChannelHeadCASPublishAndRead0228(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	ctx := context.Background()
	empty, err := r.GetChannelHead(ctx, "demo-project", "vanilla", "dev")
	if err != nil || empty.Revision != 0 || empty.ReleaseID != "" {
		t.Fatalf("initial head: %+v %v", empty, err)
	}
	first, err := r.CreateVersion("demo-project", "vanilla", "dev", "0228-v1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.CreateVersion("demo-project", "vanilla", "dev", "0228-v2")
	if err != nil {
		t.Fatal(err)
	}
	published, err := r.PublishVersionWithManifestCAS(first.ProjectID, first.ProfileID, first.Channel, first.Version, first.Manifest, 0)
	if err != nil || published.Status != "published" {
		t.Fatalf("initial publish %+v %v", published, err)
	}
	h, err := r.GetChannelHead(ctx, "demo-project", "vanilla", "dev")
	if err != nil || h.Revision != 1 || h.ReleaseID != first.ID {
		t.Fatalf("head not promoted %+v %v", h, err)
	}
	if _, err := r.PublishVersionWithManifestCAS(second.ProjectID, second.ProfileID, second.Channel, second.Version, second.Manifest, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale publish must fail: %v", err)
	}
	current, err := r.GetManifest("demo-project", "vanilla", "dev")
	if err != nil || current.Version != first.Version {
		t.Fatalf("stale publish leaked: %s %v", current.Version, err)
	}
	if _, err := r.PublishVersionWithManifestCAS(second.ProjectID, second.ProfileID, second.Channel, second.Version, second.Manifest, 1); err != nil {
		t.Fatal(err)
	}
	h, err = r.GetChannelHead(ctx, "demo-project", "vanilla", "dev")
	if err != nil || h.Revision != 2 || h.ReleaseID != second.ID {
		t.Fatalf("head not advanced %+v %v", h, err)
	}
	current, err = r.GetManifest("demo-project", "vanilla", "dev")
	if err != nil || current.Version != second.Version {
		t.Fatalf("channel read not pinned: %s %v", current.Version, err)
	}
}

func TestChannelHeadsProfileIsolated0228(t *testing.T) {
	r := NewMemoryRepository("http://127.0.0.1")
	h, err := r.GetChannelHead(context.Background(), "demo-project", "vanilla", "stable")
	if err != nil || h.Revision != 1 || h.Version != "3.4.0" {
		t.Fatalf("bootstrapped stable head: %+v %v", h, err)
	}
	empty, err := r.GetChannelHead(context.Background(), "demo-project", "fabric", "stable")
	if err != nil || empty.Revision != 0 {
		t.Fatalf("other profile inherited head: %+v %v", empty, err)
	}
}
