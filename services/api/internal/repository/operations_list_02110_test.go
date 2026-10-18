package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestListProjectOperations02110IsolationPaginationAndStatus(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository("https://example.invalid")
	for i := 0; i < 7; i++ {
		project := "alpha"
		if i == 6 {
			project = "beta"
		}
		if _, _, err := repo.EnqueueDurableJob(ctx, model.DurableJob{
			Kind: "package-publish", ActorType: "user", ActorID: "owner", Action: "release:publish",
			ProjectID: project, ResourceType: "package", ResourceID: fmt.Sprintf("pkg-%d", i),
			IdempotencyKey: fmt.Sprintf("req-%d", i),
		}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	one, err := repo.ListProjectOperations(ctx, "alpha", "", 2, 0)
	if err != nil || len(one) != 2 {
		t.Fatalf("first page %#v: %v", one, err)
	}
	two, err := repo.ListProjectOperations(ctx, "alpha", "", 2, 2)
	if err != nil || len(two) != 2 {
		t.Fatalf("second page %#v: %v", two, err)
	}
	if one[0].ID == two[0].ID {
		t.Fatal("pagination duplicates entries")
	}
	for _, j := range append(one, two...) {
		if j.ProjectID != "alpha" {
			t.Fatal("other project leaked")
		}
	}
	none, err := repo.ListProjectOperations(ctx, "alpha", "succeeded", 10, 0)
	if err != nil || len(none) != 0 {
		t.Fatalf("unexpected succeeded jobs: %+v %v", none, err)
	}
	other, err := repo.ListProjectOperations(ctx, "beta", "", 10, 0)
	if err != nil || len(other) != 1 {
		t.Fatalf("beta jobs: %+v %v", other, err)
	}
}
