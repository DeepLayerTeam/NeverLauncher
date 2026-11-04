package sqlitepg

import (
	"context"
	"testing"
)

func TestBackendGate0475RequiresDatabase(t *testing.T) {
	if err := RejectUnapprovedBackend0475(context.Background(), ""); err == nil {
		t.Fatal("accepted empty DSN; gate did not fail closed")
	}
}
