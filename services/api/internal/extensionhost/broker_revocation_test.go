package extensionhost

import (
	"context"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestBrokerResponseRevocation04312(t *testing.T) {
	host, repo, st := liveTrustFixture04210(t)
	ctx := context.Background()
	req := capabilityRequest{Key: "sample"}
	if err := host.revalidateCapability04312(ctx, st, "runtime.storage.get", req); err != nil {
		t.Fatalf("initial grant denied: %v", err)
	}
	if err := repo.RevokeExtensionPermission(ctx, st.key.ExtensionID, "global", "", "storage:read"); err != nil {
		t.Fatal(err)
	}
	if err := host.revalidateCapability04312(ctx, st, "runtime.storage.get", req); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("result leaked after permission revocation: %v", err)
	}
	if err := host.revalidateCapability04312(ctx, st, "unknown.privilege", req); err == nil {
		t.Fatal("unknown capability was allowed")
	}
	if _, err := repo.SetExtensionEmergencyDisable(ctx, model.ExtensionEmergencyDisable{ExtensionID: st.key.ExtensionID, Scope: "global", Reason: "incident", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := host.revalidateCapability04312(ctx, st, "extension.self", req); err == nil {
		t.Fatal("metadata response permitted after emergency disable")
	}
}
