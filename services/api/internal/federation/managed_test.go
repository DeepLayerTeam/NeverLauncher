package federation

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"testing"
)

func TestManagedConnectorSwapAndRollback02910(t *testing.T) {
	core := New(repository.NewMemoryRepository("http://example.test"))
	if err := core.Register(fixtureConnector{}); err != nil {
		t.Fatal(err)
	}
	if err := core.SwapManaged(fixtureConnector{}, ProviderPolicy{}, 1); err == nil {
		t.Fatal("local provider replaced")
	}
	if err := core.Register(unlinkedConnector{}); err != nil {
		t.Fatal(err)
	}
	if err := core.SwapManaged(unlinkedConnector{}, ProviderPolicy{}, 2); err == nil {
		t.Fatal("bootstrap provider replaced")
	}
	if err := core.SwapManaged(jitFixtureConnector{}, ProviderPolicy{AutoProvision: true, DefaultRole: "nonexistent"}, 1); err == nil {
		t.Fatal("unknown role accepted")
	}
	if err := core.SwapManaged(jitFixtureConnector{}, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}, 1); err != nil {
		t.Fatal(err)
	}
	if rev := core.ManagedRevision("website"); rev != 1 {
		t.Fatal(rev)
	}
	if err := core.SwapManaged(jitFixtureConnector{}, ProviderPolicy{AutoProvision: true, DefaultRole: "player"}, 2); err != nil {
		t.Fatal(err)
	}
	if rev := core.ManagedRevision("website"); rev != 2 {
		t.Fatal(rev)
	}
	if err := core.DisableManaged("website"); err != nil {
		t.Fatal(err)
	}
	if _, ok := core.Connector("website"); ok {
		t.Fatal("disabled provider still registered")
	}
	if err := core.DisableManaged("external"); err == nil {
		t.Fatal("static provider disabled")
	}
}
