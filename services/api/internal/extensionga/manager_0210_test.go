package extensionga

import (
	"context"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensioncontract"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
)

func TestValidateEmptyRepository0210(t *testing.T) {
	repo := repository.NewMemoryRepository("")
	m := New(t.TempDir(), 2, repo, storage.NewLocalStorage(t.TempDir()))
	report, err := m.Validate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 0 || report.Healthy != 0 || len(report.Issues) != 0 {
		t.Fatalf("unexpected empty report: %+v", report)
	}
	if report.Contract.ExtensionAPIVersion != extensioncontract.ExtensionAPIVersion {
		t.Fatalf("contract API=%q", report.Contract.ExtensionAPIVersion)
	}
}
