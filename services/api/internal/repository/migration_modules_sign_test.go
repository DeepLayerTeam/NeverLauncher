package repository

import (
	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
	"testing"
)

func TestMigrationModulesSignGate0338(t *testing.T) {
	p := gc.Plan{SourceSHA256: "source", InventorySHA256: "manifest"}
	report := gm.Report{Format: gm.Format, SourceSHA256: "source", InventorySHA256: "manifest", Ready: true, Blockers: []string{}}
	if err := verifyModuleRelease0338(p, report); err != nil {
		t.Fatal(err)
	}
	report.Blockers = []string{"modules/auth.jar blocked"}
	report.Ready = false
	if err := verifyModuleRelease0338(p, report); err == nil {
		t.Fatal("unsafe module allowed to sign")
	}
	report.Blockers = nil
	report.Ready = true
	report.InventorySHA256 = "wrong"
	if err := verifyModuleRelease0338(p, report); err == nil {
		t.Fatal("source repin allowed to sign")
	}
}
