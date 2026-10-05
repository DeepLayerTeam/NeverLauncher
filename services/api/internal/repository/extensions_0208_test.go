package repository

import (
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"testing"
)

func TestAdminContributions0208RequireUIGrantAndStandaloneHTML(t *testing.T) {
	base := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.admin", Name: "Example Admin", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "admin", Entrypoint: "admin/index.html"}}, Permissions: []string{"ui:contribute"}, Admin: &model.ExtensionAdminContributions{Pages: []model.ExtensionAdminPage{{ID: "main", Title: "Main"}}, Navigation: []model.ExtensionAdminNavigation{{ID: "main-nav", Label: "Main", PageID: "main"}}, DashboardWidgets: []model.ExtensionAdminWidget{{ID: "summary", Title: "Summary", PageID: "main", Height: 320}}, Actions: []model.ExtensionAdminAction{{ID: "refresh", Label: "Refresh", PageID: "main", Placement: "toolbar"}}}}
	got, _, err := NormalizeExtensionManifest(base)
	if err != nil {
		t.Fatalf("valid admin contributions rejected: %v", err)
	}
	if got.Admin == nil || got.Admin.DashboardWidgets[0].Height != 320 {
		t.Fatalf("admin contributions lost: %#v", got.Admin)
	}
	bad := base
	bad.Permissions = []string{"project:read"}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("admin contributions accepted without ui:contribute")
	}
	bad = base
	bad.Targets = []model.ExtensionTarget{{Kind: "admin", Entrypoint: "admin/index.js"}}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("admin contributions accepted with executable JS entrypoint instead of standalone HTML")
	}
	bad = base
	bad.Admin = &model.ExtensionAdminContributions{Pages: []model.ExtensionAdminPage{{ID: "main", Title: "Main"}}, Navigation: []model.ExtensionAdminNavigation{{ID: "bad-nav", Label: "Broken", PageID: "missing"}}}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("navigation accepted reference to missing page")
	}
}
