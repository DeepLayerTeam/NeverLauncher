package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestAdminContributions0208RequireUIGrantAndStandaloneHTML(t *testing.T) {
	base := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.admin", Name: "Example Admin", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "admin", Entrypoint: "admin/index.html"}}, Permissions: []string{"ui:contribute"}, Admin: &model.ExtensionAdminContributions{Pages: []model.ExtensionAdminPage{{ID: "main", Title: "Main"}}, Navigation: []model.ExtensionAdminNavigation{{ID: "main-nav", Label: "Main", PageID: "main"}}, DashboardWidgets: []model.ExtensionAdminWidget{{ID: "summary", Title: "Summary", PageID: "main", Height: 320}}, Actions: []model.ExtensionAdminAction{{ID: "refresh", Label: "Refresh", PageID: "main", Placement: "toolbar"}}}}
	got, _, err := NormalizeExtensionManifest(base)
	if err != nil {
		t.Fatalf("Корректные расширения Admin отклонены: %v", err)
	}
	if got.Admin == nil || got.Admin.DashboardWidgets[0].Height != 320 {
		t.Fatalf("Потеряны расширения панели администратора: %#v", got.Admin)
	}
	bad := base
	bad.Permissions = []string{"project:read"}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("Ошибочно приняты расширения Admin без разрешения ui:contribute")
	}
	bad = base
	bad.Targets = []model.ExtensionTarget{{Kind: "admin", Entrypoint: "admin/index.js"}}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("Ошибочно принят исполняемый JS как точка входа Admin вместо самостоятельного HTML")
	}
	bad = base
	bad.Admin = &model.ExtensionAdminContributions{Pages: []model.ExtensionAdminPage{{ID: "main", Title: "Main"}}, Navigation: []model.ExtensionAdminNavigation{{ID: "bad-nav", Label: "Broken", PageID: "missing"}}}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("Навигация ошибочно приняла ссылку на отсутствующую страницу")
	}
}
