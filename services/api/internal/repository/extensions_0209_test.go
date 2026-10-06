package repository

import (
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"testing"
)

func TestDesktopAndCLIContributions0209AreCanonicalAndPermissionBound(t *testing.T) {
	manifest := model.ExtensionManifest{SchemaVersion: "2.0", ID: "example.multitarget", Name: "Multi", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []model.ExtensionTarget{{Kind: "cli", Entrypoint: "cli/bin/tool"}, {Kind: "desktop", Entrypoint: "desktop/index.html"}, {Kind: "backend", Entrypoint: "backend/bin/host"}, {Kind: "admin", Entrypoint: "admin/index.html"}}, Permissions: []string{"cli:contribute", "desktop:contribute", "desktop:bridge"}, Desktop: &model.ExtensionDesktopContributions{Pages: []model.ExtensionDesktopPage{{ID: "main", Title: "Main"}}, Navigation: []model.ExtensionDesktopNavigation{{ID: "main-nav", Label: "Main", PageID: "main"}}, Actions: []model.ExtensionDesktopAction{{ID: "open", Label: "Open", PageID: "main", Placement: "toolbar"}}}, CLI: &model.ExtensionCLIContributions{Namespace: "ops", Commands: []model.ExtensionCLICommand{{Name: "status", Description: "Status"}, {Name: "repair", Usage: "nl x ops repair"}}}}
	got, _, err := NormalizeExtensionManifest(manifest)
	if err != nil {
		t.Fatalf("valid multi-target manifest rejected: %v", err)
	}
	if len(got.Targets) != 4 || got.Targets[0].Kind != "admin" || got.Targets[3].Kind != "desktop" {
		t.Fatalf("targets not canonical: %#v", got.Targets)
	}
	if got.Desktop == nil || got.CLI == nil || got.CLI.Namespace != "ops" {
		t.Fatalf("contributions lost: %#v %#v", got.Desktop, got.CLI)
	}
	bad := manifest
	bad.Permissions = []string{"desktop:contribute"}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("CLI contributions accepted without cli:contribute")
	}
	bad = manifest
	bad.Targets = []model.ExtensionTarget{{Kind: "desktop", Entrypoint: "desktop/index.js"}}
	bad.CLI = nil
	bad.Permissions = []string{"desktop:contribute"}
	if _, _, err := NormalizeExtensionManifest(bad); err == nil {
		t.Fatal("Desktop contributions accepted without standalone HTML")
	}
}
