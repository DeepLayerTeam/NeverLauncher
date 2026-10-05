package main

import "testing"

func TestCanonicalAdminContributions0208(t *testing.T) {
	m := CanonicalExtensionManifest0201{SchemaVersion: "2.0", ID: "example.admin", Name: "Example", Version: "1.0.0", Publisher: "example", API: "3.7", Targets: []CanonicalExtensionTarget0201{{Kind: "admin", Entrypoint: "admin/index.html"}}, Permissions: []string{"ui:contribute"}, Admin: &CanonicalExtensionAdminContributions0208{Pages: []CanonicalExtensionAdminPage0208{{ID: "main", Title: "Main"}}, Navigation: []CanonicalExtensionAdminNavigation0208{{ID: "main-nav", Label: "Main", PageID: "main"}}}}
	got, _, err := normalizeCanonicalExtension0201(m)
	if err != nil {
		t.Fatal(err)
	}
	if got.Admin == nil || len(got.Admin.Navigation) != 1 {
		t.Fatalf("admin contributions lost: %#v", got.Admin)
	}
	m.Targets[0].Entrypoint = "admin/index.js"
	if _, _, err := normalizeCanonicalExtension0201(m); err == nil {
		t.Fatal("JS admin entrypoint accepted")
	}
}
