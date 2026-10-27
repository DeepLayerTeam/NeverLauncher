package repository

import (
	"testing"

	gc "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitcontent"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestMigrationContentSigning0337(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p := gc.Plan{Ready: true, Profile: model.GravitImportResult02210{Profile: model.Profile{ID: "test"}}, Files: []gc.File{{TargetPath: "minecraft.jar", Size: 4, SHA256: hash, Ownership: "required"}}}
	f := model.ManifestFile{Path: "minecraft.jar", Size: 4, SHA256: hash, Required: true, Ownership: "required"}
	m := model.Manifest{ProfileID: "test", Files: []model.ManifestFile{f}}
	if e := checkMigrationContentSign0337(p, m); e != nil {
		t.Fatalf("verified files should pass: %v", e)
	}
	m.Files[0].SHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if e := checkMigrationContentSign0337(p, m); e == nil {
		t.Fatal("mutated file was allowed to sign")
	}
	m.Files[0].SHA256 = hash
	opt := model.GravitOptionalMigration02411{Ready: true, Catalog: model.NewComponentCatalog0241([]model.CatalogComponent0241{{ID: "mod", Name: "Mod", Files: []string{"minecraft.jar"}}}, 1)}
	p.Optional = &opt
	if e := checkMigrationContentSign0337(p, m); e == nil {
		t.Fatal("missing v3 optional catalog was allowed to sign")
	}
	catalog := opt.Catalog
	m.SchemaVersion = model.ManifestSchemaV3
	m.ComponentCatalog = &catalog
	if e := checkMigrationContentSign0337(p, m); e != nil {
		t.Fatalf("identical optional catalog should pass: %v", e)
	}
	catalog.Components[0].Files = []string{"unknown.jar"}
	if e := checkMigrationContentSign0337(p, m); e == nil {
		t.Fatal("mutated optional catalog was allowed to sign")
	}
}
