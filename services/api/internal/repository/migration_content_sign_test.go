package repository

import (
	"testing"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestMigrationContentSigning0337(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p := gc.Plan{Ready: true, Profile: model.GravitImportResult02210{Profile: model.Profile{ID: "test"}}, Files: []gc.File{{TargetPath: "minecraft.jar", Size: 4, SHA256: hash, Ownership: "required"}}}
	f := model.ManifestFile{Path: "minecraft.jar", Size: 4, SHA256: hash, Required: true, Ownership: "required"}
	m := model.Manifest{ProfileID: "test", Files: []model.ManifestFile{f}}
	if e := checkMigrationContentSign0337(p, m); e != nil {
		t.Fatalf("Проверенные файлы должны проходить проверку: %v", e)
	}
	m.Files[0].SHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if e := checkMigrationContentSign0337(p, m); e == nil {
		t.Fatal("Разрешено подписать изменённый файл")
	}
	m.Files[0].SHA256 = hash
	opt := model.GravitOptionalMigration02411{Ready: true, Catalog: model.NewComponentCatalog0241([]model.CatalogComponent0241{{ID: "mod", Name: "Mod", Files: []string{"minecraft.jar"}}}, 1)}
	p.Optional = &opt
	if e := checkMigrationContentSign0337(p, m); e == nil {
		t.Fatal("Разрешено подписать пакет без дополнительного каталога v3")
	}
	catalog := opt.Catalog
	m.SchemaVersion = model.ManifestSchemaV3
	m.ComponentCatalog = &catalog
	if e := checkMigrationContentSign0337(p, m); e != nil {
		t.Fatalf("Идентичный дополнительный каталог должен проходить проверку: %v", e)
	}
	catalog.Components[0].Files = []string{"unknown.jar"}
	if e := checkMigrationContentSign0337(p, m); e == nil {
		t.Fatal("Разрешено подписать изменённый дополнительный каталог")
	}
}
