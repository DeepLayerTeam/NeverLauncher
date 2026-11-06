package httpapi

import (
	"encoding/json"
	"os"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestPublicationCandidate0526UsesActualUploadedBytesAndGraph(t *testing.T) {
	raw, err := os.ReadFile("../../../../runtime/runtime/tests/fixtures/catalog_manifest_v3_go_signed_0242.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest model.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	uploaded := make([]model.FileObject, 0, len(manifest.Files))
	for _, f := range manifest.Files {
		uploaded = append(uploaded, model.FileObject{
			ProjectID: manifest.ProjectID, Path: f.Path, SHA256: f.SHA256,
			Size: f.Size, URL: f.URL, Required: f.Required, Ownership: f.Ownership,
		})
	}
	lookup := packageLookup{Release: model.ReleaseVersion{Manifest: manifest}, Files: uploaded}
	candidate := storageBackedCandidate0526(lookup)
	if len(candidate.Files) != len(uploaded) {
		t.Fatal("Кандидат проигнорировал загруженные файлы")
	}
	if candidate.Files[0].SHA256 != uploaded[0].SHA256 {
		t.Fatal("Неверный дайджест загруженного файла")
	}
	if len(manifest.Files) != len(uploaded) {
		t.Fatal("Исходный подписанный манифест изменён")
	}
	if err := validatePackageCandidate0526(lookup); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}

	// Удаление принадлежащего пакету необязательного JAR должно нарушить проверку
	// графа, даже если старая предварительная проверка принимала совпадающее
	// пустое подмножество объектов хранилища.
	without := lookup
	without.Files = uploaded[1:]
	if err := validatePackageCandidate0526(without); err == nil {
		t.Fatal("Предпубликационная проверка приняла отсутствие подписанного мода")
	}

	// Неверное владение также должно отклоняться до подписи манифеста.
	tampered := lookup
	tampered.Files = append([]model.FileObject(nil), uploaded...)
	tampered.Files[0].Ownership = "required"
	tampered.Files[0].Required = true
	if err := validatePackageCandidate0526(tampered); err == nil {
		t.Fatal("Обязательная принадлежность скрытно добавлена в граф необязательных компонентов")
	}
}
