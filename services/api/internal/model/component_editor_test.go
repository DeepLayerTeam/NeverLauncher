package model

import (
	"strings"
	"testing"
)

func TestAdminComponentGraphPreview0248(t *testing.T) {
	manifest := signedActionsFixture0245()
	ids, err := PreviewCatalogGraph0248(*manifest.ComponentCatalog, "quality")
	if err != nil || strings.Join(ids, ",") != "core,performance.sodium,shaders" {
		t.Fatalf("расчёт предварительного просмотра %v: %v", ids, err)
	}
	invalid := *manifest.ComponentCatalog
	invalid.Components = append([]CatalogComponent0241(nil), invalid.Components...)
	invalid.Components[2].Conflicts = []ComponentRequirement0243{{ID: "core"}}
	invalid = NewComponentCatalog0245(invalid, invalid.Revision+1)
	// Статический предпросмотр должен отклонять конфликтующий пресет, даже если
	// условные каталоги откладывают выбор под конкретную среду до нативного Runtime.
	if _, err = PreviewCatalogGraph0248(invalid, "quality"); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("Причина конфликта не объяснена: %v", err)
	}
	if _, err = PreviewCatalogGraph0248(invalid, "unknown"); err == nil {
		t.Fatal("Ошибочно принято отсутствие набора")
	}
}
