package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestV08PublishedPresetsAndCompatiblePairs0348(t *testing.T) {
	yes := true
	cat := model.NewComponentCatalog0243(model.ComponentCatalog0241{
		Components: []model.CatalogComponent0241{
			{ID: "core", Name: "Core", Version: "1.0.0", Files: []string{"mods/core.jar"}, Required: true, Visible: &yes},
			{ID: "alpha", Name: "Alpha", Version: "1.0.0", Files: []string{"mods/alpha.jar"}, Visible: &yes},
			{ID: "beta", Name: "Beta", Version: "1.0.0", Files: []string{"mods/beta.jar"}, Visible: &yes},
			{ID: "gamma", Name: "Gamma", Version: "1.0.0", Files: []string{"mods/gamma.jar"}, Visible: &yes},
		},
		Presets: []model.CatalogPreset0242{
			{ID: "minimal", Name: "Minimal", Components: []string{}},
			{ID: "alpha-only", Name: "Alpha", Components: []string{"alpha"}},
			{ID: "beta-only", Name: "Beta", Components: []string{"beta"}},
		}, DefaultPreset: "minimal",
	}, 1)
	selections, unchecked, err := RequiredMatrixSelections0348(&cat)
	if err != nil || unchecked != 0 || len(selections) != 6 {
		t.Fatalf("wrong cases: %v / %d / %v", selections, unchecked, err)
	}
	if !contains0348(selections, "minimal") || !contains0348(selections, "alpha-only") || !contains0348(selections, "beta-only") {
		t.Fatalf("published preset missing from runtime matrix: %v", selections)
	}
	if !contains0348(selections, "@custom:v1:minimal:+alpha,+beta") {
		t.Fatalf("compatible alpha+beta runtime case absent: %v", selections)
	}
	signed, _, _ := validValidationFixture0345(t)
	p := signed.Evidence
	release := model.ReleaseVersion{ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: p.PackageVersion}
	release.Manifest.SchemaVersion = "3.0"
	release.Manifest.ComponentCatalog = &cat
	target := testTarget0346(p)
	target.Preset = "minimal"
	raw, _ := json.Marshal([]validationTarget0346{target})
	if _, _, err = configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256); err == nil {
		t.Fatal("one default selection certified all published presets")
	}
	all := make([]validationTarget0346, 0, len(selections))
	for i, selection := range selections {
		item := target
		item.ID = "case-" + string(rune('a'+i))
		item.Preset = selection
		all = append(all, item)
	}
	raw, _ = json.Marshal(all)
	if _, _, err = configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256); err != nil {
		t.Fatalf("all exact preset and pair targets rejected: %v", err)
	}
	all[1].Preset = "minimal"
	raw, _ = json.Marshal(all)
	if _, _, err = configuredTargets0346(string(raw), release, p.ManifestSHA256, p.ArtifactSHA256); err == nil {
		t.Fatal("missing second published preset was silently accepted")
	}
}

func TestV08ConflictDoesNotGenerateFalseValidTarget0348(t *testing.T) {
	yes := true
	c := model.NewComponentCatalog0243(model.ComponentCatalog0241{
		Components: []model.CatalogComponent0241{
			{ID: "foo", Name: "Foo", Version: "1.0.0", Files: []string{"foo.jar"}, Visible: &yes,
				Conflicts: []model.ComponentRequirement0243{{ID: "bar"}}},
			{ID: "bar", Name: "Bar", Version: "1.0.0", Files: []string{"bar.jar"}, Visible: &yes},
		}, Presets: []model.CatalogPreset0242{{ID: "foo-only", Name: "Foo", Components: []string{"foo"}},
			{ID: "bar-only", Name: "Bar", Components: []string{"bar"}}}, DefaultPreset: "foo-only",
	}, 1)
	selections, _, err := RequiredMatrixSelections0348(&c)
	if err != nil || len(selections) != 2 {
		t.Fatalf("conflict accepted as runnable: %v %v", selections, err)
	}
}

func TestV08ConditionRequiresOSBranches0348(t *testing.T) {
	yes := true
	cat := model.NewComponentCatalog0244(model.ComponentCatalog0241{
		Components: []model.CatalogComponent0241{
			{ID: "platform", Name: "Platform", Version: "1.0.0", Files: []string{"mods/platform.jar"}, Visible: &yes,
				Conditions: &model.ComponentConditions0244{SchemaVersion: "1.0", OS: []string{"linux", "windows"}}},
		}, Presets: []model.CatalogPreset0242{{ID: "minimal", Name: "Minimal", Components: []string{}}}, DefaultPreset: "minimal",
	}, 1)
	signed, _, _ := validValidationFixture0345(t)
	p := signed.Evidence
	release := model.ReleaseVersion{ProjectID: "project-1", ProfileID: "profile-1", Channel: "stable", Version: p.PackageVersion}
	release.Manifest.SchemaVersion = "3.0"
	release.Manifest.ComponentCatalog = &cat
	target := testTarget0346(p)
	target.Preset = "minimal"
	if err := validateComponentMatrix0348(release.Manifest, []validationTarget0346{target}); err == nil || !strings.Contains(err.Error(), "required component runtime selection") {
		t.Fatalf("missing conditional target accepted: %v", err)
	}
}
