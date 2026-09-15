package httpapi

import (
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestCompatibilityMetadataPathDefaultsToSignedVersionJSON(t *testing.T) {
	minecraft := model.MinecraftInfo{Version: "1.21.1", Loader: "vanilla"}
	runtime := model.RuntimeInfo{Launch: model.RuntimeLaunch{ClasspathStrategy: "compatibility"}}
	got, enabled, err := compatibilityMetadataPath(minecraft, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || got != "versions/1.21.1/1.21.1.json" {
		t.Fatalf("unexpected compatibility metadata result: enabled=%v path=%q", enabled, got)
	}
}

func TestCompatibilityMetadataPathRejectsTraversal(t *testing.T) {
	minecraft := model.MinecraftInfo{Version: "1.21.1", Loader: "vanilla"}
	runtime := model.RuntimeInfo{Launch: model.RuntimeLaunch{ClasspathStrategy: "compatibility", VersionMetadataPath: "../evil.json"}}
	if _, _, err := compatibilityMetadataPath(minecraft, runtime); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}

func TestCompatibilityManifestRequiresMetadataInsideSignedFiles(t *testing.T) {
	manifest := model.Manifest{
		Minecraft: model.MinecraftInfo{Version: "1.21.1", Loader: "vanilla"},
		Runtime:   model.RuntimeInfo{Launch: model.RuntimeLaunch{ClasspathStrategy: "compatibility"}},
		Files:     []model.ManifestFile{{Path: "versions/1.21.1/1.21.1.json", Required: true}},
	}
	if err := validateCompatibilityManifest(manifest); err != nil {
		t.Fatalf("signed metadata must be accepted: %v", err)
	}
	manifest.Files = []model.ManifestFile{{Path: "versions/1.21.1/1.21.1.jar", Required: true}}
	if err := validateCompatibilityManifest(manifest); err == nil {
		t.Fatal("publish must fail without signed version metadata")
	}
}
