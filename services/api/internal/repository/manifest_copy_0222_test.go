package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"testing"
)

func TestManifestCopiesDoNotAlias0222(t *testing.T) {
	snapshot := model.ProfileSnapshot{Revision: 1, Spec: model.ProfileSpec{Name: "original"}}
	signature := model.SignatureInfo{Algorithm: "Ed25519"}
	input := model.Manifest{ProfileSnapshot: &snapshot, Signature: &signature,
		Minecraft: model.MinecraftInfo{GameArgs: []string{"original"}},
		Runtime:   model.RuntimeInfo{JVMArgs: []string{"original"}, Launch: model.RuntimeLaunch{Features: map[string]bool{"safe": true}}},
		Files:     []model.ManifestFile{{Path: "original", TargetOS: []string{"linux"}}},
	}
	result := cloneManifest0222(input)
	result.ProfileSnapshot.Revision = 2
	result.Signature.Algorithm = "mutated"
	result.Minecraft.GameArgs[0] = "mutated"
	result.Runtime.JVMArgs[0] = "mutated"
	result.Runtime.Launch.Features["safe"] = false
	result.Files[0].Path = "mutated"
	result.Files[0].TargetOS[0] = "win"
	if input.ProfileSnapshot.Revision != 1 || input.Signature.Algorithm != "Ed25519" ||
		input.Minecraft.GameArgs[0] != "original" || input.Runtime.JVMArgs[0] != "original" ||
		!input.Runtime.Launch.Features["safe"] || input.Files[0].Path != "original" ||
		input.Files[0].TargetOS[0] != "linux" {
		t.Fatal("manifest clone leaked mutable aliases")
	}
}

func TestCloneManifestMirrors0234(t *testing.T) {
	in := model.Manifest{Files: []model.ManifestFile{{Path: "a.jar", Mirrors: []string{"https://one.test/a.jar"}}}}
	clone := cloneManifest0222(in)
	clone.Files[0].Mirrors[0] = "https://different.test/a.jar"
	if in.Files[0].Mirrors[0] != "https://one.test/a.jar" {
		t.Fatal("clone mutates signed source mirror list")
	}
}
