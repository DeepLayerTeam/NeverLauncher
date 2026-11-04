package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSignedGameReleaseGeneration02311(t *testing.T) {
	base := Manifest{SchemaVersion: "1.0", ProjectID: "p", ProfileID: "q", Channel: "stable", Version: "v2", GameReleaseGeneration: 9, Files: []ManifestFile{{Path: "mods/a.jar", SHA256: strings.Repeat("a", 64), Size: 12}}}
	prior := &GameRollbackSource02311{Version: "v1", GameReleaseGeneration: 8, ManifestSHA256: strings.Repeat("b", 64)}
	base.RollbackSource = prior
	if err := ValidateManifestSchema(base); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"gameReleaseGeneration":9`) || !strings.Contains(string(body), `"rollbackSource"`) {
		t.Fatalf("unsigned fields: %s", body)
	}
	old := base
	old.GameReleaseGeneration = 8
	if err := ValidateManifestSchema(old); err == nil {
		t.Fatal("rollback to same generation must fail")
	}
	old = base
	old.RollbackSource = &GameRollbackSource02311{Version: "v1", GameReleaseGeneration: 7, ManifestSHA256: "invalid"}
	if err := ValidateManifestSchema(old); err == nil {
		t.Fatal("invalid hash accepted")
	}
	legacy := base
	legacy.GameReleaseGeneration = 0
	legacy.RollbackSource = nil
	bytes, _ := json.Marshal(legacy)
	if strings.Contains(string(bytes), "gameReleaseGeneration") || strings.Contains(string(bytes), "rollbackSource") {
		t.Fatal("legacy signed payload compatibility lost")
	}
}
