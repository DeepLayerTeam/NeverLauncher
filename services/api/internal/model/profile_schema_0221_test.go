package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileV2DeterministicSnapshots(t *testing.T) {
	p := Profile{ID: "forge", ProjectID: "demo", Name: "Forge", Description: "snapshot", Loader: "forge", Preset: "", Revision: 7}
	norm, err := NormalizeProfileV2(p)
	if err != nil {
		t.Fatal(err)
	}
	one := SnapshotProfile(norm)
	p.CreatedAt = p.CreatedAt.Add(12345)
	p.UpdatedAt = p.UpdatedAt.Add(12345)
	two := SnapshotProfile(p)
	if one.Digest != two.Digest || one.Revision != two.Revision {
		t.Fatalf("nondeterministic digest: %+v != %+v", one, two)
	}
	if err := ValidateProfileSnapshot(one, "demo", "forge"); err != nil {
		t.Fatal(err)
	}
	two.Spec.Loader = "fabric"
	if err := ValidateProfileSnapshot(two, "demo", "forge"); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
	if _, err := NormalizeProfileV2(Profile{ID: "evil\x00id", ProjectID: "p", Name: "n"}); err == nil {
		t.Fatal("NUL accepted")
	}
	if _, err := NormalizeProfileV2(Profile{ID: "p", ProjectID: "p", Name: "n", SchemaVersion: "3.0"}); err == nil {
		t.Fatal("future schema accepted")
	}
}

func TestManifestV1UnchangedAndV2Payload(t *testing.T) {
	v1 := Manifest{SchemaVersion: "1.0", ProjectID: "demo", ProfileID: "forge", Channel: "stable", Version: "1", CreatedAt: "2026-10-18T00:00:00Z", Files: []ManifestFile{}}
	old, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(old), "profileSnapshot") {
		t.Fatal("v1 payload changed")
	}
	if err := ValidateManifestSchema(v1); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, old)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), old, sig) {
		t.Fatal("v1 signature invalid")
	}
	v1.ProfileSnapshot = &ProfileSnapshot{}
	if err := ValidateManifestSchema(v1); err == nil {
		t.Fatal("v1 snapshot accepted")
	}
	v1.SchemaVersion = "2.0"
	if err := ValidateManifestSchema(v1); err == nil {
		t.Fatal("bad v2 snapshot accepted")
	}
	p, _ := NormalizeProfileV2(Profile{ID: "forge", ProjectID: "demo", Name: "Forge", Loader: "forge", Revision: 3})
	shot := SnapshotProfile(p)
	v1.ProfileSnapshot = &shot
	if err := ValidateManifestSchema(v1); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if len(hex.EncodeToString(digest[:])) != 64 || !strings.Contains(string(payload), `"profileSnapshot"`) {
		t.Fatal("v2 snapshot not signed")
	}
}
