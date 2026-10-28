package gravitcutover

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestCutoverInputs03311(t *testing.T) {
	valid := Stage{ProfileID: "forge-1", Channel: "stable", ReleaseID: "never-release", ExpectedHeadRevision: 0, StageID: strings.Repeat("s", 20)}
	if e := ValidateStage(valid); e != nil {
		t.Fatal(e)
	}
	bad := valid
	bad.ProfileID = "../etc"
	if ValidateStage(bad) == nil {
		t.Fatal("unsafe profile allowed")
	}
	bad = valid
	bad.ExpectedHeadRevision = -1
	if ValidateStage(bad) == nil {
		t.Fatal("negative revision allowed")
	}
	act := Activate{ProfileID: "forge-1", Channel: "stable", ExpectedRevision: 1, SourceFenceReference: "ops/ticket-92342", SourceFenceEvidenceSHA256: strings.Repeat("a", 64), CurrentSourceSnapshotSHA256: strings.Repeat("b", 64)}
	if e := ValidateActivation(act); e != nil {
		t.Fatal(e)
	}
	act.SourceFenceEvidenceSHA256 = "invalid"
	if ValidateActivation(act) == nil {
		t.Fatal("unbound evidence allowed")
	}
}
func TestSignedReleaseMustMatchCurrentNeverKey03311(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	other, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	m := model.Manifest{SchemaVersion: "1.0", ProjectID: "project", ProfileID: "profile", Channel: "stable", Version: "v3", Files: []model.ManifestFile{}}
	if _, e = VerifyRelease(m, pub); e == nil {
		t.Fatal("unsigned release allowed")
	}
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	m.Signature = &model.SignatureInfo{Algorithm: "Ed25519", PublicKey: hex.EncodeToString(pub), Signature: hex.EncodeToString(ed25519.Sign(priv, raw))}
	digest, e := VerifyRelease(m, pub)
	if e != nil || len(digest) != 64 {
		t.Fatalf("signature rejected: %s %v", digest, e)
	}
	if _, e = VerifyRelease(m, other); e == nil {
		t.Fatal("foreign signer allowed")
	}
	m.Version = "v4"
	if _, e = VerifyRelease(m, pub); e == nil {
		t.Fatal("tampered manifest allowed")
	}
}
