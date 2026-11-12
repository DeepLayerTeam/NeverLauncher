package gravitcutover

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestCutoverInputs03311(t *testing.T) {
	valid := Stage{ProfileID: "forge-1", Channel: "stable", ReleaseID: "release", ExpectedHeadRevision: 0, StageID: strings.Repeat("s", 20)}
	if e := ValidateStage(valid); e != nil {
		t.Fatal(e)
	}
	bad := valid
	bad.ProfileID = "../etc"
	if ValidateStage(bad) == nil {
		t.Fatal("Разрешён небезопасный профиль")
	}
	bad = valid
	bad.ExpectedHeadRevision = -1
	if ValidateStage(bad) == nil {
		t.Fatal("Разрешена отрицательная ревизия")
	}
	act := Activate{ProfileID: "forge-1", Channel: "stable", ExpectedRevision: 1, SourceFenceReference: "ops/ticket-92342", SourceFenceEvidenceSHA256: strings.Repeat("a", 64), CurrentSourceSnapshotSHA256: strings.Repeat("b", 64), SourceFenceReceipt: &SourceFenceReceipt0448{}}
	if e := ValidateActivation(act); e != nil {
		t.Fatal(e)
	}
	act.SourceFenceEvidenceSHA256 = "invalid"
	if ValidateActivation(act) == nil {
		t.Fatal("Разрешено неподвязанное свидетельство")
	}
}
func TestSignedReleaseMustMatchCurrentLauncherKey03311(t *testing.T) {
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
		t.Fatal("Разрешён неподписанный выпуск")
	}
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	m.Signature = &model.SignatureInfo{Algorithm: "Ed25519", PublicKey: hex.EncodeToString(pub), Signature: hex.EncodeToString(ed25519.Sign(priv, raw))}
	digest, e := VerifyRelease(m, pub)
	if e != nil || len(digest) != 64 {
		t.Fatalf("Подпись ошибочно отклонена: %s %v", digest, e)
	}
	if _, e = VerifyRelease(m, other); e == nil {
		t.Fatal("Разрешён посторонний подписант")
	}
	m.Version = "v4"
	if _, e = VerifyRelease(m, pub); e == nil {
		t.Fatal("Разрешён изменённый манифест")
	}
}

func TestVerifySourceFence0448(t *testing.T) {
	now := time.Now().UTC()
	route := Route{RunID: "run12345678", ProfileID: "client", Channel: "stable", StageID: "stage-12345678901234"}
	digest := strings.Repeat("b", 64)
	receipt := &SourceFenceReceipt0448{Format: "launcher/gravit-source-stop/v1", RunID: route.RunID, ProfileID: route.ProfileID, Channel: route.Channel, StageID: route.StageID, Unit: "gravit.service", StoppedAt: now.Add(-time.Minute), CheckedAt: now, UnitState: "inactive", UnitFileState: "masked-runtime", SnapshotSHA256: digest, SnapshotFileSHA256: strings.Repeat("c", 64)}
	makeInput := func() Activate {
		b, _ := json.Marshal(receipt)
		h := sha256.Sum256(b)
		return Activate{ProfileID: route.ProfileID, Channel: route.Channel, ExpectedRevision: 1, SourceFenceReference: "ops/receipt-001", SourceFenceEvidenceSHA256: hex.EncodeToString(h[:]), CurrentSourceSnapshotSHA256: digest, SourceFenceReceipt: receipt}
	}
	a := makeInput()
	if err := ValidateActivation(a); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceFence0448(a, route, now); err != nil {
		t.Fatal(err)
	}
	bad := a
	bad.SourceFenceEvidenceSHA256 = strings.Repeat("a", 64)
	if VerifySourceFence0448(bad, route, now) == nil {
		t.Fatal("Принята поддельная контрольная сумма")
	}
	route.StageID = "different-stage-12345"
	if VerifySourceFence0448(a, route, now) == nil {
		t.Fatal("Принята другая репетиция")
	}
	route.StageID = receipt.StageID
	if VerifySourceFence0448(a, route, now.Add(11*time.Minute)) == nil {
		t.Fatal("Принято устаревшее свидетельство")
	}
	proof := *receipt
	proof.UnitState = "active"
	a.SourceFenceReceipt = &proof
	if VerifySourceFence0448(a, route, now) == nil {
		t.Fatal("Разрешена активная служба записи")
	}
}
