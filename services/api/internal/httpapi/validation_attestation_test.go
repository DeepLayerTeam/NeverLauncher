package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func validValidationFixture0345(t *testing.T) (signedValidation0345, ed25519.PrivateKey, string) {
	t.Helper()
	key, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	end := time.Now().UTC().Format(time.RFC3339Nano)
	p := validationPayload0345{SchemaVersion: validationSchema0345, RunNonce: strings.Repeat("7", 64), Audience: validationAudience0346, Purpose: validationPurpose0346, TargetID: "linux-default", TargetMatrixSHA256: strings.Repeat("6", 64), PackageVersion: "0.34.6", IssuedAt: time.Now().UTC().Add(-3 * time.Minute).Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(23 * time.Hour).Format(time.RFC3339Nano), RunID: "run_0345", PackageID: "pkg0345",
		ManifestSHA256: strings.Repeat("a", 64), ArtifactSHA256: strings.Repeat("b", 64),
		ResolvedPlanSHA256: strings.Repeat("c", 64), SourceSHA: strings.Repeat("d", 40), BuildSHA: strings.Repeat("e", 64),
		RunnerImageSHA256: strings.Repeat("f", 64), JavaSHA256: strings.Repeat("1", 64), JavaVersion: "21.0.7", OS: "linux", Arch: "amd64",
		Loader: "vanilla", InstallAdapterSHA256: strings.Repeat("2", 64), GuardMode: "disabled",
		GuardPolicySHA256: strings.Repeat("3", 64), ServerBridgeSHA256: strings.Repeat("0", 64), ServerPluginVersion: "none", Preset: "default", AuthenticationMode: "official",
		Stages: map[string]string{}, ArtifactHashes: map[string]string{}, StartedAt: start, FinishedAt: end}
	for _, stage := range mandatoryStages0345 {
		p.Stages[stage] = "passed"
	}
	for _, name := range []string{"staged-execution.json", "verified.json", "startup-readiness.json", "server-readiness.json", "gameplay-smoke.json", "authentication.json", "runtime-launch.json", "runtime-gameplay-launch.json", "execution-identity.json", "update-recovery.json"} {
		p.ArtifactHashes[name] = strings.Repeat("8", 64)
	}
	fingerprint := sha256.Sum256(key)
	p.SignerKeyID = hex.EncodeToString(fingerprint[:])
	signed := signedValidation0345{Evidence: p}
	signFixture0345(t, &signed, private)
	return signed, private, base64.RawURLEncoding.EncodeToString(key)
}
func signFixture0345(t *testing.T, signed *signedValidation0345, key ed25519.PrivateKey) {
	t.Helper()
	raw, e := json.Marshal(signed.Evidence)
	if e != nil {
		t.Fatal(e)
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(validationDomain0345), raw...)))
}
func TestTrustedAttestationSignatures0345(t *testing.T) {
	signed, priv, pub := validValidationFixture0345(t)
	if e := verifyValidation0345(signed, pub); e != nil {
		t.Fatal(e)
	}
	signed.Evidence.JavaSHA256 = strings.Repeat("4", 64)
	if e := verifyValidation0345(signed, pub); e == nil {
		t.Fatal("принята подменённая идентичность исполнителя")
	}
	signFixture0345(t, &signed, priv)
	if e := verifyValidation0345(signed, pub); e != nil {
		t.Fatal(e)
	}
	_, _, wrong := validValidationFixture0345(t)
	if e := verifyValidation0345(signed, wrong); e == nil {
		t.Fatal("принят произвольный JSON, подписанный ключом CI")
	}
	if e := verifyValidation0345(signed, ""); e == nil {
		t.Fatal("допущено отсутствие доверенного ключа оператора")
	}
	signed.Evidence.Stages["gameplay-smoke"] = "failed"
	signFixture0345(t, &signed, priv)
	if e := verifyValidation0345(signed, pub); e == nil {
		t.Fatal("приняты свидетельства неудачного игрового процесса с действительной подписью")
	}
	delete(signed.Evidence.Stages, "gameplay-smoke")
	signFixture0345(t, &signed, priv)
	if e := verifyValidation0345(signed, pub); e == nil {
		t.Fatal("допущено отсутствие игрового процесса при действительной подписи")
	}
}
func TestV09UpdateRecoveryCannotBeOmittedOrFaked0349(t *testing.T) {
	signed, priv, pub := validValidationFixture0345(t)
	if err := verifyValidation0345(signed, pub); err != nil {
		t.Fatal(err)
	}
	delete(signed.Evidence.Stages, "update-recovery")
	signFixture0345(t, &signed, priv)
	if err := verifyValidation0345(signed, pub); err == nil {
		t.Fatal("допущено отсутствие свидетельств жизненного цикла")
	}
	signed.Evidence.Stages["update-recovery"] = "failed"
	signFixture0345(t, &signed, priv)
	if err := verifyValidation0345(signed, pub); err == nil {
		t.Fatal("принят неработающий настоящий механизм обновления")
	}
	signed.Evidence.Stages["update-recovery"] = "passed"
	delete(signed.Evidence.ArtifactHashes, "update-recovery.json")
	signFixture0345(t, &signed, priv)
	if err := verifyValidation0345(signed, pub); err == nil {
		t.Fatal("допущено отсутствие артефакта обновления")
	}
}

func TestTrustedAttestationMatchesPersistedRun0345(t *testing.T) {
	signed, _, _ := validValidationFixture0345(t)
	stageRecord := map[string]stagedStep0342{}
	for _, stage := range mandatoryStages0345 {
		s := stagedStep0342{Status: "passed"}
		if file, ok := stageArtifacts0345[stage]; ok {
			s.EvidenceSHA256 = signed.Evidence.ArtifactHashes[file]
		}
		stageRecord[stage] = s
	}
	raw, _ := json.Marshal(stageRecord)
	start, _ := time.Parse(time.RFC3339Nano, signed.Evidence.StartedAt)
	end, _ := time.Parse(time.RFC3339Nano, signed.Evidence.FinishedAt)
	run := model.StagedRuntimeRun0342{RunID: signed.Evidence.RunID, PackageID: signed.Evidence.PackageID,
		ManifestSHA256: signed.Evidence.ManifestSHA256, ArtifactSHA256: signed.Evidence.ArtifactSHA256,
		Stages: raw, StartedAt: start, FinishedAt: end}
	if e := matchObservation0345(signed.Evidence, run); e != nil {
		t.Fatal(e)
	}
	signed.Evidence.Preset = "other"
	// V05 обязан выводить применимость пресетов из политики: в V04 подписанный
	// пресет связан с неизменяемым свидетельством, но ещё не с вычисленной из
	// политики матрицей целей.
	signed.Evidence.RunID = "other-run"
	if e := matchObservation0345(signed.Evidence, run); e == nil {
		t.Fatal("Аттестация из другого запуска ошибочно принята")
	}
	signed.Evidence.RunID = run.RunID
	stageRecord["gameplay-smoke"] = stagedStep0342{Status: "passed", EvidenceSHA256: strings.Repeat("9", 64)}
	run.Stages, _ = json.Marshal(stageRecord)
	if e := matchObservation0345(signed.Evidence, run); e == nil {
		t.Fatal("принят поддельный хеш артефакта игрового процесса")
	}
}
func TestAttestationRepositoryImmutable0345(t *testing.T) {
	r := repository.NewMemoryRepository("https://example.test")
	v := model.ValidationAttestation0345{RunID: "run1", PackageID: "pkg", ProjectID: "project",
		ManifestSHA256: strings.Repeat("a", 64), ArtifactSHA256: strings.Repeat("b", 64), Evidence: json.RawMessage(`{"v":2}`),
		Signature: strings.Repeat("A", 86), ReceivedAt: time.Now()}
	if e := r.SaveValidationAttestation0345(context.Background(), v); e != nil {
		t.Fatal(e)
	}
	if e := r.SaveValidationAttestation0345(context.Background(), v); e == nil {
		t.Fatal("повторная аттестация перезаписала прежнюю")
	}
	rows, e := r.ListValidationAttestations0345(context.Background(), "pkg")
	if e != nil || len(rows) != 1 {
		t.Fatalf("аттестация не сохранена: %v %v", rows, e)
	}
}

func TestV14SignedAttestationRejectsMissingAdversarialGame03414(t *testing.T) {
	signed, private, pub := validValidationFixture0345(t)
	signed.Evidence.PackageVersion = "0.43.14"
	signFixture0345(t, &signed, private)
	if err := verifyValidation0345(signed, pub); err == nil {
		t.Fatal("версия 0.43.14 не должна подтверждать успешный игровой процесс без испытаний на противодействие обходам")
	}
	signed.Evidence.ArtifactHashes["adversarial-gameplay-04314.json"] = strings.Repeat("a", 64)
	signFixture0345(t, &signed, private)
	if err := verifyValidation0345(signed, pub); err != nil {
		t.Fatalf("Подписанное отрицательное игровое доказательство, привязанное к хешу, ошибочно отклонено: %v", err)
	}
	delete(signed.Evidence.ArtifactHashes, "adversarial-gameplay-04314.json")
	if err := verifyValidation0345(signed, pub); err == nil {
		t.Fatal("Подменённое подписанное доказательство ошибочно принято")
	}
	signed.Evidence.PackageVersion = "0.44.0"
	signFixture0345(t, &signed, private)
	if err := verifyValidation0345(signed, pub); err == nil {
		t.Fatal("будущие версии не должны обходить обязательные свидетельства испытаний на противодействие обходам")
	}
}
