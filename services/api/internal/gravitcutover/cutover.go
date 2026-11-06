// Package gravitcutover задаёт строгие входные данные для смены маршрутов MIG11.
// Разграничение записывающих процессов исходника выполняется извне; локальное
// утверждение БД ничего не доказывает.
package gravitcutover

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

var scope = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Stage struct {
	ProfileID            string `json:"profileId"`
	Channel              string `json:"channel"`
	ReleaseID            string `json:"releaseId"`
	ExpectedHeadRevision int64  `json:"expectedHeadRevision"`
	StageID              string `json:"stageId"`
}
type Activate struct {
	ProfileID        string `json:"profileId"`
	Channel          string `json:"channel"`
	ExpectedRevision int64  `json:"expectedRevision"`
	// Ссылка и SHA-256 на отдельно сохраняемые эксплуатационные доказательства того,
	// что старый записывающий процесс Gravit действительно остановлен или
	// заблокирован. Это не утверждение Never.
	SourceFenceReference        string                  `json:"sourceFenceReference"`
	SourceFenceEvidenceSHA256   string                  `json:"sourceFenceEvidenceSha256"`
	CurrentSourceSnapshotSHA256 string                  `json:"currentSourceSnapshotSha256"`
	SourceFenceReceipt          *SourceFenceReceipt0448 `json:"sourceFenceReceipt"`
}

// SourceFenceReceipt0448 — детерминированный результат остановки/mask через
// systemd на источнике и проверки свежего снимка. Это свидетельство оператора,
// НЕ аппаратная аттестация; оно не доказывает остановку посторонних служб.
type SourceFenceReceipt0448 struct {
	Format             string    `json:"format"`
	RunID              string    `json:"runId"`
	ProfileID          string    `json:"profileId"`
	Channel            string    `json:"channel"`
	StageID            string    `json:"stageId"`
	Unit               string    `json:"unit"`
	StoppedAt          time.Time `json:"stoppedAt"`
	CheckedAt          time.Time `json:"checkedAt"`
	UnitState          string    `json:"unitState"`
	UnitFileState      string    `json:"unitFileState"`
	SnapshotSHA256     string    `json:"snapshotSha256"`
	SnapshotFileSHA256 string    `json:"snapshotFileSha256"`
}

var systemdUnit0448 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.service$`)

func VerifySourceFence0448(a Activate, r Route, now time.Time) error {
	proof := a.SourceFenceReceipt
	if proof == nil || proof.Format != "never/gravit-source-stop/v1" ||
		proof.RunID != r.RunID || proof.ProfileID != r.ProfileID || proof.Channel != r.Channel || proof.StageID != r.StageID ||
		!systemdUnit0448.MatchString(proof.Unit) || proof.UnitState != "inactive" ||
		(proof.UnitFileState != "masked" && proof.UnitFileState != "masked-runtime") ||
		proof.SnapshotSHA256 != a.CurrentSourceSnapshotSHA256 || !digest.MatchString(proof.SnapshotFileSHA256) ||
		proof.StoppedAt.After(proof.CheckedAt) || now.Sub(proof.CheckedAt) > 10*time.Minute || proof.CheckedAt.After(now.Add(time.Minute)) ||
		proof.StoppedAt.After(now.Add(time.Minute)) || now.Sub(proof.StoppedAt) > 15*time.Minute {
		return errors.New("Квитанция остановки источника отсутствует, устарела или не привязана к миграции и снимку")
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != a.SourceFenceEvidenceSHA256 {
		return errors.New("Несовпадение: «SHA-256 подтверждения остановки источника»")
	}
	return nil
}

type Route struct {
	RunID               string `json:"runId"`
	ProjectID           string `json:"projectId"`
	ProfileID           string `json:"profileId"`
	Channel             string `json:"channel"`
	StageID             string `json:"stageId"`
	ReleaseID           string `json:"releaseId"`
	ReleaseVersion      string `json:"releaseVersion"`
	TargetDigest        string `json:"targetDigest"`
	BaselineRevision    int64  `json:"baselineRevision"`
	BaselineReleaseID   string `json:"baselineReleaseId"`
	BaselineVersion     string `json:"baselineVersion"`
	BaselineDigest      string `json:"baselineDigest"`
	State               string `json:"state"`
	Revision            int64  `json:"revision"`
	ActivatedRevision   *int64 `json:"activatedRevision,omitempty"`
	FenceReference      string `json:"fenceReference,omitempty"`
	FenceEvidenceSHA256 string `json:"fenceEvidenceSha256,omitempty"`
}

func ValidateStage(s Stage) error {
	if !scope.MatchString(s.ProfileID) || !scope.MatchString(s.Channel) || len(s.ReleaseID) < 1 || len(s.ReleaseID) > 256 || strings.ContainsAny(s.ReleaseID, "\x00\r\n") || s.ExpectedHeadRevision < 0 || len(s.StageID) < 16 || len(s.StageID) > 128 {
		return errors.New("Некорректное значение: «область действия, выпуск, ревизия или репетиция этапа переключения»")
	}
	return nil
}
func ValidateActivation(a Activate) error {
	if !scope.MatchString(a.ProfileID) || !scope.MatchString(a.Channel) || a.ExpectedRevision < 1 || len(a.SourceFenceReference) < 8 || len(a.SourceFenceReference) > 256 || strings.ContainsAny(a.SourceFenceReference, "\r\n\x00") || !digest.MatchString(a.SourceFenceEvidenceSHA256) || !digest.MatchString(a.CurrentSourceSnapshotSHA256) || a.SourceFenceReceipt == nil {
		return errors.New("Некорректное значение: «доказательства активации переключения и блокировки источника»")
	}
	return nil
}

// VerifyRelease проверяет настоящие байты Ed25519 и ТЕКУЩИЙ корень подписи Never;
// самоподписанный старый манифест Gravit нельзя выбирать целью.
func VerifyRelease(m model.Manifest, trusted ed25519.PublicKey) (string, error) {
	if err := model.ValidateManifestSchema(m); err != nil {
		return "", err
	}
	if m.Signature == nil || !strings.EqualFold(m.Signature.Algorithm, "Ed25519") {
		return "", errors.New("Требуется: «подписанный выпуск Never»")
	}
	pub, err := hex.DecodeString(m.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.PublicKey(pub).Equal(trusted) {
		return "", errors.New("Подписант релиза не соответствует текущему доверенному ключу Never")
	}
	sig, err := hex.DecodeString(m.Signature.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", errors.New("Некорректное значение: подпись релиза")
	}
	bare := m
	bare.Signature = nil
	raw, err := json.Marshal(bare)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, raw, sig) {
		return "", errors.New("Ошибка: «проверка подписи выпуска»")
	}
	all, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(all)
	return hex.EncodeToString(sum[:]), nil
}
