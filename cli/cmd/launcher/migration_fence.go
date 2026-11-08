package main

// Служба записи исходной системы systemd управляется только на ЕЁ СОБСТВЕННОМ хосте, не через
// Never Backend. Две явные операции допускают экспорт нового снимка только ПОСЛЕ остановки
// записи. Это проверяемое свидетельство оператора, а не удалённая аппаратная аттестация и не
// утверждение обо всех неучтённых службах записи или прокси.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var fenceUnit0448 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.service$`)
var fenceScope0448 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
var fenceDigest0448 = regexp.MustCompile(`^[a-f0-9]{64}$`)

type sourceFenceState0448 struct {
	Format    string    `json:"format"`
	RunID     string    `json:"runId"`
	ProfileID string    `json:"profileId"`
	Channel   string    `json:"channel"`
	StageID   string    `json:"stageId"`
	Unit      string    `json:"unit"`
	StoppedAt time.Time `json:"stoppedAt"`
}
type sourceFenceEvidence0448 struct {
	sourceFenceState0448
	CheckedAt          time.Time `json:"checkedAt"`
	UnitState          string    `json:"unitState"`
	UnitFileState      string    `json:"unitFileState"`
	SnapshotSHA256     string    `json:"snapshotSha256"`
	SnapshotFileSHA256 string    `json:"snapshotFileSha256"`
}

type fenceRunner0448 func(context.Context, ...string) (string, error)

func fenceSystemctl0448(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl %s: %w", args[0], err)
	}
	return strings.TrimSpace(string(out)), nil
}
func checkSourceFenced0448(ctx context.Context, unit string, run fenceRunner0448) (string, string, error) {
	state, err := run(ctx, "show", "--property=ActiveState", "--value", unit)
	if err != nil {
		return "", "", err
	}
	// Допустимы только состояния masked-runtime и masked: неактивную, но незамаскированную
	// службу могут перезапустить systemd или другой администратор.
	mask, err := run(ctx, "show", "--property=UnitFileState", "--value", unit)
	if err != nil {
		return "", "", err
	}
	if state != "inactive" || (mask != "masked-runtime" && mask != "masked") {
		return state, mask, fmt.Errorf("Процесс записи источника не заблокирован: ActiveState=%q UnitFileState=%q", state, mask)
	}
	return state, mask, nil
}
func writeExclusiveFence0448(path string, data []byte) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("Необходимо указать абсолютный путь вывода")
	}
	// O_EXCL не позволяет повторной попытке перезаписать уже сохранённое свидетельство.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}
func readFenceFile0448(path string, max int64, dest any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > max || st.Size() == 0 {
		return errors.New("Входной файл блокировки не является обычным файлом допустимого размера")
	}
	dec := json.NewDecoder(io.LimitReader(f, max+1))
	dec.DisallowUnknownFields()
	if err = dec.Decode(dest); err != nil {
		return err
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return errors.New("Лишние данные JSON в файле блокировки")
	}
	return nil
}
func validateFenceState0448(s sourceFenceState0448) error {
	if s.Format != "never/gravit-source-stop/v1" || !fenceScope0448.MatchString(s.RunID) || !fenceScope0448.MatchString(s.ProfileID) || !fenceScope0448.MatchString(s.Channel) || len(s.StageID) < 16 || len(s.StageID) > 128 || !fenceUnit0448.MatchString(s.Unit) || s.StoppedAt.IsZero() {
		return errors.New("Некорректная область блокировки источника")
	}
	return nil
}
func stopSourceWriter0448(ctx context.Context, state sourceFenceState0448, output string, run fenceRunner0448) error {
	state.StoppedAt = time.Now().UTC()
	if err := validateFenceState0448(state); err != nil {
		return err
	}
	if output == "" || !filepath.IsAbs(output) {
		return errors.New("Необходимо указать абсолютный путь вывода")
	}
	if _, err := os.Lstat(output); err == nil {
		return errors.New("Уже существует: результат")
	} else if !os.IsNotExist(err) {
		return err
	}
	// Маскирование Runtime обеспечивает отказ при неудачной проверке; автоматического снятия
	// маски нет, даже если последующий экспорт снимка завершился ошибкой.
	if _, err := run(ctx, "mask", "--runtime", "--now", state.Unit); err != nil {
		return err
	}
	if _, _, err := checkSourceFenced0448(ctx, state.Unit, run); err != nil {
		return err
	}
	// Вторая независимая проверка обнаруживает немедленный перезапуск и состояния гонки.
	if _, _, err := checkSourceFenced0448(ctx, state.Unit, run); err != nil {
		return err
	}
	state.StoppedAt = time.Now().UTC()
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeExclusiveFence0448(output, raw)
}
func verifyStoppedSource0448(ctx context.Context, statePath, snapshotPath, expected, output string, run fenceRunner0448) (sourceFenceEvidence0448, error) {
	var state sourceFenceState0448
	if err := readFenceFile0448(statePath, 8<<10, &state); err != nil {
		return sourceFenceEvidence0448{}, err
	}
	if err := validateFenceState0448(state); err != nil {
		return sourceFenceEvidence0448{}, err
	}
	if !fenceDigest0448.MatchString(expected) {
		return sourceFenceEvidence0448{}, errors.New("Требуется: ожидаемый SHA-256 снимка пробной миграции")
	}
	if time.Since(state.StoppedAt) > 15*time.Minute || time.Until(state.StoppedAt) > time.Minute {
		return sourceFenceEvidence0448{}, errors.New("Подтверждение остановки источника просрочено либо датировано будущим")
	}
	active, masked, err := checkSourceFenced0448(ctx, state.Unit, run)
	if err != nil {
		return sourceFenceEvidence0448{}, err
	}
	// Импортируйте типизированный снимок репетиции, чтобы encoding/json хешировал поля в
	// том же порядке, что и gravitrehearsal.SnapshotDigest в API.
	var snapshot struct {
		WorldSHA256          string `json:"worldSha256"`
		Loader               string `json:"loader"`
		OptionalPresetSHA256 string `json:"optionalPresetSha256"`
		Players              []struct {
			SourceID          string `json:"sourceId"`
			UUID              string `json:"uuid"`
			InventorySHA256   string `json:"inventorySha256"`
			PermissionsSHA256 string `json:"permissionsSha256"`
			Economy           string `json:"economy"`
			SkinSHA256        string `json:"skinSha256"`
			Admin             bool   `json:"admin"`
		} `json:"players"`
	}
	st, err := os.Stat(snapshotPath)
	if err != nil {
		return sourceFenceEvidence0448{}, err
	}
	if !st.Mode().IsRegular() || st.Size() > 8<<20 || st.Size() == 0 || st.ModTime().Before(state.StoppedAt.Add(-time.Second)) {
		return sourceFenceEvidence0448{}, errors.New("После остановки исходной системы необходимо создать новый снимок в виде обычного файла экспорта")
	}
	if err := readFenceFile0448(snapshotPath, 8<<20, &snapshot); err != nil {
		return sourceFenceEvidence0448{}, err
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return sourceFenceEvidence0448{}, err
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != expected {
		return sourceFenceEvidence0448{}, errors.New("Состояние источника изменилось после MIG10: хеш снимка не совпадает")
	}
	raw, err := os.ReadFile(snapshotPath)
	if err != nil {
		return sourceFenceEvidence0448{}, err
	}
	filehash := sha256.Sum256(raw)
	// Повторно проверяйте состояние после чтения: перезапуск во время хеширования делает свидетельство недействительным.
	if _, _, err = checkSourceFenced0448(ctx, state.Unit, run); err != nil {
		return sourceFenceEvidence0448{}, err
	}
	evidence := sourceFenceEvidence0448{sourceFenceState0448: state, CheckedAt: time.Now().UTC(), UnitState: active, UnitFileState: masked, SnapshotSHA256: expected, SnapshotFileSHA256: hex.EncodeToString(filehash[:])}
	data, err := json.Marshal(evidence)
	if err != nil {
		return sourceFenceEvidence0448{}, err
	}
	if err = writeExclusiveFence0448(output, data); err != nil {
		return sourceFenceEvidence0448{}, err
	}
	h := sha256.Sum256(data)
	fmt.Printf("sourceFenceReference=%s\nsourceFenceEvidenceSha256=%s\ncurrentSourceSnapshotSha256=%s\n", output, hex.EncodeToString(h[:]), expected)
	return evidence, nil
}
func handleMigrationFence0448(args []string) error {
	if len(args) == 0 {
		return errors.New("Требуется: «fence-source|verify-source-fence»")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch args[0] {
	case "fence-source":
		state := sourceFenceState0448{Format: "never/gravit-source-stop/v1", RunID: flagValue(args, "--run", ""), ProfileID: flagValue(args, "--profile-id", ""), Channel: flagValue(args, "--channel", ""), StageID: flagValue(args, "--stage-id", ""), Unit: flagValue(args, "--unit", "")}
		if flagValue(args, "--confirm", "") != state.RunID {
			return errors.New("Требуется точное подтверждение идентификатора задачи миграции")
		}
		return stopSourceWriter0448(ctx, state, flagValue(args, "--output", ""), fenceSystemctl0448)
	case "verify-source-fence":
		_, err := verifyStoppedSource0448(ctx, flagValue(args, "--state", ""), flagValue(args, "--snapshot", ""), flagValue(args, "--expected-snapshot-sha256", ""), flagValue(args, "--output", ""), fenceSystemctl0448)
		return err
	default:
		return errors.New("Неизвестная команда блокировки источника")
	}
}
