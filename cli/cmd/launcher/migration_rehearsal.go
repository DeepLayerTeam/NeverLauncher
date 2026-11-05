package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CLI запускает проверки В УЖЕ ИЗОЛИРОВАННОМ тестовом окружении оператора. Это намеренно
// не универсальный endpoint удалённого выполнения команд. Команды, предоставленные
// сервером, не выполняются; оболочка не используется.
type rehearsalPlayer03310 struct {
	SourceID          string `json:"sourceId"`
	UUID              string `json:"uuid"`
	InventorySHA256   string `json:"inventorySha256"`
	PermissionsSHA256 string `json:"permissionsSha256"`
	Economy           string `json:"economy"`
	SkinSHA256        string `json:"skinSha256"`
	Admin             bool   `json:"admin"`
}
type rehearsalSnapshot03310 struct {
	WorldSHA256          string                 `json:"worldSha256"`
	Loader               string                 `json:"loader"`
	OptionalPresetSHA256 string                 `json:"optionalPresetSha256"`
	Players              []rehearsalPlayer03310 `json:"players"`
}
type rehearsalProbe03310 struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	RunID          string `json:"runId"`
	StageID        string `json:"stageId"`
	UUID           string `json:"uuid,omitempty"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	Detail         string `json:"detail,omitempty"`
}
type rehearsalReport03310 struct {
	Format                string                    `json:"format"`
	RunID                 string                    `json:"runId"`
	StageID               string                    `json:"stageId"`
	SourceInventorySHA256 string                    `json:"sourceInventorySha256"`
	SourceSnapshotSHA256  string                    `json:"sourceSnapshotSha256"`
	TargetSnapshotSHA256  string                    `json:"targetSnapshotSha256"`
	Source                rehearsalSnapshot03310    `json:"source"`
	Target                rehearsalSnapshot03310    `json:"target"`
	Probes                []rehearsalProbe03310     `json:"probes"`
	LiveSession           *rehearsalLiveWitness0447 `json:"liveSession,omitempty"`
	Blockers              []string                  `json:"blockers"`
	Ready                 bool                      `json:"ready"`
	CutoverAllowed        bool                      `json:"cutoverAllowed"`
}

var rehearsalRequired03310 = []string{"launch", "login", "join", "skins", "loader", "optional", "admin"}
var rehearsalHex03310 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var rehearsalStageID03310 = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,128}$`)

func rehearsalPath03310(root, sub string) (string, error) {
	if filepath.IsAbs(sub) || strings.ContainsAny(sub, "\\\x00") || sub == "" {
		return "", errors.New("Ожидается относительный путь в подготовленной области")
	}
	full := filepath.Join(root, sub)
	rel, e := filepath.Rel(root, full)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("Путь выходит за пределы корня подготовленной области")
	}
	real, e := filepath.EvalSymlinks(full)
	if e != nil {
		return "", e
	}
	rel, e = filepath.Rel(root, real)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("Символическая ссылка выходит за пределы корня подготовленной области")
	}
	return real, nil
}
func rehearsalRead03310(root, sub string, limit int64) ([]byte, error) {
	path, e := rehearsalPath03310(root, sub)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > limit {
		return nil, errors.New("Некорректное значение: размер файла свидетельства тестового окружения")
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}
func rehearsalDigest03310(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func rehearsalProbeExec03310(ctx context.Context, root, run, stage, name string) (rehearsalProbe03310, error) {
	probe := rehearsalProbe03310{Name: name, RunID: run, StageID: stage}
	program, e := rehearsalPath03310(root, "probes/"+name)
	if e != nil {
		return probe, e
	}
	st, e := os.Stat(program)
	if e != nil {
		return probe, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return probe, errors.New("Для проверочный запуск требуется: обычный исполняемый файл")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program)
	cmd.Dir = root
	// Не наследуйте токены, облачные учётные данные и подключение к производственной БД.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "MIGRATION_RUN_ID=" + run, "MIGRATION_STAGE_ID=" + stage, "MIGRATION_CHECK=" + name}
	var stdout, stderr limitedProbeBuffer03310
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if e = cmd.Run(); e != nil {
		return probe, fmt.Errorf("Проверка %s завершилась ошибкой (выход/тайм-аут): %w", name, e)
	}
	var output struct {
		Passed   bool   `json:"passed"`
		UUID     string `json:"uuid"`
		Evidence string `json:"evidenceFile"`
		Detail   string `json:"detail"`
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&output); e != nil {
		return probe, fmt.Errorf("Некорректное значение: %s JSON: %w", name, e)
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return probe, errors.New("JSON проверки содержит лишние данные")
	}
	if output.Evidence == "" || len(output.Detail) > 512 {
		return probe, errors.New("Проверка должна создать файл подтверждения допустимого размера и описание")
	}
	raw, e := rehearsalRead03310(root, output.Evidence, 1<<20)
	if e != nil {
		return probe, fmt.Errorf("Для проверки %s отсутствуют подтверждения: %w", name, e)
	}
	h := sha256.Sum256(raw)
	probe.Passed = output.Passed
	probe.UUID = output.UUID
	probe.Detail = ""
	probe.EvidenceSHA256 = hex.EncodeToString(h[:])
	return probe, nil
}

// Не допускайте переполнения памяти сервера и CLI внешними тестовыми процессами и утечки stderr.
type limitedProbeBuffer03310 struct{ bytes.Buffer }

func (b *limitedProbeBuffer03310) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16<<10 {
		return 0, errors.New("Результат проверки превышает 16 КиБ")
	}
	return b.Buffer.Write(p)
}

func migrationRehearsalRun03310(ctx context.Context, root, run, inventory string) (rehearsalReport03310, error) {
	var report rehearsalReport03310
	if !rehearsalHex03310.MatchString(inventory) || len(run) < 8 || len(run) > 128 {
		return report, errors.New("Требуются --run и точное значение --inventory-sha256")
	}
	if !filepath.IsAbs(root) {
		return report, errors.New("--stage должен содержать абсолютный путь к отдельной изолированной среде")
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil {
		return report, e
	}
	if real == "/" || real == filepath.Dir(real) {
		return report, errors.New("Небезопасное значение: корневой каталог тестового окружения")
	}
	marker, e := rehearsalRead03310(real, ".migration-stage.json", 8192)
	if e != nil {
		return report, e
	}
	var stage struct {
		Format   string `json:"format"`
		RunID    string `json:"runId"`
		StageID  string `json:"stageId"`
		Isolated bool   `json:"isolated"`
	}
	if e = json.Unmarshal(marker, &stage); e != nil {
		return report, e
	}
	if stage.Format != "never/migration-stage/v1" || stage.RunID != run || !rehearsalStageID03310.MatchString(stage.StageID) || !stage.Isolated {
		return report, errors.New("Некорректное значение: маркер изолированного тестового окружения")
	}
	a, e := rehearsalRead03310(real, "source-snapshot.json", 4<<20)
	if e != nil {
		return report, e
	}
	report.Format = "never/gravit-rehearsal/v1"
	report.RunID = run
	report.StageID = stage.StageID
	report.SourceInventorySHA256 = inventory
	if e = json.Unmarshal(a, &report.Source); e != nil {
		return report, e
	}
	report.SourceSnapshotSHA256, e = rehearsalDigest03310(report.Source)
	if e != nil {
		return report, e
	}
	live, verifyLive, cleanup, e := rehearsalLaunchLive0447(ctx, real, report.Source)
	if e != nil {
		return report, fmt.Errorf("Ошибка репетиции реального запуска и подключения Minecraft: %w", e)
	}
	defer cleanup()
	report.LiveSession = &live
	report.Probes = []rehearsalProbe03310{}
	for _, check := range rehearsalRequired03310 {
		probe, err := rehearsalProbeExec03310(ctx, real, run, stage.StageID, check)
		if err != nil {
			return report, err
		} // После неудачного выполнения отчёт не отправляется.
		report.Probes = append(report.Probes, probe)
	}
	if e = verifyLive(); e != nil {
		return report, e
	}
	// Считывайте итоговый снимок цели ПОСЛЕ проверок, чтобы тесты, меняющие изолированный игровой
	// мир, не смогли пройти на основании устаревшего снимка до запуска.
	b, e := rehearsalRead03310(real, "target-snapshot.json", 4<<20)
	if e != nil {
		return report, e
	}
	if e = json.Unmarshal(b, &report.Target); e != nil {
		return report, e
	}
	if e = verifyLive(); e != nil {
		return report, e
	}
	report.TargetSnapshotSHA256, e = rehearsalDigest03310(report.Target)
	if e != nil {
		return report, e
	}
	// Backend заново вычисляет все сравнения данных, проверки и предварительные условия в БД.
	// Не объявляйте локально успешную сертификацию до его ответа.
	report.Ready = false
	report.CutoverAllowed = false
	report.Blockers = []string{"Ожидается авторитетная проверка на стороне сервера"}
	return report, nil
}
func handleMigrationRehearsal03310(args []string) error {
	run := flagValue(args, "--run", "")
	stage := flagValue(args, "--stage", "")
	inventory := flagValue(args, "--inventory-sha256", "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	report, e := migrationRehearsalRun03310(ctx, stage, run, inventory)
	if e != nil {
		return e
	}
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	token := backendToken(args)
	if backend == "" || token == "" {
		return errors.New("Требуются --backend и --token: локальные результаты ещё не сертифицированы")
	}
	endpoint := backend + "/api/v1/admin/migration-runs/" + run + "/rehearsal"
	if e = migrationModuleEndpoint0338(endpoint); e != nil {
		return e
	}
	raw, e := json.Marshal(report)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Migration-Rehearsal-Confirm", run)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	answer, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return e
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Фиксация репетиции вернула HTTP %d: %s", resp.StatusCode, answer)
	}
	var parsed any
	if e = json.Unmarshal(answer, &parsed); e != nil {
		return e
	}
	out := flagValue(args, "--output", "")
	if out != "" {
		return writePrivateIdentityReport0334(out, parsed)
	}
	fmt.Println(string(answer))
	return nil
}
