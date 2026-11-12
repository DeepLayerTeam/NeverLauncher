package main

// Промежуточная загрузка содержимого миграции намеренно последовательна: каждый успешный
// импорт меняет снимок целевого проекта, поэтому следующая пробная операция должна учитывать
// новое фактическое состояние. Пакетная пробная проверка не разрешает запись: каждый профиль
// проходит долговечную CAS-проверку плана и импорт в зашифрованное рабочее пространство
// сборки через производственный API.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

type migrationLivePlan0493 struct {
	RunID           string       `json:"runId"`
	ProjectID       string       `json:"projectId"`
	SourceSHA256    string       `json:"sourceSha256"`
	InventorySHA256 string       `json:"inventorySha256"`
	TargetSHA256    string       `json:"targetSha256"`
	PlanSHA256      string       `json:"planSha256"`
	Destination     gravDest0492 `json:"destination"`
	Status          string       `json:"status"`
	Blockers        []string     `json:"blockers"`
	Content         struct {
		ProfilePath     string            `json:"profilePath"`
		SourceSHA256    string            `json:"sourceSha256"`
		InventorySHA256 string            `json:"inventorySha256"`
		FilesSHA256     string            `json:"filesSha256"`
		Ready           bool              `json:"ready"`
		Files           []json.RawMessage `json:"files"`
	} `json:"content"`
}
type migrationLiveContent0493 struct {
	Complete    bool   `json:"complete"`
	WorkspaceID string `json:"workspaceId"`
	State       string `json:"state"`
	StagedFiles int    `json:"stagedFiles"`
	TotalFiles  int    `json:"totalFiles"`
	Plan        struct {
		ProfilePath     string `json:"profilePath"`
		SourceSHA256    string `json:"sourceSha256"`
		InventorySHA256 string `json:"inventorySha256"`
		FilesSHA256     string `json:"filesSha256"`
		Profile         struct {
			Profile struct {
				ID string `json:"id"`
			} `json:"profile"`
		} `json:"profile"`
	} `json:"plan"`
}
type migrationImported0493 struct {
	ProfilePath string `json:"profilePath"`
	ProfileID   string `json:"profileId"`
	FilesSHA256 string `json:"filesSha256"`
	WorkspaceID string `json:"workspaceId"`
	FileCount   int    `json:"fileCount"`
}

// Только хост Backend вправе получать API bearer-токен. Запросы не
// перенаправляются; сторонние URL из ZIP Gravit никогда не открываются.
func migrationURL0493(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || u.Hostname() == "" || (u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())) {
		return nil, errors.New("Для адреса серверной части требуется HTTPS либо HTTP на локальном IP-адресе обратной связи без учётных данных и параметров запроса")
	}
	return u, nil
}

func migrationRequest0493(client *http.Client, method, address, token, source string, headers map[string]string) (int, []byte, error) {
	var reader io.Reader
	var f *os.File
	if source != "" {
		var err error
		f, err = os.Open(source)
		if err != nil {
			return 0, nil, err
		}
		defer f.Close()
		reader = f
	}
	req, err := http.NewRequest(method, address, reader)
	if err != nil {
		return 0, nil, err
	}
	if f != nil {
		stat, err := f.Stat()
		if err != nil {
			return 0, nil, err
		}
		req.ContentLength = stat.Size()
		req.Header.Set("Content-Type", "application/zip")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20+1))
	if err != nil {
		return 0, nil, err
	}
	if len(raw) > 16<<20 {
		return 0, nil, errors.New("Размер ответа серверной части превысил 16 МиБ")
	}
	return res.StatusCode, raw, nil
}
func migrationJSON0493(client *http.Client, method, endpoint, token, source string, headers map[string]string, target any, allowNotFound bool) (bool, error) {
	status, body, err := migrationRequest0493(client, method, endpoint, token, source, headers)
	if err != nil {
		return false, err
	}
	if allowNotFound && status == 404 {
		return false, nil
	}
	if status != 200 {
		return false, fmt.Errorf("Миграция %s: HTTP %d: %s", method, status, string(body))
	}
	wrapper := struct {
		Data json.RawMessage `json:"data"`
	}{}
	if err = json.Unmarshal(body, &wrapper); err != nil || len(wrapper.Data) == 0 {
		return false, errors.New("Отсутствуют данные миграции серверной части")
	}
	if err = json.Unmarshal(wrapper.Data, target); err != nil {
		return false, err
	}
	return true, nil
}
func migrationVerifyLivePlan0493(plan migrationLivePlan0493, batch gravBatch0492, row gravProfile0492, first bool) error {
	if plan.RunID != batch.RunID || plan.ProjectID != batch.ProjectID || plan.SourceSHA256 != batch.SourceSHA256 || plan.InventorySHA256 != batch.InventorySHA256 || plan.Destination != row.Destination || plan.Status != "manual" || len(plan.Blockers) != 0 || len(plan.PlanSHA256) != 64 || !plan.Content.Ready || plan.Content.SourceSHA256 != batch.SourceSHA256 || plan.Content.InventorySHA256 != batch.InventorySHA256 || plan.Content.ProfilePath != row.Destination.ProfilePath || plan.Content.FilesSHA256 != row.FilesSHA256 || len(plan.Content.Files) != row.FileCount {
		return fmt.Errorf("Текущий план для %s отличается от утверждённого пакетного плана", row.Destination.ProfilePath)
	}
	if first && (plan.TargetSHA256 != batch.TargetSHA256 || plan.PlanSHA256 != row.PlanSHA256) {
		return errors.New("Целевая система изменилась после утверждённого пробного импорта нескольких профилей")
	}
	return nil
}
func migrationVerifyStage0493(stage migrationLiveContent0493, batch gravBatch0492, row gravProfile0492) error {
	if !stage.Complete || (stage.State != "staged" && stage.State != "built") || stage.WorkspaceID == "" || stage.StagedFiles != row.FileCount || stage.TotalFiles != row.FileCount || stage.Plan.ProfilePath != row.Destination.ProfilePath || stage.Plan.Profile.Profile.ID != row.Destination.ProfileID || stage.Plan.SourceSHA256 != batch.SourceSHA256 || stage.Plan.InventorySHA256 != batch.InventorySHA256 || stage.Plan.FilesSHA256 != row.FilesSHA256 {
		return fmt.Errorf("Импортированная рабочая область неполна или не совпадает: %s", row.Destination.ProfilePath)
	}
	return nil
}

func migrationImportAll0493(args []string) error {
	backend, token := strings.TrimRight(flagValue(args, "--backend", ""), "/"), backendToken(args)
	run, confirm := strings.TrimSpace(flagValue(args, "--run", "")), strings.TrimSpace(flagValue(args, "--confirm", ""))
	source, mapping, report := flagValue(args, "--source", ""), flagValue(args, "--mapping", ""), flagValue(args, "--report", "")
	if backend == "" || token == "" || run == "" || confirm != run || source == "" || mapping == "" || report == "" {
		return errors.New("Для import-content-all необходимы параметры --backend, --token, --run, --confirm (тот же запуск), --source, --mapping и --report")
	}
	if _, err := migrationURL0493(backend); err != nil {
		return err
	}
	b, err := os.ReadFile(report)
	if err != nil {
		return err
	}
	if len(b) > 16<<20 {
		return errors.New("Превышен допустимый размер: отчёт о миграции")
	}
	var receipt gravBatchResponse0492
	if err = json.Unmarshal(b, &receipt); err != nil {
		return err
	}
	batch := receipt.Data
	if err = verifyGravBatchDigest0492(batch); err != nil {
		return err
	}
	if batch.RunID != run || batch.Status != "manual" || len(batch.Blockers) != 0 || len(batch.Profiles) == 0 {
		return errors.New("Пробный запуск пакета не сформировал разрешённый план для этой операции")
	}
	mf, err := os.Open(mapping)
	if err != nil {
		return err
	}
	defer mf.Close()
	stat, err := mf.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 12288 {
		return errors.New("Некорректное значение: файл сопоставления")
	}
	d := json.NewDecoder(io.LimitReader(mf, 12289))
	d.DisallowUnknownFields()
	var mapped []gravDest0492
	if err = d.Decode(&mapped); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("В файле сопоставлений обнаружены лишние данные в конце")
	}
	if len(mapped) != batch.ProfileCount {
		return errors.New("Обнаружено изменение: число профилей в файле сопоставления")
	}
	expected := append([]gravDest0492(nil), mapped...)
	sort.Slice(expected, func(i, j int) bool { return expected[i].ProfilePath < expected[j].ProfilePath })
	for i, row := range batch.Profiles {
		if !reflect.DeepEqual(expected[i], row.Destination) || row.Status != "manual" || len(row.Blockers) != 0 || row.FileCount <= 0 || len(row.FilesSHA256) != 64 {
			return fmt.Errorf("Сопоставление профиля %d заблокировано или изменено", i)
		}
	}
	sf, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sf.Close()
	ss, err := sf.Stat()
	if err != nil {
		return err
	}
	if !ss.Mode().IsRegular() || ss.Size() < 1 || ss.Size() > 512<<20 {
		return errors.New("Источник: требуется обычный ZIP-архив размером от 1 до 512 МиБ")
	}
	h := sha256.New()
	if _, err = io.Copy(h, sf); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != batch.SourceSHA256 {
		return errors.New("Источник Gravit изменился после пробного импорта нескольких профилей")
	}
	client := &http.Client{Timeout: 45 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := backend + "/api/v1/admin/migration-runs/" + url.PathEscape(run)
	imported := make([]migrationImported0493, 0, len(batch.Profiles))
	resume := flagValue(args, "--resume", "") == "true"
	progressed := false
	for i, row := range batch.Profiles {
		contentURL := base + "/content?profilePath=" + url.QueryEscape(row.Destination.ProfilePath)
		var stage migrationLiveContent0493
		exists, err := migrationJSON0493(client, "GET", contentURL, token, "", nil, &stage, true)
		if err != nil {
			return err
		}
		if exists && stage.Complete {
			if !resume {
				return fmt.Errorf("Профиль %s уже импортирован; используйте --resume=true для проверки и продолжения", row.Destination.ProfilePath)
			}
			if err = migrationVerifyStage0493(stage, batch, row); err != nil {
				return err
			}
			progressed = true
			imported = append(imported, migrationImported0493{row.Destination.ProfilePath, row.Destination.ProfileID, row.FilesSHA256, stage.WorkspaceID, stage.TotalFiles})
			continue
		}
		var plan migrationLivePlan0493
		if exists {
			if !resume {
				return errors.New("Для продолжения частично импортированного рабочего пространства требуется --resume=true")
			}
			_, err = migrationJSON0493(client, "GET", base+"/dry-run", token, "", nil, &plan, false)
		} else {
			if progressed && i == 0 {
				return errors.New("Неожиданное состояние")
			}
			fields := map[string]string{"X-Gravit-Profile-Path": row.Destination.ProfilePath, "X-Profile-ID": row.Destination.ProfileID, "X-Profile-Name": row.Destination.ProfileName, "X-Loader": row.Destination.Loader, "X-Loader-Version": row.Destination.LoaderVersion, "X-Channel": row.Destination.Channel, "X-Version": row.Destination.Version}
			_, err = migrationJSON0493(client, "POST", base+"/dry-run", token, source, fields, &plan, false)
		}
		if err != nil {
			return err
		}
		if err = migrationVerifyLivePlan0493(plan, batch, row, i == 0 && !progressed); err != nil {
			return err
		}
		fields := map[string]string{"X-Gravit-Profile-Path": row.Destination.ProfilePath, "X-Profile-ID": row.Destination.ProfileID, "X-Profile-Name": row.Destination.ProfileName, "X-Loader": row.Destination.Loader, "X-Loader-Version": row.Destination.LoaderVersion, "X-Channel": row.Destination.Channel, "X-Version": row.Destination.Version, "X-Migration-Content-Confirm": run, "X-Migration-Plan-SHA256": plan.PlanSHA256}
		var importedStage migrationLiveContent0493
		_, err = migrationJSON0493(client, "POST", base+"/content/import", token, source, fields, &importedStage, false)
		if err != nil {
			return fmt.Errorf("Ошибка импорта %s: %w (после устранения ошибки используйте --resume=true с тем же отчётом)", row.Destination.ProfilePath, err)
		}
		if err = migrationVerifyStage0493(importedStage, batch, row); err != nil {
			return err
		}
		_, err = migrationJSON0493(client, "GET", contentURL, token, "", nil, &stage, false)
		if err != nil {
			return err
		}
		if err = migrationVerifyStage0493(stage, batch, row); err != nil {
			return err
		}
		if stage.WorkspaceID != importedStage.WorkspaceID {
			return errors.New("Рабочая область изменилась после импорта содержимого")
		}
		imported = append(imported, migrationImported0493{row.Destination.ProfilePath, row.Destination.ProfileID, row.FilesSHA256, stage.WorkspaceID, stage.TotalFiles})
		progressed = true
	}
	result := map[string]any{"format": "launcher.gravit-content-stage.v1", "batchSha256": batch.BatchSHA256, "sourceSha256": batch.SourceSHA256, "runId": run, "profiles": imported, "status": "staged", "next": "Соберите клиенты, примените дополнительные каталоги к неподписанным черновикам, проверьте, подпишите и испытайте каждый клиент до переключения"}
	if out := flagValue(args, "--output", ""); out != "" {
		return writePrivateIdentityReport0334(out, result)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}
