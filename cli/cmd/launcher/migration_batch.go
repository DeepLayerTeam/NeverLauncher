package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Повторяет точный сериализуемый формат производственного калькулятора планов Gravit. Повторное
// вычисление дайджеста выявляет изменение отчёта, а не только устаревшие хеши. Хеш без ключа не
// означает криптографического доверия к третьей стороне.
type gravDest0492 struct {
	ProfilePath   string `json:"profilePath"`
	ProfileID     string `json:"profileId"`
	ProfileName   string `json:"profileName"`
	Loader        string `json:"loader"`
	LoaderVersion string `json:"loaderVersion,omitempty"`
	Channel       string `json:"channel"`
	Version       string `json:"version"`
}
type gravDependency0492 struct {
	Component string `json:"component"`
	Requires  string `json:"requires"`
	Kind      string `json:"kind"`
}
type gravProfile0492 struct {
	Destination     gravDest0492         `json:"destination"`
	SourceDirectory string               `json:"sourceDirectory,omitempty"`
	Status          string               `json:"status"`
	PlanSHA256      string               `json:"planSha256,omitempty"`
	FilesSHA256     string               `json:"filesSha256,omitempty"`
	FileCount       int                  `json:"fileCount"`
	TransferBytes   int64                `json:"transferBytes"`
	Dependencies    []gravDependency0492 `json:"dependencies"`
	Blockers        []string             `json:"blockers"`
}
type gravBatch0492 struct {
	Format          string            `json:"format"`
	RunID           string            `json:"runId"`
	ProjectID       string            `json:"projectId"`
	SourceSHA256    string            `json:"sourceSha256"`
	InventorySHA256 string            `json:"inventorySha256"`
	TargetSHA256    string            `json:"targetSha256"`
	Profiles        []gravProfile0492 `json:"profiles"`
	ProfileCount    int               `json:"profileCount"`
	Status          string            `json:"status"`
	Blockers        []string          `json:"blockers"`
	BatchSHA256     string            `json:"batchSha256"`
}
type gravBatchResponse0492 struct {
	Data gravBatch0492 `json:"data"`
}

func verifyGravBatchDigest0492(b gravBatch0492) error {
	if b.Format != "launcher.gravit-multi-profile-dry-run.v1" || len(b.BatchSHA256) != 64 || b.ProfileCount != len(b.Profiles) || b.ProfileCount < 1 || b.ProfileCount > 32 {
		return errors.New("Некорректное значение: отчёт по нескольким профилям")
	}
	expected := b.BatchSHA256
	b.BatchSHA256 = ""
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected {
		return errors.New("Несовпадение: контрольная сумма отчёта по нескольким профилям")
	}
	return nil
}
func migrationBatchCLI0492(endpoint, token, source, mapping, report, out string) error {
	if source == "" || mapping == "" {
		return errors.New("dry-run-all: требуется «--source and --mapping»")
	}
	uri, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if uri.Scheme != "https" {
		ip := net.ParseIP(uri.Hostname())
		if uri.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("Источник миграции: требуется HTTPS, кроме локального loopback-адреса")
		}
	}
	mf, err := os.Lstat(mapping)
	if err != nil {
		return err
	}
	if !mf.Mode().IsRegular() || mf.Size() < 2 || mf.Size() > 12288 {
		return errors.New("Для сопоставление требуется: «a regular JSON file at most 12 KiB»")
	}
	raw, err := os.ReadFile(mapping)
	if err != nil {
		return err
	}
	// Кодируйте каноническое проверенное сопоставление, чтобы исключить внедрение заголовков и
	// случайную пересылку произвольных сырых конфиденциальных данных.
	var rows []struct {
		ProfilePath   string `json:"profilePath"`
		ProfileID     string `json:"profileId"`
		ProfileName   string `json:"profileName"`
		Loader        string `json:"loader"`
		LoaderVersion string `json:"loaderVersion,omitempty"`
		Channel       string `json:"channel"`
		Version       string `json:"version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&rows); err != nil {
		return fmt.Errorf("Некорректное значение: сопоставление: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("Лишние данные после карты сопоставления")
	}
	if len(rows) == 0 || len(rows) > 32 {
		return errors.New("Для сопоставление требуется: 1..32 профили")
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if len(encoded) > 12288 {
		return errors.New("Превышен допустимый размер: сопоставление")
	}
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	st, err := sourceFile.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return errors.New("Источник: требуется «regular ZIP of 1..512 MiB»")
	}
	req, err := http.NewRequest("POST", endpoint, sourceFile)
	if err != nil {
		return err
	}
	req.ContentLength = st.Size()
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("X-Gravit-Profiles", base64.RawURLEncoding.EncodeToString(encoded))
	client := &http.Client{Timeout: 45 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20+1))
	if err != nil {
		return err
	}
	if len(body) > 16<<20 {
		return errors.New("Превышен допустимый размер: «dry-run response»")
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("Пробный запуск всех миграций вернул HTTP %d: %s", res.StatusCode, string(body))
	}
	var value gravBatchResponse0492
	if err = json.Unmarshal(body, &value); err != nil {
		return err
	}
	current := value.Data
	if current.Format != "launcher.gravit-multi-profile-dry-run.v1" || len(current.BatchSHA256) != 64 || len(current.SourceSHA256) != 64 || len(current.TargetSHA256) != 64 || current.ProfileCount != len(rows) || (current.Status != "blocked" && current.Status != "manual") {
		return errors.New("Некорректное значение: «backend dry-run report»")
	}
	if err = verifyGravBatchDigest0492(current); err != nil {
		return err
	}

	if report != "" {
		// Это повтор проверки относительно текущей цели и полного исходного ZIP; одной локальной
		// контрольной суммы недостаточно, чтобы доказать актуальность цели.
		file, err := os.Open(report)
		if err != nil {
			return err
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil {
			return err
		}
		if !stat.Mode().IsRegular() || stat.Size() > 16<<20 {
			return errors.New("Некорректное значение: «prior dry-run report»")
		}
		existing, err := io.ReadAll(io.LimitReader(file, 16<<20+1))
		if err != nil {
			return err
		}
		var previous gravBatchResponse0492
		if json.Unmarshal(existing, &previous) != nil || verifyGravBatchDigest0492(previous.Data) != nil || previous.Data.Format != current.Format || previous.Data.BatchSHA256 != current.BatchSHA256 || previous.Data.SourceSHA256 != current.SourceSHA256 || previous.Data.TargetSHA256 != current.TargetSHA256 || previous.Data.ProfileCount != current.ProfileCount {
			return errors.New("Обнаружено изменение: «STALE dry-run: source, profile mapping, target or dependencies»")
		}
	}
	// Сохраняйте полный отчёт по каждому профилю, а не только сводку, в закрытом хранилище.
	var decoded any
	if err = json.Unmarshal(body, &decoded); err != nil {
		return err
	}
	if out != "" {
		if err = writePrivateIdentityReport0334(out, decoded); err != nil {
			return err
		}
	} else {
		fmt.Println(string(body))
	}
	if current.Status == "blocked" {
		return errors.New("ЗАБЛОКИРОВАНО: проверьте ошибки каждого профиля; импорт не выполнялся")
	}
	if report != "" {
		fmt.Println("Проверенный пробный запуск на работающем Backend и исходных данных: " + current.BatchSHA256)
	}
	return nil
}
