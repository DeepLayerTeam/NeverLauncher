package main

import (
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

func postMigrationContent0337(endpoint, token, source, run, profilePath, profileID, name, loader, channel, version, out string, commit bool, planSHA, loaderVersion string) error {
	if source == "" || profilePath == "" || profileID == "" || loader == "" || channel == "" || version == "" {
		return errors.New("Требуется: --source --profile-path --profile-id --loader --channel --version")
	}
	if commit {
		if len(planSHA) != 64 {
			return errors.New("content import: требуется зафиксированная контрольная сумма --plan-sha256 из пробного запуска")
		}
		if _, err := hex.DecodeString(planSHA); err != nil {
			return errors.New("Некорректное значение: план миграции SHA-256")
		}
	}
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("Перенос содержимого Gravit: требуется HTTPS или локальный IP-адрес обратной связи")
		}
	}
	f, e := os.Open(source)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return errors.New("ZIP-архив должен быть обычным файлом размером от 1 до 512 МиБ")
	}
	r, e := http.NewRequest("POST", endpoint, f)
	if e != nil {
		return e
	}
	r.ContentLength = st.Size()
	r.Header.Set("Content-Type", "application/zip")
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	for k, v := range map[string]string{"X-Gravit-Profile-Path": profilePath, "X-Profile-ID": profileID, "X-Profile-Name": name, "X-Loader": loader, "X-Loader-Version": loaderVersion, "X-Channel": channel, "X-Version": version} {
		r.Header.Set(k, v)
	}
	if commit {
		r.Header.Set("X-Migration-Content-Confirm", run)
		r.Header.Set("X-Migration-Plan-SHA256", planSHA)
	}
	client := &http.Client{Timeout: 45 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(r)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if e != nil {
		return e
	}
	// Сохраняйте блокирующие отчёты при HTTP 422, не принимая их ошибочно за успешный результат.
	var data any
	if e = json.Unmarshal(raw, &data); e != nil {
		return fmt.Errorf("HTTP %d: некорректный JSON: %w", response.StatusCode, e)
	}
	if out != "" {
		if e = writePrivateIdentityReport0334(out, data); e != nil {
			return e
		}
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Миграция содержимого вернула HTTP %d: %s", response.StatusCode, string(raw))
	}
	if commit {
		var result struct {
			Data struct {
				Complete bool `json:"complete"`
				Plan     struct {
					FilesSHA256 string `json:"filesSha256"`
				} `json:"plan"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &result); err != nil || !result.Data.Complete || len(result.Data.Plan.FilesSHA256) != 64 {
			return errors.New("Backend не подтвердил полную проверенную рабочую область содержимого")
		}
	}
	if out == "" {
		var rendered []byte
		rendered, e = json.MarshalIndent(data, "", "  ")
		if e != nil {
			return e
		}
		fmt.Println(string(rendered))
	}
	return nil
}

// apply-optionals — явное решение оператора после сборки. Изменяется только
// неподписанный черновик v3 до обычной привилегированной операции подписи.
func migrationApplyOptionalsCLI0337(endpoint, token, id, out string) error {
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("catalog mutation: требуется HTTPS")
		}
	}
	r, e := http.NewRequest("POST", endpoint, nil)
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	r.Header.Set("X-Migration-Content-Confirm", id)
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if e != nil {
		return e
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Применение каталога дополнительных компонентов вернуло HTTP %d: %s", resp.StatusCode, string(b))
	}
	var value any
	if e = json.Unmarshal(b, &value); e != nil {
		return e
	}
	if out != "" {
		return writePrivateIdentityReport0334(out, value)
	}
	fmt.Println(string(b))
	return nil
}
