package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Проверка отчёта всегда начинается со свежего снимка БД, рассчитанного сервером. Данные
// сертификации, сформированные вызывающей стороной, не принимаются.
func handleMigrationReport03313(args []string) error {
	if len(args) == 0 {
		return errors.New("Отчёт: требуется «report|report-review|report-review-status»")
	}
	command := args[0]
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	run := flagValue(args, "--run", "")
	token := backendToken(args)
	if backend == "" || run == "" || token == "" {
		return errors.New("Отчёт: требуется «--backend --run --token»")
	}
	u, e := url.Parse(backend)
	if e != nil {
		return e
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Host == "" {
		return errors.New("Некорректное значение: URL серверной части")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("Отчёт: требуется HTTPS или локальный адрес обратной связи")
		}
	}
	endpoint := backend + "/api/v1/admin/migration-runs/" + url.PathEscape(run) + "/report"
	method := "GET"
	var body []byte
	switch command {
	case "report":
	case "report-review-status":
		endpoint += "/review"
	case "report-review":
		if flagValue(args, "--confirm", "") != run {
			return errors.New("Проверка: требуется точный идентификатор запуска в параметре --confirm")
		}
		hash := flagValue(args, "--report-sha256", "")
		evidence := flagValue(args, "--evidence-sha256", "")
		ref := flagValue(args, "--evidence-reference", "")
		if !reportDigest03313(hash) || !reportDigest03313(evidence) || len(ref) < 8 || len(ref) > 256 {
			return errors.New("Проверка: требуется SHA-256 отчёта, независимого свидетельства проверки и ссылка")
		}
		body, e = json.Marshal(map[string]string{"reportSha256": hash, "evidenceSha256": evidence, "evidenceReference": ref})
		if e != nil {
			return e
		}
		endpoint += "/review"
		method = "POST"
	default:
		return fmt.Errorf("Неизвестное значение: команда отчёта %q", command)
	}
	req, e := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Migration-RC-Confirm", run)
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	data, e := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if e != nil {
		return e
	}
	if len(data) >= 32<<20 {
		return errors.New("Превышен допустимый размер: ответ службы отчётов")
	}
	var result map[string]any
	if e = json.Unmarshal(data, &result); e != nil {
		return fmt.Errorf("Некорректное значение: HTTP-ответ с отчётом JSON, код %d", res.StatusCode)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("Ошибка HTTP %d при получении отчёта: %v", res.StatusCode, result["error"])
	}
	return writePrivateIdentityReport0334(flagValue(args, "--output", ""), result)
}
func reportDigest03313(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
