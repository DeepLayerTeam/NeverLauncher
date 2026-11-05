package main

import (
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

// postMigrationAuth0335 передаёт выбранный оператором оригинальный ZIP потоково через TLS. Никогда не
// помещайте хеши учётных записей в аргументы командной строки или ответ JSON.
func postMigrationAuth0335(endpoint, token, sourcePath, algorithm, runID, out string, commit bool) error {
	if sourcePath == "" {
		return errors.New("Для переноса учётных данных требуется --source /path/to/original-gravit.zip")
	}
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("credential import: требуется HTTPS (IP-адрес обратной связи допускается для локальных проверок)")
		}
	}
	f, e := os.Open(sourcePath)
	if e != nil {
		return e
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return e
	}
	if !stat.Mode().IsRegular() || stat.Size() < 1 || stat.Size() > 512<<20 {
		return errors.New("Исходный ZIP должен быть обычным файлом размером от 1 до 512 МиБ")
	}
	request, e := http.NewRequest("POST", endpoint, f)
	if e != nil {
		return e
	}
	request.ContentLength = stat.Size()
	request.Header.Set("Content-Type", "application/zip")
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	request.Header.Set("X-Gravit-Password-Format", algorithm)
	if commit {
		request.Header.Set("X-Migration-Import-Confirm", runID)
	}
	client := &http.Client{Timeout: 30 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 128<<20))
	if e != nil {
		return e
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Учётные данные: HTTP %d: %s", response.StatusCode, string(raw))
	}
	// Никогда не сохраняйте конфиденциальный отчёт миграции в общедоступном файле.
	var value any
	if e = json.Unmarshal(raw, &value); e != nil {
		return e
	}
	return writePrivateIdentityReport0334(out, value)
}
