package main

import (
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

// CLI никогда не отправляет сырые ключи и сопоставления идентичностей. Подтверждение явное, а не флаг
// по умолчанию; ответные файлы создаёт защищённый механизм записи отчётов.
func postMigrationSecurity0336(endpoint, token, runID, out string, activate bool, confirmation string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("Для «security reset» требуется «HTTPS (or explicit local IP loopback)»")
		}
	}
	if activate && confirmation != runID {
		return errors.New("Для «activate-security» требуется «--confirm with exact --run ID; provision new independent Never keys first»")
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	if activate {
		req.Header.Set("X-Migration-Trust-Confirm", runID)
		req.Header.Set("X-Migration-Fresh-Keys-Confirmed", "true")
	}
	client := &http.Client{Timeout: 15 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("security reset HTTP %d", res.StatusCode)
	}
	// Не дублируйте код запросов: GET API использует ту же структуру ответа и логику закрытого вывода,
	// но здесь применяется ограниченный по объёму читатель закрытого вывода.
	return readMigrationSecurityResponse0336(res, out)
}

// Аутентифицированный административный ответ содержит небольшую сводку фиксированного размера; не
// доверяйте Content-Length и ограничивайте тело до декодирования или записи отчёта.
func readMigrationSecurityResponse0336(res *http.Response, out string) error {
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return err
	}
	var summary map[string]any
	if err = json.Unmarshal(raw, &summary); err != nil {
		return err
	}
	return writePrivateIdentityReport0334(out, summary)
}
