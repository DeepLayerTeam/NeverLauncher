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

// No raw keys or identity maps are ever sent by CLI. Confirmation is explicit,
// not a default flag, and response files use the protected report writer.
func postMigrationSecurity0336(endpoint, token, runID, out string, activate bool, confirmation string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("security reset requires HTTPS (or explicit local IP loopback)")
		}
	}
	if activate && confirmation != runID {
		return errors.New("activate-security requires --confirm with exact --run ID; provision new independent Never keys first")
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
	// Do not duplicate request code: GET API uses the same response shape and
	// private-output logic, but here use the bounded private output reader.
	return readMigrationSecurityResponse0336(res, out)
}

// Authenticated administrative response has a fixed small summary; do not
// trust Content-Length and cap body before decoding or writing a report.
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
