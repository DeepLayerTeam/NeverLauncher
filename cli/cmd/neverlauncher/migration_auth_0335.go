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

// postMigrationAuth0335 streams an operator-selected original ZIP over TLS.
// Never put account hashes into a command-line argument or JSON response.
func postMigrationAuth0335(endpoint, token, sourcePath, algorithm, runID, out string, commit bool) error {
	if sourcePath == "" {
		return errors.New("credentials require --source /path/to/original-gravit.zip")
	}
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("credential import requires HTTPS (loopback IP allowed for local tests)")
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
		return errors.New("source ZIP must be a regular file of 1..512 MiB")
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
		return fmt.Errorf("credentials HTTP %d: %s", response.StatusCode, string(raw))
	}
	// Never place a sensitive migration report into a world-readable file.
	var value any
	if e = json.Unmarshal(raw, &value); e != nil {
		return e
	}
	return writePrivateIdentityReport0334(out, value)
}
