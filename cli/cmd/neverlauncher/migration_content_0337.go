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

func postMigrationContent0337(endpoint, token, source, run, profilePath, profileID, name, loader, channel, version, out string, commit bool) error {
	if source == "" || profilePath == "" || profileID == "" || loader == "" || channel == "" || version == "" {
		return errors.New("--source --profile-path --profile-id --loader --channel --version required")
	}
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("Gravit content transfer requires HTTPS or local loopback IP")
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
		return errors.New("ZIP must be a regular file of 1..512 MiB")
	}
	r, e := http.NewRequest("POST", endpoint, f)
	if e != nil {
		return e
	}
	r.ContentLength = st.Size()
	r.Header.Set("Content-Type", "application/zip")
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	for k, v := range map[string]string{"X-Gravit-Profile-Path": profilePath, "X-Never-Profile-ID": profileID, "X-Never-Profile-Name": name, "X-Never-Loader": loader, "X-Never-Channel": channel, "X-Never-Version": version} {
		r.Header.Set(k, v)
	}
	if commit {
		r.Header.Set("X-Migration-Content-Confirm", run)
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
	// Preserve blocking reports on 422 instead of silently treating them as success.
	var data any
	if e = json.Unmarshal(raw, &data); e != nil {
		return fmt.Errorf("HTTP %d: invalid JSON: %w", response.StatusCode, e)
	}
	if out != "" {
		if e = writePrivateIdentityReport0334(out, data); e != nil {
			return e
		}
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("content migration HTTP %d: %s", response.StatusCode, string(raw))
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

// apply-optionals is an explicit post-build operator decision. It modifies
// only an unsigned v3 draft, before the normal privileged sign operation.
func migrationApplyOptionalsCLI0337(endpoint, token, id, out string) error {
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("catalog mutation requires HTTPS")
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
		return fmt.Errorf("apply optional catalog HTTP %d: %s", resp.StatusCode, string(b))
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
