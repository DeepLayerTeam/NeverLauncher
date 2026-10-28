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
	"strconv"
	"strings"
	"time"
)

// The actual publication pointer changes on the backend. CLI never modifies
// the source Gravit database or mistakes an operator receipt for source proof.
func handleMigrationCutover03311(args []string) error {
	if len(args) == 0 {
		return errors.New("cutover requires cutover-list|cutover-stage|cutover-activate|cutover-cancel")
	}
	cmd := args[0]
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	token := backendToken(args)
	run := flagValue(args, "--run", "")
	if backend == "" || token == "" || run == "" {
		return errors.New("cutover requires --backend --token --run")
	}
	u, e := url.Parse(backend)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("cutover requires HTTPS or local loopback")
		}
	}
	endpoint := backend + "/api/v1/admin/migration-runs/" + url.PathEscape(run) + "/cutovers"
	if cmd == "cutover-list" {
		return cutoverRequest03311("GET", endpoint, token, run, nil, false, flagValue(args, "--output", ""))
	}
	if flagValue(args, "--confirm", "") != run {
		return errors.New("cutover mutation requires --confirm with the exact migration run ID")
	}
	profile := flagValue(args, "--profile-id", "")
	channel := flagValue(args, "--channel", "")
	var body any
	fenced := false
	switch cmd {
	case "cutover-stage":
		rev, e := strconv.ParseInt(flagValue(args, "--head-revision", ""), 10, 64)
		if e != nil {
			return errors.New("stage requires --head-revision (including 0)")
		}
		body = map[string]any{"profileId": profile, "channel": channel, "releaseId": flagValue(args, "--release-id", ""), "stageId": flagValue(args, "--stage-id", ""), "expectedHeadRevision": rev}
		endpoint += "/stage"
	case "cutover-activate":
		rev, e := strconv.ParseInt(flagValue(args, "--expected-revision", ""), 10, 64)
		if e != nil {
			return errors.New("activate requires --expected-revision")
		}
		if flagValue(args, "--source-fenced", "") != "true" {
			return errors.New("activate requires explicit --source-fenced true after stopping the external Gravit writer")
		}
		body = map[string]any{"profileId": profile, "channel": channel, "expectedRevision": rev, "sourceFenceReference": flagValue(args, "--fence-reference", ""), "sourceFenceEvidenceSha256": flagValue(args, "--fence-sha256", ""), "currentSourceSnapshotSha256": flagValue(args, "--source-snapshot-sha256", "")}
		endpoint += "/activate"
		fenced = true
	case "cutover-cancel":
		rev, e := strconv.ParseInt(flagValue(args, "--expected-revision", ""), 10, 64)
		if e != nil {
			return errors.New("cancel requires --expected-revision")
		}
		body = map[string]any{"profileId": profile, "channel": channel, "expectedRevision": rev}
		endpoint += "/cancel"
	default:
		return fmt.Errorf("unknown cutover command %s", cmd)
	}
	return cutoverRequest03311("POST", endpoint, token, run, body, fenced, flagValue(args, "--output", ""))
}
func cutoverRequest03311(method, endpoint, token, run string, body any, fenced bool, out string) error {
	var payload io.Reader
	if body != nil {
		data, e := json.Marshal(body)
		if e != nil {
			return e
		}
		payload = bytes.NewReader(data)
	}
	req, e := http.NewRequest(method, endpoint, payload)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Migration-Cutover-Confirm", run)
	}
	if fenced {
		req.Header.Set("X-Migration-Source-Fenced", "true")
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("cutover request HTTP %d (check durable state before retry)", resp.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return e
	}
	var decoded map[string]any
	if e = json.Unmarshal(data, &decoded); e != nil {
		return e
	}
	return writePrivateIdentityReport0334(out, decoded)
}
