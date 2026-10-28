package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// The CLI reads a full current snapshot exported independently from the
// fenced production deployment. It never fabricates unchanged player data.
func handleMigrationRollback03312(args []string) error {
	if len(args) == 0 {
		return errors.New("rollback requires rollback-plan|rollback-commit|rollback-status")
	}
	cmd := args[0]
	backend := strings.TrimRight(flagValue(args, "--backend", ""), "/")
	run := flagValue(args, "--run", "")
	token := backendToken(args)
	if backend == "" || run == "" || token == "" {
		return errors.New("rollback requires --backend --run --token")
	}
	u, e := url.Parse(backend)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("rollback requires HTTPS or local loopback")
		}
	}
	path := backend + "/api/v1/admin/migration-runs/" + url.PathEscape(run) + "/rollbacks"
	if cmd == "rollback-status" {
		return cutoverRequest03311("GET", path+"/"+url.PathEscape(flagValue(args, "--profile-id", ""))+"/"+url.PathEscape(flagValue(args, "--channel", "")), token, run, nil, false, flagValue(args, "--output", ""))
	}
	if flagValue(args, "--confirm", "") != run || flagValue(args, "--never-writer-fenced", "") != "true" {
		return errors.New("rollback requires exact --confirm run and --never-writer-fenced true")
	}
	revision, e := strconv.ParseInt(flagValue(args, "--expected-revision", ""), 10, 64)
	if e != nil || revision < 1 {
		return errors.New("rollback requires positive --expected-revision")
	}
	body := map[string]any{"profileId": flagValue(args, "--profile-id", ""), "channel": flagValue(args, "--channel", ""), "expectedRevision": revision}
	switch cmd {
	case "rollback-plan", "rollback-commit":
		file := flagValue(args, "--snapshot", "")
		if file == "" {
			return errors.New("rollback requires --snapshot JSON from independently fenced live deployment")
		}
		f, e := os.Open(file)
		if e != nil {
			return e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 {
			return errors.New("rollback snapshot must be a regular JSON file up to 8 MiB")
		}
		var snapshot any
		d := json.NewDecoder(io.LimitReader(f, 8<<20))
		d.DisallowUnknownFields()
		if e = d.Decode(&snapshot); e != nil {
			return e
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return errors.New("snapshot has trailing data or is too large")
		}
		body["current"] = snapshot
		sourceFile := flagValue(args, "--reconciled-source-snapshot", "")
		if sourceFile != "" {
			source, err := os.Open(sourceFile)
			if err != nil {
				return err
			}
			defer source.Close()
			meta, err := source.Stat()
			if err != nil || !meta.Mode().IsRegular() || meta.Size() > 8<<20 {
				return errors.New("reconciled source must be regular JSON <= 8 MiB")
			}
			var data any
			decoder := json.NewDecoder(io.LimitReader(source, 8<<20))
			if err = decoder.Decode(&data); err != nil {
				return err
			}
			var remain any
			if decoder.Decode(&remain) != io.EOF {
				return errors.New("reconciled source has trailing data")
			}
			body["reconciledSource"] = data
			body["reconciliationEvidenceSha256"] = flagValue(args, "--reconciliation-evidence-sha256", "")
		}
		if cmd == "rollback-plan" {
			body["evidenceReference"] = flagValue(args, "--evidence-reference", "")
			body["evidenceSha256"] = flagValue(args, "--evidence-sha256", "")
			path += "/plan"
		} else {
			if flagValue(args, "--source-writer-fenced", "") != "true" {
				return errors.New("commit requires independently fenced source writer")
			}
			body["planSha256"] = flagValue(args, "--plan-sha256", "")
			body["sourceWriterFenced"] = true
			body["neverWriterFenced"] = true
			body["currentEvidenceSha256"] = flagValue(args, "--current-evidence-sha256", "")
			path += "/commit"
		}
	default:
		return errors.New("unknown rollback command")
	}
	// Reuse the production HTTP client with timeouts and redirects disabled.
	// Unlike MIG11, both additional fencing headers are required.
	raw, _ := json.Marshal(body)
	req, e := http.NewRequest("POST", path, strings.NewReader(string(raw)))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Migration-Rollback-Confirm", run)
	req.Header.Set("X-Never-Writer-Fenced", "true")
	if cmd == "rollback-commit" {
		req.Header.Set("X-Migration-Source-Fenced", "true")
	}
	return rollbackSend03312(req, flagValue(args, "--output", ""))
}
