package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	if flagValue(args, "--confirm", "") != run || flagValue(args, "--writer-fenced", "") != "true" {
		return errors.New("rollback requires exact --confirm run and --writer-fenced true")
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
		snapshot, snapshotHash, e := rollbackReadSnapshot0448(file)
		if e != nil {
			return e
		}
		body["current"] = snapshot
		sourceFile := flagValue(args, "--reconciled-source-snapshot", "")
		if sourceFile != "" {
			data, _, err := rollbackReadSnapshot0448(sourceFile)
			if err != nil {
				return err
			}
			body["reconciledSource"] = data
			body["reconciliationEvidenceSha256"] = flagValue(args, "--reconciliation-evidence-sha256", "")
		}
		if cmd == "rollback-plan" {
			body["evidenceReference"] = flagValue(args, "--evidence-reference", file)
			if expected := flagValue(args, "--evidence-sha256", ""); expected != "" && expected != snapshotHash {
				return errors.New("snapshot file SHA-256 differs from rollback evidence SHA-256")
			}
			body["evidenceSha256"] = snapshotHash
			path += "/plan"
		} else {
			if flagValue(args, "--source-writer-fenced", "") != "true" {
				return errors.New("commit requires independently fenced source writer")
			}
			body["planSha256"] = flagValue(args, "--plan-sha256", "")
			body["sourceWriterFenced"] = true
			body["neverWriterFenced"] = true
			if expected := flagValue(args, "--current-evidence-sha256", ""); expected != "" && expected != snapshotHash {
				return errors.New("fresh snapshot SHA-256 differs from rollback evidence")
			}
			body["currentEvidenceSha256"] = snapshotHash
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
	req.Header.Set("X-Writer-Fenced", "true")
	if cmd == "rollback-commit" {
		req.Header.Set("X-Migration-Source-Fenced", "true")
	}
	return rollbackSend03312(req, flagValue(args, "--output", ""))
}

// rollbackReadSnapshot0448 hashes the EXACT bytes sent to the server, avoiding
// the TOCTOU introduced by hashing a separately re-read operator file. Never
// use an arbitrary --evidence-sha256 to authorize a new rollback plan.
func rollbackReadSnapshot0448(path string) (any, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 8<<20 {
		return nil, "", errors.New("rollback snapshot must be a regular JSON file up to 8 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > 8<<20 {
		return nil, "", errors.New("rollback snapshot exceeds 8 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var snapshot any
	if err = d.Decode(&snapshot); err != nil {
		return nil, "", err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, "", errors.New("snapshot has trailing data")
	}
	sum := sha256.Sum256(raw)
	return snapshot, hex.EncodeToString(sum[:]), nil
}
