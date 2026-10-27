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

func migrationModuleEndpoint0338(endpoint string) error {
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("Gravit module upload requires HTTPS or loopback IP")
}
func migrationModuleAnalyze0338(endpoint, token, source, out string) error {
	if err := migrationModuleEndpoint0338(endpoint); err != nil {
		return err
	}
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return errors.New("expected regular source ZIP 1..512 MiB")
	}
	req, err := http.NewRequest("POST", endpoint, f)
	if err != nil {
		return err
	}
	req.ContentLength = st.Size()
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	client := &http.Client{Timeout: 45 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("module inspection HTTP %d: %s", resp.StatusCode, raw)
	}
	var parsed any
	if err = json.Unmarshal(raw, &parsed); err != nil {
		return err
	}
	if out != "" {
		return writePrivateIdentityReport0334(out, parsed)
	}
	fmt.Println(string(raw))
	return nil
}
func migrationModuleEnroll0338(endpoint, token, run, out, wrapper, id, name, kind, profile, key string, fresh bool) error {
	if err := migrationModuleEndpoint0338(endpoint); err != nil {
		return err
	}
	if !fresh {
		return errors.New("--fresh-keys-confirmed required: newly generated independent Never Ed25519 keypair")
	}
	if run == "" || wrapper == "" || id == "" || kind == "" || profile == "" || key == "" {
		return errors.New("--run --wrapper --server-id --kind --profile-id --public-key required")
	}
	body := map[string]string{"wrapperPath": wrapper, "id": id, "name": name, "kind": kind, "profileId": profile, "publicKey": key}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Migration-Modules-Confirm", run)
	req.Header.Set("X-Migration-Fresh-Keys-Confirmed", "true")
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("ServerBridge enrollment HTTP %d: %s", resp.StatusCode, answer)
	}
	var parsed any
	if err = json.Unmarshal(answer, &parsed); err != nil {
		return err
	}
	if out != "" {
		return writePrivateIdentityReport0334(out, parsed)
	}
	fmt.Println(string(answer))
	return nil
}
