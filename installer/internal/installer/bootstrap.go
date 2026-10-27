package installer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func readSecretFile(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return "", errors.New("secret file must be regular 0600")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if len(s) < 12 || len(s) > 4096 {
		return "", errors.New("invalid secret length")
	}
	return s, nil
}
func BootstrapOwner(base, email, name, passwordFile, tokenFile string) error {
	token, err := readSecretFile(tokenFile)
	if err != nil {
		return err
	}
	return bootstrapWithToken(base, email, name, passwordFile, token)
}

// BootstrapOwnerFromEnv reads the generated installation environment without
// ever sending the token as a command line argument.
func BootstrapOwnerFromEnv(base, email, name, passwordFile, envFile string) error {
	st, err := os.Lstat(envFile)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return errors.New("installer environment must be regular 0600")
	}
	f, err := os.Open(envFile)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 64<<10))
	var token string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NEVERLAUNCHER_BOOTSTRAP_TOKEN=") {
			if token != "" {
				return errors.New("duplicate bootstrap token")
			}
			token = strings.TrimSpace(strings.TrimPrefix(line, "NEVERLAUNCHER_BOOTSTRAP_TOKEN="))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if token == "" {
		return errors.New("bootstrap token missing from environment")
	}
	return bootstrapWithToken(base, email, name, passwordFile, token)
}
func bootstrapWithToken(base, email, name, passwordFile, token string) error {
	if err := validatePublicURL(base); err != nil {
		return err
	}
	if !strings.Contains(email, "@") || len(email) > 254 || len(name) > 200 {
		return errors.New("invalid owner email/name")
	}
	password, err := readSecretFile(passwordFile)
	if err != nil {
		return err
	}
	if len(token) < 32 || len(token) > 4096 {
		return errors.New("invalid token length")
	}
	payload, err := json.Marshal(map[string]string{"email": email, "displayName": name, "password": password, "actor": "neverlauncher-install"})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/install/bootstrap-admin", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NeverLauncher-Bootstrap-Token", token)
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("bootstrap redirects forbidden") }, Transport: &http.Transport{Proxy: nil}}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8192))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusCreated {
		return fmt.Errorf("owner bootstrap refused, HTTP %d: %s", res.StatusCode, string(body))
	}
	return nil
}
