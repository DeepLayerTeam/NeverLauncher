package hostcontrol

// The Backend operates ONLY explicitly provisioned RemoteControl nodes. It
// never accepts a destination or credentials from an HTTP request.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Target struct {
	URL        string `json:"url"`
	NodeID     string `json:"nodeId"`
	CAFile     string `json:"caFile"`
	TokenFile  string `json:"tokenFile"`
	ClientCert string `json:"clientCert,omitempty"`
	ClientKey  string `json:"clientKey,omitempty"`
}
type Status struct {
	NodeID string `json:"nodeId"`
	Status struct {
		Configured      bool   `json:"configured"`
		ObservedStatus  string `json:"observedStatus"`
		ProcessAlive    bool   `json:"processAlive"`
		SupervisorAlive bool   `json:"supervisorAlive"`
		SessionID       string `json:"sessionId"`
		Telemetry       *struct {
			ProcessID                int    `json:"processId"`
			ProcessResidentBytes     uint64 `json:"processResidentBytes,omitempty"`
			HostTotalMemoryBytes     uint64 `json:"hostTotalMemoryBytes,omitempty"`
			HostAvailableMemoryBytes uint64 `json:"hostAvailableMemoryBytes,omitempty"`
		} `json:"telemetry,omitempty"`
	} `json:"status"`
}
type Receipt struct {
	KeyHash string          `json:"keyHash"`
	Action  string          `json:"action"`
	State   string          `json:"state"`
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error"`
}

type Client struct {
	url    string
	nodeID string
	token  string
	client *http.Client
}

func privateFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute secret/CA file path required")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("host-control private file must not be accessible by group/others")
	}
	return os.ReadFile(path)
}
func LoadTarget(path, serverID string) (Target, error) {
	var empty Target
	if path == "" {
		return empty, errors.New("host control is not configured")
	}
	b, err := privateFile(path)
	if err != nil {
		return empty, err
	}
	if len(b) > 1<<20 {
		return empty, errors.New("host target registry too large")
	}
	var targets map[string]Target
	if err = json.Unmarshal(b, &targets); err != nil {
		return empty, err
	}
	t, ok := targets[serverID]
	if !ok {
		return empty, errors.New("host control target not provisioned")
	}
	if t.NodeID == "" || t.CAFile == "" || t.TokenFile == "" {
		return empty, errors.New("host target missing identity or trust configuration")
	}
	u, err := url.Parse(t.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return empty, errors.New("host target must be an HTTPS origin")
	}
	return t, nil
}
func NewClient(t Target) (*Client, error) {
	ca, err := privateFile(t.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("host-control CA is invalid")
	}
	token, err := privateFile(t.TokenFile)
	if err != nil {
		return nil, err
	}
	secret := strings.TrimSpace(string(token))
	if len(secret) < 32 || len(secret) > 4096 {
		return nil, errors.New("invalid host-control token")
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if t.ClientCert != "" || t.ClientKey != "" {
		if t.ClientCert == "" || t.ClientKey == "" {
			return nil, errors.New("both client certificate and key are required")
		}
		certPEM, err := privateFile(t.ClientCert)
		if err != nil {
			return nil, err
		}
		keyPEM, err := privateFile(t.ClientKey)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 10 * time.Second}
	return &Client{url: strings.TrimRight(t.URL, "/"), nodeID: t.NodeID, token: secret, client: &http.Client{Timeout: 105 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) request(ctx context.Context, method, path, key string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return 0, nil, err
	}
	if len(b) > 65536 || !json.Valid(b) {
		return 0, nil, errors.New("invalid or oversized host response")
	}
	return resp.StatusCode, b, nil
}
func (c *Client) Status(ctx context.Context) (Status, error) {
	code, b, err := c.request(ctx, http.MethodGet, "/v1/host/status", "", nil)
	if err != nil {
		return Status{}, err
	}
	if code != 200 {
		return Status{}, fmt.Errorf("host status HTTP %d", code)
	}
	var s Status
	if err = json.Unmarshal(b, &s); err != nil {
		return Status{}, err
	}
	if s.NodeID != c.nodeID {
		return Status{}, errors.New("host node identity mismatch")
	}
	return s, nil
}
func (c *Client) Execute(ctx context.Context, action, key string) (Receipt, error) {
	if action != "start" && action != "stop" && action != "restart" {
		return Receipt{}, errors.New("invalid host action")
	}
	if len(key) < 16 || len(key) > 128 {
		return Receipt{}, errors.New("invalid host idempotency key")
	}
	payload, _ := json.Marshal(map[string]string{"action": action})
	code, b, err := c.request(ctx, http.MethodPost, "/v1/host/commands", key, payload)
	if err != nil {
		return Receipt{}, err
	}
	if code != 200 && code != 409 {
		return Receipt{}, fmt.Errorf("host command HTTP %d", code)
	}
	var r Receipt
	if err = json.Unmarshal(b, &r); err != nil {
		return Receipt{}, err
	}
	hash := sha256.Sum256([]byte(key))
	if r.Action != action || (r.State != "succeeded" && r.State != "indeterminate") || r.KeyHash != hex.EncodeToString(hash[:]) {
		return Receipt{}, errors.New("host command receipt does not match requested action")
	}
	return r, nil
}

// Success is based on observed host state, not merely a successful HTTP POST.
// A restart must change the Host Supervisor session when a prior session existed.
func Verified(action string, before, after Status, receipt Receipt) bool {
	if receipt.State != "succeeded" || before.NodeID == "" || before.NodeID != after.NodeID {
		return false
	}
	s := after.Status
	switch action {
	case "start":
		return s.Configured && s.ProcessAlive && s.SupervisorAlive && s.ObservedStatus == "running"
	case "stop":
		return !s.ProcessAlive && (s.ObservedStatus == "stopped" || s.ObservedStatus == "not-started") && !s.SupervisorAlive
	case "restart":
		return s.Configured && s.ProcessAlive && s.SupervisorAlive && s.ObservedStatus == "running" && s.SessionID != "" && (before.Status.SessionID == "" || before.Status.SessionID != s.SessionID)
	default:
		return false
	}
}
