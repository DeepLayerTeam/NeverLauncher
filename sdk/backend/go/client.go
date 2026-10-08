package neverextensions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultTimeout = 10 * time.Second

type Client struct {
	env      HostEnvironment
	http     *http.Client
	mu       sync.RWMutex
	hello    HelloResponse
	callback *CallbackServer
}

type CapabilityError struct {
	Capability string
	StatusCode int
	Body       string
}

func (e *CapabilityError) Error() string {
	return fmt.Sprintf("NeverLauncher capability %s failed: HTTP %d: %s", e.Capability, e.StatusCode, strings.TrimSpace(e.Body))
}

func Environment() (HostEnvironment, error) {
	env := HostEnvironment{
		ExtensionId:         strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_ID")),
		ExtensionApiVersion: strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_API_VERSION")),
		Version:             strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_VERSION")),
		Scope:               strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_SCOPE")),
		ScopeId:             strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_SCOPE_ID")),
		Target:              strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_TARGET")),
		HostUrl:             strings.TrimRight(strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_HOST_URL")), "/"),
		HostToken:           strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_HOST_TOKEN")),
		CallbackToken:       strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN")),
		InstanceId:          strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_INSTANCE_ID")),
	}
	if env.HostUrl == "" || env.HostToken == "" || env.ExtensionId == "" || env.InstanceId == "" || env.ExtensionApiVersion == "" {
		return HostEnvironment{}, errors.New("NeverLauncher Extension Host environment is incomplete")
	}
	if env.Scope == "" {
		env.Scope = "global"
	}
	return env, nil
}

func NewFromEnvironment() (*Client, error) {
	env, err := Environment()
	if err != nil {
		return nil, err
	}
	return New(env), nil
}

func New(env HostEnvironment) *Client {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{env: env, http: &http.Client{Transport: transport, Timeout: defaultTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) Environment() HostEnvironment { return c.env }
func (c *Client) HelloResponse() HelloResponse { c.mu.RLock(); defer c.mu.RUnlock(); return c.hello }

func (c *Client) doJSON(ctx context.Context, method, path string, input any, output any) error {
	var body io.Reader
	if input != nil {
		buf, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.env.HostUrl+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.env.HostToken)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &CapabilityError{Capability: path, StatusCode: resp.StatusCode, Body: string(data)}
	}
	if output != nil && len(bytes.TrimSpace(data)) != 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return nil
}

func (c *Client) Hello(ctx context.Context, callbackURL string) (HelloResponse, error) {
	req := HelloRequest{ProtocolVersion: HostProtocolVersion, ExtensionApiVersion: ExtensionAPIVersion, InstanceId: c.env.InstanceId, ExtensionId: c.env.ExtensionId, Pid: os.Getpid(), CallbackUrl: strings.TrimSpace(callbackURL)}
	var out HelloResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/hello", req, &out); err != nil {
		return HelloResponse{}, err
	}
	if out.ProtocolVersion != HostProtocolVersion || out.ExtensionApiVersion != ExtensionAPIVersion || out.InstanceId != c.env.InstanceId {
		return HelloResponse{}, errors.New("NeverLauncher Host hello identity/protocol mismatch")
	}
	c.mu.Lock()
	c.hello = out
	c.mu.Unlock()
	return out, nil
}

func (c *Client) Heartbeat(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/heartbeat", map[string]any{}, nil)
}

func (c *Client) HeartbeatLoop(ctx context.Context) error {
	resp := c.HelloResponse()
	interval := 5 * time.Second
	if resp.HeartbeatTimeoutSeconds > 0 {
		candidate := time.Duration(resp.HeartbeatTimeoutSeconds) * time.Second / 3
		if candidate >= time.Second {
			interval = candidate
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.Heartbeat(callCtx)
			cancel()
			if err != nil {
				return err
			}
		}
	}
}

func (c *Client) Log(ctx context.Context, level, message string, fields map[string]any) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/log", LogRequest{Level: level, Message: message, Fields: fields}, nil)
}

func (c *Client) Capability(ctx context.Context, name string, request any, response any) error {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		return errors.New("invalid capability name")
	}
	return c.doJSON(ctx, http.MethodPost, "/v1/capabilities/"+name, request, response)
}

type Health struct {
	Status any `json:"status"`
}
type ExtensionSelf map[string]any
type ProjectResult struct {
	Project map[string]any `json:"project"`
}
type ReleaseListResult struct {
	Items []map[string]any `json:"items"`
}
type StorageReadResult struct {
	Size          int    `json:"size"`
	ContentBase64 string `json:"contentBase64"`
}
type SecretResult struct {
	Name        string `json:"name"`
	ValueBase64 string `json:"valueBase64"`
}

func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.Capability(ctx, "host.health", nil, &out)
	return out, err
}
func (c *Client) Self(ctx context.Context) (ExtensionSelf, error) {
	var out ExtensionSelf
	err := c.Capability(ctx, "extension.self", nil, &out)
	return out, err
}
func (c *Client) Project(ctx context.Context, projectID string) (map[string]any, error) {
	var out ProjectResult
	err := c.Capability(ctx, "project.get", map[string]string{"projectId": projectID}, &out)
	return out.Project, err
}
func (c *Client) Releases(ctx context.Context, projectID string) ([]map[string]any, error) {
	var out ReleaseListResult
	err := c.Capability(ctx, "release.list", map[string]string{"projectId": projectID}, &out)
	return out.Items, err
}
func (c *Client) StorageRead(ctx context.Context, projectID, version, path string) ([]byte, error) {
	var out StorageReadResult
	if err := c.Capability(ctx, "storage.read", map[string]string{"projectId": projectID, "version": version, "path": path}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.ContentBase64)
}
func (c *Client) Secret(ctx context.Context, name string) ([]byte, error) {
	var out SecretResult
	if err := c.Capability(ctx, "secret.get", map[string]string{"name": name}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.ValueBase64)
}
func (c *Client) Telemetry(ctx context.Context, projectID, event, status string) error {
	var out map[string]any
	return c.Capability(ctx, "telemetry.emit", map[string]string{"projectId": projectID, "event": event, "status": status}, &out)
}

func (c *Client) Subscribe(ctx context.Context, eventType, mode string) (EventSubscription, error) {
	var out EventSubscription
	err := c.doJSON(ctx, http.MethodPost, "/v1/events/subscriptions", map[string]string{"eventType": eventType, "mode": mode}, &out)
	return out, err
}
func (c *Client) Unsubscribe(ctx context.Context, id int64) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/events/subscriptions/"+strconv.FormatInt(id, 10), nil, nil)
}

// StartCallbackServer starts the loopback callback endpoint required for events/hooks.
// The returned URL is safe to pass to Hello. Close the server when the extension exits.
func (c *Client) StartCallbackServer(events EventHandler, hooks HookHandler) (*CallbackServer, error) {
	if c.env.CallbackToken == "" {
		return nil, errors.New("NeverLauncher callback token is missing")
	}
	s, err := newCallbackServer(c.env.CallbackToken, events, hooks)
	if err != nil {
		return nil, err
	}
	c.callback = s
	return s, nil
}
