// Package neverapi provides a production HTTP client for the canonical NeverLauncher OpenAPI v1.
package neverapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const ContractVersion = "1.0.0"
const maxResponseBytes = 8 << 20

type Operation struct{ Method, Path string }
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}
type APIError struct {
	Status                   int
	Code, Message, RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("neverlauncher API status=%d code=%q requestId=%q: %s", e.Status, e.Code, e.RequestID, e.Message)
}

var segment = regexp.MustCompile(`\{([^{}]+)\}`)

func New(baseURL, token string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("invalid API base URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("API requires HTTPS (HTTP is only allowed on loopback)")
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func Path(template string, params map[string]string) (string, error) {
	if !strings.HasPrefix(template, "/") || strings.Contains(template, "?") || strings.Contains(template, "#") {
		return "", errors.New("invalid route template")
	}
	used := map[string]bool{}
	var resolveErr error
	resolved := segment.ReplaceAllStringFunc(template, func(match string) string {
		key := match[1 : len(match)-1]
		v, ok := params[key]
		used[key] = true
		if !ok || v == "" || v == "." || v == ".." || strings.ContainsAny(v, "/\\") {
			resolveErr = fmt.Errorf("invalid path parameter %s", key)
			return ""
		}
		return url.PathEscape(v)
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	for k := range params {
		if !used[k] {
			return "", fmt.Errorf("unexpected path parameter %s", k)
		}
	}
	if strings.Contains(resolved, "{") || strings.Contains(resolved, "}") {
		return "", errors.New("unresolved route parameter")
	}
	return resolved, nil
}
func (c *Client) Call(ctx context.Context, operationID string, params map[string]string, query url.Values, request any, response any, idempotencyKey string) error {
	op, ok := Operations[operationID]
	if !ok {
		return fmt.Errorf("unknown OpenAPI operation: %s", operationID)
	}
	path, err := Path(op.Path, params)
	if err != nil {
		return err
	}
	return c.Request(ctx, op.Method, path, query, request, response, idempotencyKey)
}
func (c *Client) Request(ctx context.Context, method, path string, query url.Values, request any, response any, key string) error {
	if c == nil || c.HTTP == nil {
		return errors.New("uninitialized client")
	}
	if !strings.HasPrefix(path, "/api/v1/") && path != "/health" && path != "/ready" && path != "/metrics" && !strings.HasPrefix(path, "/api/profiles/minecraft") && !strings.HasPrefix(path, "/api/user/profile/") && !strings.HasPrefix(path, "/authserver/") && !strings.HasPrefix(path, "/sessionserver/") {
		return errors.New("route outside supported OpenAPI v1")
	}
	if strings.Contains(path, "?") || strings.Contains(path, "#") || strings.Contains(path, "..") || strings.HasPrefix(path, "//") {
		return errors.New("unsafe request path")
	}
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if key != "" {
		if strings.ContainsAny(key, "\r\n") {
			return errors.New("invalid idempotency key")
		}
		req.Header.Set("Idempotency-Key", key)
	}
	result, err := c.doNoRedirect(req)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	data, err := io.ReadAll(io.LimitReader(result.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("API response exceeds 8 MiB")
	}
	if result.StatusCode < 200 || result.StatusCode > 299 {
		var e struct {
			Code    string `json:"code"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		if msg == "" {
			msg = e.Error
		}
		if msg == "" {
			msg = http.StatusText(result.StatusCode)
		}
		return &APIError{Status: result.StatusCode, Code: e.Code, Message: msg, RequestID: result.Header.Get("X-Correlation-ID")}
	}
	if response != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, response); err != nil {
			return fmt.Errorf("decode API response: %w", err)
		}
	}
	return nil
}

// CheckCompatibility accepts current API contract v1 and the deployed 0.45.11 predecessor.
// Older backends did not publish X-Launcher-API-Contract, so /ready version is checked.
func (c *Client) CheckCompatibility(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/ready", nil)
	if err != nil {
		return err
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("backend not ready: %d", resp.StatusCode)
	}
	contract := resp.Header.Get("X-Launcher-API-Contract")
	if contract != "" {
		if contract != ContractVersion {
			return fmt.Errorf("incompatible API contract: %q", contract)
		}
		return nil
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&info); err != nil {
		return err
	}
	if info.Version != "0.45.11" && info.Version != "0.45.12" {
		return fmt.Errorf("backend %q has no verified v1 compatibility", info.Version)
	}
	return nil
}

// CallRaw sends multipart/binary payloads to any registered OpenAPI operation.
// Use Call for JSON; raw responses are returned as bytes without lossy JSON coercion.
func (c *Client) CallRaw(ctx context.Context, operationID string, params map[string]string, query url.Values, body []byte, contentType, idempotencyKey string) ([]byte, error) {
	op, ok := Operations[operationID]
	if !ok {
		return nil, fmt.Errorf("unknown OpenAPI operation: %s", operationID)
	}
	path, err := Path(op.Path, params)
	if err != nil {
		return nil, err
	}
	if c == nil || c.HTTP == nil {
		return nil, errors.New("uninitialized client")
	}
	if idempotencyKey != "" && strings.ContainsAny(idempotencyKey, "\r\n") {
		return nil, errors.New("invalid idempotency key")
	}
	target := c.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, errors.New("API response exceeds 8 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		message := e.Message
		if message == "" {
			message = e.Error
		}
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{Status: resp.StatusCode, Code: e.Code, Message: message, RequestID: resp.Header.Get("X-Correlation-ID")}
	}
	return data, nil
}

// CallStream transfers an OpenAPI operation's request and response without
// buffering the successful response. Multipart bodies can be supplied via a
// streaming io.Reader; callers own requestReader and responseWriter.
// A response limit of 0 uses the default 1 GiB cap. The caller must discard
// a partially written destination if an error is returned.
func (c *Client) CallStream(ctx context.Context, operationID string, params map[string]string, query url.Values, requestReader io.Reader, contentType string, responseWriter io.Writer, maxResponseBytes int64, idempotencyKey string) (int64, error) {
	op, ok := Operations[operationID]
	if !ok {
		return 0, fmt.Errorf("unknown OpenAPI operation: %s", operationID)
	}
	path, err := Path(op.Path, params)
	if err != nil {
		return 0, err
	}
	return c.RequestStream(ctx, op.Method, path, query, requestReader, contentType, responseWriter, maxResponseBytes, idempotencyKey)
}

// RequestStream prevents cross-origin redirects even if a caller provided an
// http.Client with redirect-following enabled. It does not alter that client.
func (c *Client) RequestStream(ctx context.Context, method, path string, query url.Values, requestReader io.Reader, contentType string, responseWriter io.Writer, maxResponseBytes int64, key string) (int64, error) {
	if c == nil || c.HTTP == nil {
		return 0, errors.New("uninitialized client")
	}
	if !strings.HasPrefix(path, "/api/v1/") && path != "/health" && path != "/ready" && path != "/metrics" && !strings.HasPrefix(path, "/api/profiles/minecraft") && !strings.HasPrefix(path, "/api/user/profile/") && !strings.HasPrefix(path, "/authserver/") && !strings.HasPrefix(path, "/sessionserver/") {
		return 0, errors.New("route outside supported OpenAPI v1")
	}
	if strings.Contains(path, "?") || strings.Contains(path, "#") || strings.Contains(path, "..") || strings.HasPrefix(path, "//") {
		return 0, errors.New("unsafe request path")
	}
	if key != "" && strings.ContainsAny(key, "\r\n") {
		return 0, errors.New("invalid idempotency key")
	}
	if maxResponseBytes == 0 {
		maxResponseBytes = 1 << 30
	}
	if maxResponseBytes < 0 || maxResponseBytes > 1<<30 {
		return 0, errors.New("invalid response limit (max 1 GiB)")
	}
	if responseWriter == nil {
		return 0, errors.New("response writer required")
	}
	target := c.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, requestReader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "*/*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not leak an authorization token to a redirect target, and do not
		// parse attacker-controlled unbounded error responses.
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytesForError+1))
		if err != nil {
			return 0, err
		}
		if len(data) > maxResponseBytesForError {
			return 0, errors.New("API error response too large")
		}
		var parsed struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(data, &parsed)
		message := parsed.Message
		if message == "" {
			message = parsed.Error
		}
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return 0, &APIError{Status: resp.StatusCode, Code: parsed.Code, Message: message, RequestID: resp.Header.Get("X-Correlation-ID")}
	}
	if resp.ContentLength > maxResponseBytes {
		return 0, errors.New("API stream exceeds configured size limit")
	}
	// LimitReader(max+1) detects a chunked response larger than announced;
	// no full-response allocation is performed.
	n, err := io.Copy(responseWriter, io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return n, err
	}
	if n > maxResponseBytes {
		return n, errors.New("API stream exceeds configured size limit")
	}
	return n, nil
}

const maxResponseBytesForError = 1 << 20

// doNoRedirect protects bearer credentials and prevents treating a cross-origin
// redirect as an API response. A caller-supplied client cannot override it.
func (c *Client) doNoRedirect(req *http.Request) (*http.Response, error) {
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client.Do(req)
}
