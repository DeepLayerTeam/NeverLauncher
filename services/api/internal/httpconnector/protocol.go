package httpconnector

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

const (
	headerKeyID       = "X-NeverLauncher-Key-Id"
	headerTimestamp   = "X-NeverLauncher-Timestamp"
	headerNonce       = "X-NeverLauncher-Nonce"
	headerSignature   = "X-NeverLauncher-Signature"
	headerConnectorID = "X-NeverLauncher-Connector-Id"
)

type signedClient struct {
	cfg      RuntimeConfig
	client   *http.Client
	nonceMu  sync.Mutex
	consumed map[string]time.Time
}

type requestEnvelope struct {
	ProtocolVersion string    `json:"protocolVersion"`
	RequestID       string    `json:"requestId"`
	Timestamp       time.Time `json:"timestamp"`
	Identifier      string    `json:"identifier,omitempty"`
	Password        string    `json:"password,omitempty"`
	Subject         string    `json:"subject,omitempty"`
	ProviderToken   string    `json:"providerToken,omitempty"`
}

type identityResponse struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Issuer          string         `json:"issuer"`
	Subject         string         `json:"subject"`
	Username        string         `json:"username,omitempty"`
	Email           string         `json:"email,omitempty"`
	DisplayName     string         `json:"displayName,omitempty"`
	Groups          []string       `json:"groups,omitempty"`
	Roles           []string       `json:"roles,omitempty"`
	Claims          map[string]any `json:"claims,omitempty"`
	AuthMethods     []string       `json:"authMethods,omitempty"`
	ProviderToken   string         `json:"providerToken,omitempty"`
	ExpiresAt       *time.Time     `json:"expiresAt,omitempty"`
}

type healthResponse struct {
	ProtocolVersion string `json:"protocolVersion"`
	Issuer          string `json:"issuer"`
	Status          string `json:"status"`
}

type actionResponse struct {
	ProtocolVersion string `json:"protocolVersion"`
	Issuer          string `json:"issuer"`
	Status          string `json:"status"`
}

type remoteErrorResponse struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Issuer          string      `json:"issuer"`
	Error           remoteError `json:"error"`
}

type remoteError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

func newSignedClient(cfg RuntimeConfig, client *http.Client) *signedClient {
	return &signedClient{cfg: cfg, client: client, consumed: make(map[string]time.Time)}
}

func (c *signedClient) doJSON(ctx context.Context, method, endpoint string, payload any, output any) error {
	body := []byte(nil)
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP connector request cannot be encoded", err)
		}
	}
	target := *c.cfg.ParsedBaseURL
	target.Path = strings.TrimSuffix(target.Path, "/") + endpoint
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP connector request cannot be created", err)
	}
	nonce, err := randomHex(24)
	if err != nil {
		return authconnector.WrapError(authconnector.ErrUnavailable, "HTTP connector nonce generation failed", err)
	}
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	canonical := requestCanonical(method, req.URL.EscapedPath(), timestamp, nonce, body)
	signature := sign(c.cfg.HMACSecret, canonical)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "NeverLauncher/"+providerVersion+" HTTP-Connector")
	req.Header.Set(headerKeyID, c.cfg.HMAC.KeyID)
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, "v1="+hex.EncodeToString(signature))
	req.Header.Set(headerConnectorID, c.cfg.ID)

	resp, err := c.client.Do(req)
	if err != nil {
		return authconnector.WrapError(authconnector.ErrUnavailable, "HTTP auth provider request failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider redirects are forbidden")
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider returned non-JSON content type")
	}
	limited := io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return authconnector.WrapError(authconnector.ErrUnavailable, "HTTP auth provider response cannot be read", err)
	}
	if int64(len(responseBody)) > c.cfg.MaxResponseBytes {
		return authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider response exceeds configured size limit")
	}
	if err := c.verifyResponse(resp, nonce, responseBody); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return c.decodeRemoteError(resp.StatusCode, responseBody)
	}
	if output == nil {
		return nil
	}
	if err := strictDecode(responseBody, output); err != nil {
		return authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP auth provider response schema is invalid", err)
	}
	return nil
}

func (c *signedClient) verifyResponse(resp *http.Response, expectedNonce string, body []byte) error {
	keyID := strings.TrimSpace(resp.Header.Get(headerKeyID))
	timestampRaw := strings.TrimSpace(resp.Header.Get(headerTimestamp))
	nonce := strings.TrimSpace(resp.Header.Get(headerNonce))
	signatureRaw := strings.TrimSpace(resp.Header.Get(headerSignature))
	if keyID != c.cfg.HMAC.KeyID || nonce == "" || nonce != expectedNonce || timestampRaw == "" || signatureRaw == "" {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider response signature headers are invalid")
	}
	unix, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider response timestamp is invalid")
	}
	delta := time.Since(time.Unix(unix, 0)).Abs()
	if delta > c.cfg.MaxClockSkewDuration {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider response timestamp is outside replay window")
	}
	if !strings.HasPrefix(signatureRaw, "v1=") {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider response signature version is unsupported")
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signatureRaw, "v1="))
	if err != nil {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider response signature is malformed")
	}
	expected := sign(c.cfg.HMACSecret, responseCanonical(resp.StatusCode, timestampRaw, nonce, body))
	if !hmac.Equal(expected, provided) {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider response signature verification failed")
	}
	if !c.consumeNonce(nonce, time.Now().UTC()) {
		return authconnector.NewError(authconnector.ErrUnavailable, "HTTP auth provider response replay detected")
	}
	return nil
}

func (c *signedClient) consumeNonce(nonce string, now time.Time) bool {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	cutoff := now.Add(-2 * c.cfg.MaxClockSkewDuration)
	for value, expiry := range c.consumed {
		if expiry.Before(cutoff) {
			delete(c.consumed, value)
		}
	}
	if _, exists := c.consumed[nonce]; exists {
		return false
	}
	c.consumed[nonce] = now
	return true
}

func (c *signedClient) decodeRemoteError(status int, body []byte) error {
	var envelope remoteErrorResponse
	if err := strictDecode(body, &envelope); err != nil {
		return authconnector.WrapError(authconnector.ErrMisconfigured, "HTTP auth provider error schema is invalid", err)
	}
	if err := validateProtocol(c.cfg, envelope.ProtocolVersion, envelope.Issuer); err != nil {
		return err
	}
	code := strings.ToLower(strings.TrimSpace(envelope.Error.Code))
	switch status {
	case http.StatusUnauthorized:
		return authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	case http.StatusForbidden:
		return authconnector.NewError(authconnector.ErrIdentityDisabled, "HTTP identity is disabled")
	case http.StatusNotFound:
		return authconnector.NewError(authconnector.ErrIdentityNotFound, "HTTP identity not found")
	case http.StatusConflict:
		return authconnector.NewError(authconnector.ErrConflict, "HTTP identity conflict")
	case http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &authconnector.Error{Code: authconnector.ErrUnavailable, Message: "HTTP auth provider is temporarily unavailable", Temporary: true}
	}
	if status >= 500 {
		return &authconnector.Error{Code: authconnector.ErrUnavailable, Message: "HTTP auth provider failed", Temporary: true}
	}
	switch code {
	case "invalid_credentials":
		return authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	case "identity_disabled":
		return authconnector.NewError(authconnector.ErrIdentityDisabled, "HTTP identity is disabled")
	case "identity_not_found":
		return authconnector.NewError(authconnector.ErrIdentityNotFound, "HTTP identity not found")
	case "conflict":
		return authconnector.NewError(authconnector.ErrConflict, "HTTP identity conflict")
	default:
		return authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider returned unsupported error status")
	}
}

func requestCanonical(method, path, timestamp, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.ToUpper(method) + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
}

func responseCanonical(status int, timestamp, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return "RESPONSE\n" + strconv.Itoa(status) + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
}

func sign(secret []byte, canonical string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return mac.Sum(nil)
}

func randomHex(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func strictDecode(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func validateProtocol(cfg RuntimeConfig, version, issuer string) error {
	if version != protocolVersion {
		return authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider protocolVersion mismatch")
	}
	if issuer != cfg.Issuer {
		return authconnector.NewError(authconnector.ErrMisconfigured, "HTTP auth provider issuer mismatch")
	}
	return nil
}
