package extensionhost

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func forbiddenOutboundIP0207(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func (s *Supervisor) secureHTTPFetch0207(ctx context.Context, method, rawURL string, headers map[string]string, bodyBase64 string) (map[string]any, int, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, http.StatusBadRequest, errors.New("http.fetch requires an https URL without userinfo")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	host := u.Hostname()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, http.StatusBadGateway, errors.New("outbound hostname resolution failed")
	}
	var selected net.IP
	for _, ip := range ips {
		if forbiddenOutboundIP0207(ip) {
			return nil, http.StatusForbidden, errors.New("outbound target resolves to a private/local address")
		}
		if selected == nil {
			selected = ip
		}
	}
	dialer := &net.Dialer{Timeout: s.cfg.HTTPTimeout}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(c, network, net.JoinHostPort(selected.String(), port))
	}, ForceAttemptHTTP2: true, MaxIdleConns: 2, IdleConnTimeout: 10 * time.Second}
	client := &http.Client{Transport: transport, Timeout: s.cfg.HTTPTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return nil, http.StatusBadRequest, errors.New("unsupported outbound HTTP method")
	}
	var body []byte
	if bodyBase64 != "" {
		body, err = base64.StdEncoding.DecodeString(bodyBase64)
		if err != nil {
			return nil, http.StatusBadRequest, errors.New("bodyBase64 is invalid")
		}
		if int64(len(body)) > s.cfg.MaxHTTPRequestBytes {
			return nil, http.StatusRequestEntityTooLarge, errors.New("outbound request body too large")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	for k, v := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(k))
		if canonical == "Host" || canonical == "Connection" || strings.HasPrefix(canonical, "Proxy-") {
			return nil, http.StatusBadRequest, fmt.Errorf("header %s is not allowed", canonical)
		}
		if len(v) > 8192 {
			return nil, http.StatusBadRequest, errors.New("outbound header value too large")
		}
		req.Header.Set(canonical, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("outbound request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxHTTPResponseBytes+1))
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	if int64(len(data)) > s.cfg.MaxHTTPResponseBytes {
		return nil, http.StatusBadGateway, errors.New("outbound response exceeds configured limit")
	}
	outHeaders := map[string]string{}
	for _, k := range []string{"Content-Type", "ETag", "Last-Modified", "Cache-Control"} {
		if v := resp.Header.Get(k); v != "" {
			outHeaders[k] = v
		}
	}
	return map[string]any{"status": resp.StatusCode, "headers": outHeaders, "bodyBase64": base64.StdEncoding.EncodeToString(data)}, http.StatusOK, nil
}
