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
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Addresses that are globally unicast according to net.IP can still belong
// to carrier NAT, benchmark, documentation or protocol-translation ranges.
// Do not allow an extension to reach host services via special-use routing.
var blockedOutboundPrefixes04210 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
}

func forbiddenOutboundIP0207(ip net.IP) bool {
	if ip == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range blockedOutboundPrefixes04210 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Disallow transport/framing headers that could alter the request the broker
// validated, or conflict with the pinned HTTPS connection's destination.
func outboundHeaderAllowed04210(name string) bool {
	if name == "" || name == "Host" || name == "Connection" || name == "Transfer-Encoding" ||
		name == "Upgrade" || name == "Trailer" || name == "Te" || name == "Content-Length" ||
		strings.HasPrefix(name, "Proxy-") {
		return false
	}
	// Only RFC 7230 token characters can name a forwarded HTTP field.
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
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
		if !outboundHeaderAllowed04210(canonical) {
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
