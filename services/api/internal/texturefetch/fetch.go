// Пакет texturefetch загружает недоверенные HTTPS PNG, блокируя SSRF.
package texturefetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
)

var (
	ErrUnsafe   = errors.New("unsafe texture URL or address")
	ErrRemote   = errors.New("remote texture request failed")
	ErrRedirect = errors.New("texture redirects are forbidden")
	ErrTooLarge = errors.New("remote texture is too large")
	ErrBusy     = errors.New("too many concurrent texture fetches")
)

// Запрещать адреса, не полностью охватываемые netip.IsGlobalUnicast, включая
// частные, операторские, документационные, 6to4, NAT64 и Teredo IP.
var blocked = func() []netip.Prefix {
	raw := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96",
		"64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, v := range raw {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}()

func safeAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blocked {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// Пустой allowlist разрешает публичные HTTPS DNS-хосты; записи в allowlist
// должны быть точными именами хостов. Маски и совпадения суффиксов не поддерживаются.
type Fetcher struct {
	hosts  map[string]bool
	lookup func(context.Context, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  *x509.CertPool // внедрение только для тестов; рабочая среда использует системные центры сертификации
}

func isDNSName(host string) bool {
	if len(host) < 4 || len(host) > 253 || strings.HasSuffix(host, ".") || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
				return false
			}
		}
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home", ".lan", ".onion", ".test", ".invalid", ".example"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return true
}

// New разбирает необязательный список точных хостов через запятую; некорректные правила
// отказывать по умолчанию, а не незаметно разрешать произвольные хосты.
func New(allowlist string) (*Fetcher, error) {
	f := &Fetcher{hosts: map[string]bool{}}
	if allowlist != "" {
		for _, raw := range strings.Split(allowlist, ",") {
			host := strings.ToLower(strings.TrimSpace(raw))
			if !isDNSName(host) {
				return nil, fmt.Errorf("invalid texture fetch allowlist entry: %q", raw)
			}
			f.hosts[host] = true
		}
	}
	f.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	f.dial = (&net.Dialer{Timeout: 3 * time.Second}).DialContext
	return f, nil
}

func (f *Fetcher) validateURL(raw string) (*url.URL, error) {
	if len(raw) < 10 || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n\t\\") {
		return nil, ErrUnsafe
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Host == "" || (u.Port() != "" && u.Port() != "443") {
		return nil, ErrUnsafe
	}
	host := strings.ToLower(u.Hostname())
	if !isDNSName(host) || (len(f.hosts) != 0 && !f.hosts[host]) {
		return nil, ErrUnsafe
	}
	return u, nil
}

func (f *Fetcher) dialValidated(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || !isDNSName(strings.ToLower(host)) {
		return nil, ErrUnsafe
	}
	host = strings.ToLower(host)
	if len(f.hosts) != 0 && !f.hosts[host] {
		return nil, ErrUnsafe
	}
	ips, err := f.lookup(ctx, host)
	if err != nil || len(ips) == 0 || len(ips) > 32 {
		return nil, fmt.Errorf("%w: DNS resolution rejected", ErrUnsafe)
	}
	// Проверить ВСЕ записи A/AAAA до использования любой из них, предотвращая DNS-rebinding.
	for _, ip := range ips {
		if !safeAddress(ip) {
			return nil, ErrUnsafe
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, e := f.dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		lastErr = e
	}
	return nil, fmt.Errorf("%w: dial validated address: %v", ErrRemote, lastErr)
}

// Fetch имеет жёсткие ограничения времени ответа, DNS, подключения, TLS и общего времени. Не используются прокси,
// перенаправления, сжатие, постоянные соединения, cookies или учётные данные.
// Возвращает только полностью декодированное, проверенное по геометрии, нормализованное содержимое PNG.
var fetchSlots = make(chan struct{}, 8)

func (f *Fetcher) Fetch(ctx context.Context, rawURL, kind, model string) (texturepng.Result, error) {
	var empty texturepng.Result
	u, err := f.validateURL(rawURL)
	if err != nil {
		return empty, err
	}
	select {
	case fetchSlots <- struct{}{}:
		defer func() { <-fetchSlots }()
	default:
		return empty, ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil, DialContext: f.dialValidated, DisableKeepAlives: true,
		DisableCompression: true, ForceAttemptHTTP2: false, MaxConnsPerHost: 1,
		TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.roots},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return empty, ErrUnsafe
	}
	req.Header.Set("Accept", "image/png")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return empty, fmt.Errorf("%w: %v", ErrRemote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return empty, ErrRedirect
	}
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("%w: HTTP %d", ErrRemote, resp.StatusCode)
	}
	if resp.ContentLength > texturepng.MaxEncodedBytes {
		return empty, ErrTooLarge
	}
	if v := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding"))); v != "" && v != "identity" {
		return empty, ErrUnsafe
	}
	typ := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if typ != "image/png" && typ != "application/octet-stream" {
		return empty, ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, texturepng.MaxEncodedBytes+1))
	if err != nil {
		return empty, fmt.Errorf("%w: reading response: %v", ErrRemote, err)
	}
	if len(data) > texturepng.MaxEncodedBytes {
		return empty, ErrTooLarge
	}
	return texturepng.Process(bytes.NewReader(data), kind, model)
}
