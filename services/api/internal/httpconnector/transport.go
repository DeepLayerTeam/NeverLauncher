package httpconnector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var specialUseCIDRs = mustCIDRs([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
})

func mustCIDRs(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		result = append(result, network)
	}
	return result
}

func newHTTPClient(cfg RuntimeConfig) (*http.Client, *http.Transport, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.MTLS.CAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.MTLS.CAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read mTLS CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, nil, errors.New("mTLS CA file contains no valid certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if cfg.MTLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.MTLS.CertFile, cfg.MTLS.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load mTLS client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	safeDial := &ssrfSafeDialer{cfg: cfg, resolver: net.DefaultResolver, dialer: net.Dialer{Timeout: cfg.ConnectTimeoutDuration, KeepAlive: 30 * time.Second}}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           safeDial.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConns,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeoutDuration,
		TLSHandshakeTimeout:   cfg.ConnectTimeoutDuration,
		ResponseHeaderTimeout: cfg.RequestTimeoutDuration,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeoutDuration,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, transport, nil
}

type ssrfSafeDialer struct {
	cfg      RuntimeConfig
	resolver *net.Resolver
	dialer   net.Dialer
}

func (d *ssrfSafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("HTTP connector invalid dial address: %w", err)
	}
	normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
	if !hostAllowed(normalizedHost, d.cfg.HostAllowlist) {
		return nil, fmt.Errorf("HTTP connector SSRF protection rejected host %q", normalizedHost)
	}

	ips := []net.IP{}
	if parsed := net.ParseIP(normalizedHost); parsed != nil {
		ips = append(ips, parsed)
	} else {
		resolved, err := d.resolver.LookupIP(ctx, "ip", normalizedHost)
		if err != nil {
			return nil, fmt.Errorf("HTTP connector DNS resolution failed for %q: %w", normalizedHost, err)
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("HTTP connector DNS resolution returned no addresses for %q", normalizedHost)
	}

	for _, ip := range ips {
		if err := d.validateIP(ip); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("HTTP connector failed to connect to validated addresses for %q: %w", normalizedHost, lastErr)
}

func (d *ssrfSafeDialer) validateIP(ip net.IP) error {
	for _, allowed := range d.cfg.ParsedAllowedCIDRs {
		if allowed.Contains(ip) {
			return nil
		}
	}
	for _, blocked := range specialUseCIDRs {
		if blocked.Contains(ip) {
			return fmt.Errorf("HTTP connector SSRF protection rejected special-use address %s", ip)
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("HTTP connector SSRF protection rejected non-public address %s", ip)
	}
	return nil
}
