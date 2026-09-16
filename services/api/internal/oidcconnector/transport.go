package oidcconnector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func newHTTPClient(cfg RuntimeConfig) (*http.Client, *http.Transport, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, nil, fmt.Errorf("CA file contains no certificates")
		}
	}
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeoutValue, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: cfg.ConnectTimeoutValue, ResponseHeaderTimeout: cfg.RequestTimeoutValue, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 32, ForceAttemptHTTP2: true}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if !hostAllowed(host, cfg.HostAllowlist) {
			return nil, fmt.Errorf("OIDC SSRF protection rejected host %q", host)
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("OIDC resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("OIDC host %q resolved to no addresses", host)
		}
		var last error
		for _, item := range ips {
			if err := validateTargetIP(item.IP, cfg.ParsedAllowedCIDRs); err != nil {
				last = err
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(item.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			last = fmt.Errorf("no permitted addresses")
		}
		return nil, last
	}
	return &http.Client{Transport: transport, Timeout: cfg.RequestTimeoutValue, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}, transport, nil
}
func validateTargetIP(ip net.IP, allowed []*net.IPNet) error {
	for _, n := range allowed {
		if n.Contains(ip) {
			return nil
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("OIDC SSRF protection rejected non-public address %s", ip)
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 || v4[0] >= 224 || v4[0] == 100 && (v4[1]&0xc0) == 64 || v4[0] == 192 && v4[1] == 0 && v4[2] == 0 || v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return fmt.Errorf("OIDC SSRF protection rejected special-use address %s", ip)
		}
	}
	return nil
}
