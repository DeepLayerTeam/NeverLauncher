package extensionbroker

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const MaxFileBytes = 256 << 10

var ErrDenied = errors.New("scoped broker: access denied")

// AllowedDestination matches the EXACT origin in the signed manifest. Only
// HTTPS is supported, including explicit :443; no URL userinfo, IP redirects,
// wildcard hostnames, noncanonical ports or implicit subdomain privileges.
func AllowedDestination(rawURL string, grants []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	host := u.Hostname()
	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "%\\ ") {
		return false
	}
	if strings.Contains(host, ":") {
		return false
	} // no IPv6 grants in v1
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	} // outbound must use verified DNS/TLS
	if u.Host != host && u.Host != net.JoinHostPort(host, port) {
		return false
	}
	target := net.JoinHostPort(host, port)
	for _, grant := range grants {
		if grant == target {
			return true
		}
	}
	return false
}

func HasGrant(grants []string, value string) bool {
	for _, grant := range grants {
		if grant == value {
			return true
		}
	}
	return false
}
