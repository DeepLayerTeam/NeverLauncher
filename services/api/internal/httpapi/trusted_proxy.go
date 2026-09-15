package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type trustedProxySet struct {
	nets []*net.IPNet
}

type effectiveClientIPKey struct{}

func newTrustedProxySet(cidrs []string) (*trustedProxySet, error) {
	set := &trustedProxySet{}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		set.nets = append(set.nets, network)
	}
	return set, nil
}

func (s *trustedProxySet) contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	for _, network := range s.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func resolveClientIP(r *http.Request, trusted *trustedProxySet) string {
	remote := remoteIP(r.RemoteAddr)
	if remote == nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	if !trusted.contains(remote) {
		return remote.String()
	}

	chain := make([]net.IP, 0, 8)
	for _, value := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
			chain = append(chain, ip)
		}
	}
	if len(chain) == 0 {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
			chain = append(chain, ip)
		}
	}
	chain = append(chain, remote)
	for i := len(chain) - 1; i >= 0; i-- {
		if trusted.contains(chain[i]) {
			continue
		}
		return chain[i].String()
	}
	return chain[0].String()
}

func withTrustedProxyResolution(next http.Handler, trusted *trustedProxySet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := resolveClientIP(r, trusted)
		ctx := context.WithValue(r.Context(), effectiveClientIPKey{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientIP(r *http.Request) string {
	if value, ok := r.Context().Value(effectiveClientIPKey{}).(string); ok && strings.TrimSpace(value) != "" {
		return value
	}
	if ip := remoteIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(r.RemoteAddr)
}
