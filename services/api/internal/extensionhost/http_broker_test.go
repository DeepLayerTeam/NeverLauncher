package extensionhost

import (
	"net"
	"testing"
)

func TestForbiddenOutboundIP0207(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "100.127.255.254", "198.19.12.1", "192.0.2.1", "203.0.113.15", "2001:db8::1", "64:ff9b::a9fe:a9fe", "::ffff:127.0.0.1", "::1", "fc00::1", "fe80::1"} {
		if !forbiddenOutboundIP0207(net.ParseIP(raw)) {
			t.Fatalf("private/local address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if forbiddenOutboundIP0207(net.ParseIP(raw)) {
			t.Fatalf("public address rejected: %s", raw)
		}
	}
}

func TestOutboundHeadersCannotOverrideTransport04210(t *testing.T) {
	for _, header := range []string{"Host", "Connection", "Transfer-Encoding", "Upgrade", "Trailer", "Te", "Content-Length", "Proxy-Authorization", "Bad Header", "Bad\nHeader"} {
		if outboundHeaderAllowed04210(header) {
			t.Errorf("header %q bypassed transport boundary", header)
		}
	}
	for _, header := range []string{"Authorization", "Content-Type", "Accept", "X-Request-ID"} {
		if !outboundHeaderAllowed04210(header) {
			t.Errorf("valid application header %q blocked", header)
		}
	}
}
