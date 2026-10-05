package extensionhost

import (
	"net"
	"testing"
)

func TestForbiddenOutboundIP0207(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "::1", "fc00::1", "fe80::1"} {
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
