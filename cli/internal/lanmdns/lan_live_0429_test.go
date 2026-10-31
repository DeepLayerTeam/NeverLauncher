package lanmdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Run on a real multicast-capable LAN with LAUNCHER_LAN_E2E=1.
// It publishes a real TLS endpoint over UDP multicast, discovers its DNS-SD
// advertisement and validates the *independently captured* leaf certificate.
func TestLiveLANPublishDiscoverAndPinnedTLS0429(t *testing.T) {
	if os.Getenv("LAUNCHER_LAN_E2E") != "1" {
		t.Skip("requires actual LAN multicast: LAUNCHER_LAN_E2E=1")
	}
	interfaces, err := ipForInterface()
	if err != nil {
		t.Fatal(err)
	}
	host := interfaces[0].String()
	listener, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	hash := sha256.Sum256(server.TLS.Certificates[0].Certificate[0])
	pin := hex.EncodeToString(hash[:])
	if err := VerifyTLS(context.Background(), server.URL, pin); err != nil {
		t.Fatalf("TLS leaf pin verification failed: %v", err)
	}
	url, err := ValidatePublishAddress(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	if _, err := fmt.Sscan(url.Port(), &port); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	published := make(chan error, 1)
	go func() { published <- Publish(ctx, "NL429_Integration", port, pin, net.ParseIP(host)) }()
	time.Sleep(300 * time.Millisecond)
	entries, err := Discover(ctx, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if strings.EqualFold(e.Instance, "NL429_Integration") && e.Address == host && e.Port == port && e.Fingerprint == pin {
			if e.Verified {
				t.Fatal("mDNS alone must not mark discovery verified")
			}
			found = true
		}
	}
	cancel()
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("real multicast DNS-SD response not found among %v", entries)
	}
}
