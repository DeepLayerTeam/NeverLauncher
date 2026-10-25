package lanmdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdvertisementRoundTrip(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	p, err := announceMessage("Example_Backend", 19443, fp, []net.IP{net.ParseIP("192.168.1.10")}, 120)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAdvertisement(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Instance != "example_backend" || got[0].Address != "192.168.1.10" || got[0].Port != 19443 || got[0].Fingerprint != fp || got[0].Verified {
		t.Fatalf("invalid parsed advertisement: %#v", got)
	}
	bye, _ := announceMessage("Example_Backend", 19443, fp, []net.IP{net.ParseIP("192.168.1.10")}, 0)
	found, _ := ParseAdvertisement(bye)
	if len(found) != 0 {
		t.Fatal("goodbye must not create discoveries")
	}
}
func TestMalformedMessagesNeverPanic(t *testing.T) {
	for n := 0; n < 64; n++ {
		p := make([]byte, n)
		for i := range p {
			p[i] = 0xc0
		}
		_, _, _ = parsePacket(p)
		_, _ = ParseAdvertisement(p)
	}
	p := make([]byte, 32)
	p[4] = 0
	p[5] = 1
	p[12] = 0xc0
	p[13] = 12
	if _, _, err := parsePacket(p); err == nil {
		t.Fatal("compression cycle accepted")
	}
}
func TestRejectInvalidPublication(t *testing.T) {
	if _, err := announceMessage("Bad.Name", 443, strings.Repeat("a", 64), []net.IP{net.IPv4(192, 168, 1, 3)}, 120); err == nil {
		t.Fatal("invalid instance")
	}
	if _, err := announceMessage("Good", 443, "not-a-hash", []net.IP{net.IPv4(192, 168, 1, 3)}, 120); err == nil {
		t.Fatal("invalid fingerprint")
	}
	for _, raw := range []string{"http://10.0.0.1:443", "https://10.0.0.1", "https://user:pwd@10.0.0.1:443", "https://10.0.0.1:443/path"} {
		if _, err := ValidateURL(raw); err == nil {
			t.Fatalf("accepted bad URL: %s", raw)
		}
	}
}
func TestPublishMustBeLocalLANAddress(t *testing.T) {
	for _, raw := range []string{"https://127.0.0.1:443", "https://192.0.2.10:443", "https://example.org:443"} {
		if _, err := ValidatePublishAddress(raw); err == nil {
			t.Fatalf("accepted remote or loopback publisher %s", raw)
		}
	}
}
func TestTLSCertificatePin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	raw := server.TLS.Certificates[0].Certificate[0]
	sum := sha256.Sum256(raw)
	pin := hex.EncodeToString(sum[:])
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := VerifyTLS(ctx, server.URL, pin); err != nil {
		t.Fatalf("correct pinned cert rejected: %v", err)
	}
	if err := VerifyTLS(ctx, server.URL, strings.Repeat("0", 64)); err == nil {
		t.Fatal("incorrect pin accepted")
	}
	if err := VerifyTLS(ctx, server.URL, ""); err == nil {
		t.Fatal("unpinned TLS accepted")
	}
	if err := VerifyTLS(ctx, "http://127.0.0.1:1234", pin); err == nil {
		t.Fatal("plaintext accepted")
	}
}
func TestDiscoveryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Discover(ctx, 500*time.Millisecond)
	// Some CI networks prohibit multicast entirely; both cancellation and OS
	// multicast rejection must be returned, not silently reported as success.
	if err == nil {
		t.Fatal("cancelled discovery returned success")
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	t.Logf("multicast unavailable on CI host: %v", err)
}
