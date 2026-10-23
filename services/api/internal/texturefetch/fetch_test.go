package texturefetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func fixture() []byte {
	im := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	im.SetNRGBA(2, 3, color.NRGBA{R: 90, G: 30, B: 5, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, im); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func TestURLRejections(t *testing.T) {
	f, _ := New("")
	for _, raw := range []string{
		"http://textures.example.org/file.png", "https://localhost/", "https://metadata.google.internal/latest",
		"https://169.254.169.254/latest", "https://[::1]/", "https://127.0.0.1/",
		"https://textures.example.org:8080/img.png", "https://user:pass@textures.example.org/img.png",
		"https://textures.example.org@127.0.0.1/image.png", "https://textures.example.org./img",
		"https://textures.example.org/img#frag", "https://textures.example.org\\@127.0.0.1/",
		"https://textures.example.org/\r\nHost:evil", "https://textures.example.org:000443/x",
	} {
		if _, err := f.validateURL(raw); !errors.Is(err, ErrUnsafe) {
			t.Errorf("accepted unsafe URL %q: %v", raw, err)
		}
	}
	if _, err := f.validateURL("https://textures.example.org/img.png"); err != nil {
		t.Fatal(err)
	}
	if _, err := New("textures.example.org,*.example.org"); err == nil {
		t.Fatal("wildcard allowed")
	}
	g, err := New("textures.example.org,cdn.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.validateURL("https://sub.textures.example.org/foo"); !errors.Is(err, ErrUnsafe) {
		t.Fatal("allowlist suffix match bypass")
	}
}

func TestAddressBlockAndDNSRebinding(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "169.254.169.254", "10.0.0.5", "100.64.0.1", "192.0.2.2", "198.18.0.1",
		"::1", "fc00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::1", "64:ff9b::7f00:1", "::ffff:127.0.0.1",
	} {
		if safeAddress(netip.MustParseAddr(raw)) {
			t.Errorf("allowed blocked IP %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !safeAddress(netip.MustParseAddr(raw)) {
			t.Errorf("blocked public IP %s", raw)
		}
	}
	f, _ := New("")
	var called bool
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	f.dial = func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("should not dial")
	}
	if _, err := f.dialValidated(context.Background(), "tcp", "textures.example.org:443"); !errors.Is(err, ErrUnsafe) || called {
		t.Fatalf("rebind not blocked: %v dialed=%t", err, called)
	}
}

func TestHTTPSVerifiedFetchAndResourceLimits(t *testing.T) {
	payload := fixture()
	responseCode := http.StatusOK
	mime := "image/png"
	encoding := ""
	body := payload
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cookie") != "" {
			t.Errorf("untrusted headers forwarded: %+v", r.Header)
		}
		w.Header().Set("Content-Type", mime)
		if encoding != "" {
			w.Header().Set("Content-Encoding", encoding)
		}
		if responseCode == http.StatusFound {
			w.Header().Set("Location", "http://127.0.0.1/admin")
		}
		w.WriteHeader(responseCode)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	f, _ := New("textures.example.org")
	f.roots = pool
	var dialAddress string
	f.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	f.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialAddress = address
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	// httptest TLS uses a certificate for example.com? httptest cert covers example.com
	// and 127.0.0.1. A custom DNS hostname fails certificate hostname verification.
	_, err := f.Fetch(context.Background(), "https://textures.example.org/image.png", "skin", "classic")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("must verify hostname: %v", err)
	}
	f2, _ := New("example.com")
	f2.roots = pool
	f2.lookup = f.lookup
	f2.dial = f.dial
	result, err := f2.Fetch(context.Background(), "https://example.com/skin.png", "skin", "classic")
	if err != nil {
		t.Fatal(err)
	}
	if result.Width != 64 || result.Height != 64 || result.Digest == "" || dialAddress != "8.8.8.8:443" {
		t.Fatalf("invalid result %+v dial %s", result, dialAddress)
	}
	responseCode = http.StatusFound
	if _, err = f2.Fetch(context.Background(), "https://example.com/redirect", "skin", "classic"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("redirect: %v", err)
	}
	responseCode = http.StatusOK
	mime = "text/html"
	if _, err = f2.Fetch(context.Background(), "https://example.com/html", "skin", "classic"); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("MIME: %v", err)
	}
	mime = "image/png"
	encoding = "gzip"
	if _, err = f2.Fetch(context.Background(), "https://example.com/gzip", "skin", "classic"); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("encoded response: %v", err)
	}
	encoding = ""
	body = bytes.Repeat([]byte("x"), 4<<20+1)
	if _, err = f2.Fetch(context.Background(), "https://example.com/oversize", "skin", "classic"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large stream: %v", err)
	}
	body = []byte("not PNG")
	if _, err = f2.Fetch(context.Background(), "https://example.com/invalid", "skin", "classic"); err == nil {
		t.Fatal("accepted invalid PNG")
	}
}
