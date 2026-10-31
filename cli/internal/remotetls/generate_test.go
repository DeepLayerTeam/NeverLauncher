package remotetls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateAuthenticatesTLSAndClientCertificate0428(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	result, err := Generate(dir, []string{"127.0.0.1", "localhost", "::1"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if result.Directory != dir || !strings.HasPrefix(result.CAFingerprint, "sha256:") {
		t.Fatalf("unexpected result %+v", result)
	}
	for _, f := range []string{"server.key", "client.key", "ca.key"} {
		st, err := os.Lstat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 || !st.Mode().IsRegular() {
			t.Fatalf("unsafe private key %s: %v", f, st.Mode())
		}
	}
	st, _ := os.Lstat(dir)
	if st.Mode().Perm() != 0700 {
		t.Fatalf("unsafe credential directory: %v", st.Mode())
	}
	rootData, err := os.ReadFile(result.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootData) {
		t.Fatal("no trust root")
	}
	serverPair, err := tls.LoadX509KeyPair(result.ServerCertificate, result.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.LoadX509KeyPair(result.ClientCertificate, result.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientPair}}}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("HTTP %d", response.StatusCode)
	}
	tr.CloseIdleConnections()
	// Never accept clients that lack an authorized client certificate.
	unauthenticated := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, Timeout: 3 * time.Second}
	if resp, err := unauthenticated.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("accepted missing client certificate")
	}
	wrongName := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "unrelated.example", Certificates: []tls.Certificate{clientPair}}}, Timeout: 3 * time.Second}
	if resp, err := wrongName.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("accepted unlisted SAN")
	}
	// Same directory must never rotate existing credentials implicitly.
	before, err := os.ReadFile(result.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Generate(dir, []string{"127.0.0.1"}, 30); err == nil {
		t.Fatal("overwrote existing credentials")
	}
	after, err := os.ReadFile(result.ServerKey)
	if err != nil || string(before) != string(after) {
		t.Fatal("existing key changed")
	}
}
func TestGenerateInvalidInputsLeaveNoCredentials0428(t *testing.T) {
	cases := []struct {
		hosts []string
		days  int
	}{
		{nil, 30}, {[]string{"example.com"}, 0}, {[]string{"example.com"}, 91},
		{[]string{"*.example.com"}, 30}, {[]string{"host\nInjected=1"}, 30},
		{[]string{"example.com/path"}, 30}, {[]string{"a..b"}, 30},
	}
	for i, c := range cases {
		dir := filepath.Join(t.TempDir(), "secret")
		if _, err := Generate(dir, c.hosts, c.days); err == nil {
			t.Fatalf("case %d accepted", i)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("case %d left credentials", i)
		}
	}
	if _, err := Generate("relative", []string{"127.0.0.1"}, 30); err == nil {
		t.Fatal("accepted relative output path")
	}
}
func TestGenerateServerCertificateCannotImpersonateClient0428(t *testing.T) {
	res, err := Generate(filepath.Join(t.TempDir(), "tls"), []string{"127.0.0.1"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(res.CAFile)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	pair, err := tls.LoadX509KeyPair(res.ServerCertificate, res.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("server certificate accepted for client auth")
	}
	// The public server leaf must be valid for the documented IP address.
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: net.ParseIP("127.0.0.1").String(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
}
