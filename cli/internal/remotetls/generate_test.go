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
		t.Fatalf("Неожиданный результат %+v", result)
	}
	for _, f := range []string{"server.key", "client.key", "ca.key"} {
		st, err := os.Lstat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 || !st.Mode().IsRegular() {
			t.Fatalf("Небезопасное хранение закрытого ключа %s: %v", f, st.Mode())
		}
	}
	st, _ := os.Lstat(dir)
	if st.Mode().Perm() != 0700 {
		t.Fatalf("Небезопасный каталог учётных данных: %v", st.Mode())
	}
	rootData, err := os.ReadFile(result.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootData) {
		t.Fatal("Отсутствует корневой ключ доверия")
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
	// Никогда не принимайте клиентов без разрешённого клиентского сертификата.
	unauthenticated := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, Timeout: 3 * time.Second}
	if resp, err := unauthenticated.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("Принят запрос без клиентского сертификата")
	}
	wrongName := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "unrelated.example", Certificates: []tls.Certificate{clientPair}}}, Timeout: 3 * time.Second}
	if resp, err := wrongName.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("Принято имя SAN вне разрешённого списка")
	}
	// Повторный вызов для того же каталога не должен незаметно менять действующие учётные данные.
	before, err := os.ReadFile(result.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Generate(dir, []string{"127.0.0.1"}, 30); err == nil {
		t.Fatal("Существующие учётные данные перезаписаны")
	}
	after, err := os.ReadFile(result.ServerKey)
	if err != nil || string(before) != string(after) {
		t.Fatal("Существующий ключ изменился")
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
			t.Fatalf("Принят тестовый случай %d", i)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("После тестового случая %d остались учётные данные", i)
		}
	}
	if _, err := Generate("relative", []string{"127.0.0.1"}, 30); err == nil {
		t.Fatal("Принят относительный путь для результата")
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
		t.Fatal("Серверный сертификат принят для клиентской аутентификации")
	}
	// Открытый серверный конечный сертификат должен быть действителен для указанного в документации IP-адреса.
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: net.ParseIP("127.0.0.1").String(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
}
