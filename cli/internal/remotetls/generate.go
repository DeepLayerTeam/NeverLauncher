// Package remotetls provisions an isolated CA and distinct server/client
// credentials for the authenticated RemoteControl HTTPS transport.
package remotetls

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Result struct {
	Directory         string `json:"directory"`
	CAFile            string `json:"caFile"`
	ServerCertificate string `json:"serverCertificate"`
	ServerKey         string `json:"serverKey"`
	ClientCertificate string `json:"clientCertificate"`
	ClientKey         string `json:"clientKey"`
	CAKey             string `json:"caKey"`
	CAFingerprint     string `json:"caFingerprint"`
	ExpiresAt         string `json:"expiresAt"`
}

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func names(hosts []string) ([]net.IP, []string, error) {
	if len(hosts) == 0 || len(hosts) > 16 {
		return nil, nil, errors.New("1-16 explicit --host SAN values required")
	}
	var ips []net.IP
	var dns []string
	seen := make(map[string]bool)
	for _, raw := range hosts {
		if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n/\\:*?@") && net.ParseIP(raw) == nil {
			return nil, nil, fmt.Errorf("invalid TLS host %q", raw)
		}
		if ip := net.ParseIP(raw); ip != nil {
			k := ip.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			ips = append(ips, ip)
			continue
		}
		if len(raw) > 253 || strings.HasSuffix(raw, ".") || strings.Contains(raw, "..") {
			return nil, nil, fmt.Errorf("invalid DNS SAN %q", raw)
		}
		labels := strings.Split(raw, ".")
		for _, l := range labels {
			if !dnsLabel.MatchString(l) {
				return nil, nil, fmt.Errorf("invalid DNS SAN %q", raw)
			}
		}
		k := strings.ToLower(raw)
		if seen[k] {
			continue
		}
		seen[k] = true
		dns = append(dns, k)
	}
	if len(ips)+len(dns) == 0 {
		return nil, nil, errors.New("empty SAN list")
	}
	return ips, dns, nil
}

func serial() (*big.Int, error) {
	// Positive 128-bit serial, enough entropy to avoid collisions.
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}
func key() (ed25519.PublicKey, ed25519.PrivateKey, error) { return ed25519.GenerateKey(rand.Reader) }
func encodeKey(private ed25519.PrivateKey) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func writeExclusive(path string, contents []byte, perm os.FileMode) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if e != nil {
		return e
	}
	_, e = f.Write(contents)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

// Generate atomically owns a *new* private output directory. No existing
// credentials are overwritten. A failed generation removes only this directory.
// Operators must move ca.key to offline storage after distributing credentials.
func Generate(directory string, hosts []string, days int) (result Result, err error) {
	if days < 1 || days > 90 {
		return result, errors.New("certificate lifetime must be 1-90 days")
	}
	ips, dns, err := names(hosts)
	if err != nil {
		return result, err
	}
	if directory == "" || !filepath.IsAbs(directory) {
		return result, errors.New("--output-dir must be absolute")
	}
	directory = filepath.Clean(directory)
	if directory == string(filepath.Separator) {
		return result, errors.New("output directory cannot be filesystem root")
	}
	if e := os.Mkdir(directory, 0700); e != nil {
		return result, fmt.Errorf("output directory must not already exist: %w", e)
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(directory)
		}
	}()
	caPub, caPriv, e := key()
	if e != nil {
		return result, e
	}
	serverPub, serverPriv, e := key()
	if e != nil {
		return result, e
	}
	clientPub, clientPriv, e := key()
	if e != nil {
		return result, e
	}
	now := time.Now().UTC()
	expiry := now.Add(time.Duration(days) * 24 * time.Hour)
	serialCA, e := serial()
	if e != nil {
		return result, e
	}
	caTmpl := &x509.Certificate{SerialNumber: serialCA, Subject: pkix.Name{CommonName: "NeverLauncher RemoteControl local CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expiry.Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	caDER, e := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if e != nil {
		return result, e
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		return result, e
	}
	makeLeaf := func(common string, pub ed25519.PublicKey, usage x509.ExtKeyUsage, withSAN bool) ([]byte, error) {
		s, e := serial()
		if e != nil {
			return nil, e
		}
		t := &x509.Certificate{SerialNumber: s, Subject: pkix.Name{CommonName: common}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if withSAN {
			t.IPAddresses = ips
			t.DNSNames = dns
		}
		return x509.CreateCertificate(rand.Reader, t, ca, pub, caPriv)
	}
	serverDER, e := makeLeaf("NeverLauncher RemoteControl server", serverPub, x509.ExtKeyUsageServerAuth, true)
	if e != nil {
		return result, e
	}
	clientDER, e := makeLeaf("NeverLauncher RemoteControl operator", clientPub, x509.ExtKeyUsageClientAuth, false)
	if e != nil {
		return result, e
	}
	caKey, e := encodeKey(caPriv)
	if e != nil {
		return result, e
	}
	serverKey, e := encodeKey(serverPriv)
	if e != nil {
		return result, e
	}
	clientKey, e := encodeKey(clientPriv)
	if e != nil {
		return result, e
	}
	crt := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"ca.pem", crt(caDER), 0644}, {"ca.key", caKey, 0600},
		{"server.pem", crt(serverDER), 0644}, {"server.key", serverKey, 0600},
		{"client.pem", crt(clientDER), 0644}, {"client.key", clientKey, 0600},
	}
	for _, f := range files {
		if e = writeExclusive(filepath.Join(directory, f.name), f.data, f.perm); e != nil {
			return result, e
		}
	}
	// Validate all generated objects against the same trust root used by the CLI.
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, item := range []struct {
		der   []byte
		usage x509.ExtKeyUsage
		dns   string
	}{{serverDER, x509.ExtKeyUsageServerAuth, func() string {
		if len(ips) > 0 {
			return ips[0].String()
		}
		return dns[0]
	}()}, {clientDER, x509.ExtKeyUsageClientAuth, ""}} {
		cert, e := x509.ParseCertificate(item.der)
		if e != nil {
			return result, e
		}
		if _, e = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{item.usage}, DNSName: item.dns}); e != nil {
			return result, fmt.Errorf("generated certificate verification: %w", e)
		}
	}
	f, e := os.Open(directory)
	if e != nil {
		return result, e
	}
	e = f.Sync()
	ce := f.Close()
	if e != nil {
		return result, e
	}
	if ce != nil {
		return result, ce
	}
	hash := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
	result = Result{Directory: directory, CAFile: filepath.Join(directory, "ca.pem"), CAKey: filepath.Join(directory, "ca.key"), ServerCertificate: filepath.Join(directory, "server.pem"), ServerKey: filepath.Join(directory, "server.key"), ClientCertificate: filepath.Join(directory, "client.pem"), ClientKey: filepath.Join(directory, "client.key"), CAFingerprint: "sha256:" + hex.EncodeToString(hash[:]), ExpiresAt: expiry.Format(time.RFC3339)}
	success = true
	return result, nil
}

// Ensure the private keys are Ed25519 keys and distinct from one another.
var _ crypto.Signer = ed25519.PrivateKey{}
