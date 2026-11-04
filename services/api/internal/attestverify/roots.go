package attestverify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Roots are provisioned by the backend operator, never by a device or extension.
// An AK issuer root is not interchangeable with an EK certificate issuer root:
// operators must only enroll CAs that certify TPM-backed attestation keys.
type Root struct {
	ID             string    `json:"id"`
	CertificatePEM string    `json:"certificatePem"`
	Status         string    `json:"status"` // active, revoked
	NotBefore      time.Time `json:"notBefore"`
	NotAfter       time.Time `json:"notAfter"`
	Platforms      []string  `json:"platforms"`
}
type RootFile struct {
	Schema                string   `json:"schema"`
	Roots                 []Root   `json:"roots"`
	RevokedAKFingerprints []string `json:"revokedAkFingerprints,omitempty"`
}
type parsedRoot struct {
	Root
	certificate *x509.Certificate
	fingerprint string
}
type Store struct {
	roots     []parsedRoot
	revokedAK map[string]bool
}

const rootSchema = "launcher/tpm-ak-trust-roots/v1"

// Load reads a fresh snapshot on each verification and status check. Replacing
// the file atomically allows root overlap/rotation and immediate revocation;
// failures are fail-closed. The file must be controlled by the backend operator.
func Load(path string, now time.Time) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("tpm-ak-trust-roots-not-configured")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("tpm roots: absolute operator-controlled path required")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("tpm roots: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 || fi.Mode().Perm()&0022 != 0 {
		return nil, errors.New("tpm roots: invalid file type or size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config RootFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return nil, fmt.Errorf("tpm roots: %w", err)
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return nil, errors.New("tpm roots: trailing JSON")
	}
	if config.Schema != rootSchema || len(config.Roots) == 0 || len(config.Roots) > 64 {
		return nil, errors.New("tpm roots: bad schema or empty/oversized list")
	}
	store := &Store{revokedAK: make(map[string]bool)}
	ids := make(map[string]bool)
	fps := make(map[string]bool)
	for _, f := range config.RevokedAKFingerprints {
		if !isSHA256(f) {
			return nil, errors.New("tpm roots: invalid revoked AK fingerprint")
		}
		store.revokedAK[f] = true
	}
	for _, r := range config.Roots {
		if r.ID == "" || len(r.ID) > 96 || ids[r.ID] || (r.Status != "active" && r.Status != "revoked") {
			return nil, errors.New("tpm roots: invalid/duplicate root id or status")
		}
		ids[r.ID] = true
		block, rest := pem.Decode([]byte(r.CertificatePEM))
		if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, errors.New("tpm roots: expected one PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("tpm roots: CA signing certificate required")
		}
		fingerprint := Fingerprint(cert.Raw)
		if fps[fingerprint] {
			return nil, errors.New("tpm roots: duplicate certificate")
		}
		fps[fingerprint] = true
		if r.NotBefore.IsZero() || r.NotAfter.IsZero() || !r.NotAfter.After(r.NotBefore) {
			return nil, errors.New("tpm roots: invalid validity policy")
		}
		for _, p := range r.Platforms {
			if p != "windows" && p != "linux" {
				return nil, errors.New("tpm roots: only windows/linux supported")
			}
		}
		store.roots = append(store.roots, parsedRoot{Root: r, certificate: cert, fingerprint: fingerprint})
	}
	_ = now // validity is deliberately evaluated per verification rather than during load
	return store, nil
}
func Fingerprint(der []byte) string { h := sha256.Sum256(der); return hex.EncodeToString(h[:]) }
func isSHA256(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (s *Store) Active(rootID, akFingerprint, platform string, now time.Time) bool {
	return s.ActivePinned(rootID, "", akFingerprint, platform, now)
}
func (s *Store) ActivePinned(rootID, rootFingerprint, akFingerprint, platform string, now time.Time) bool {
	if s == nil || s.revokedAK[akFingerprint] {
		return false
	}
	for _, r := range s.roots {
		if r.ID != rootID || (rootFingerprint != "" && r.fingerprint != rootFingerprint) || r.Status != "active" || now.Before(r.NotBefore) || !now.Before(r.NotAfter) || now.Before(r.certificate.NotBefore) || !now.Before(r.certificate.NotAfter) {
			continue
		}
		if len(r.Platforms) == 0 {
			return true
		}
		for _, p := range r.Platforms {
			if p == platform {
				return true
			}
		}
	}
	return false
}
