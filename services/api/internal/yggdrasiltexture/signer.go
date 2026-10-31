// Package yggdrasiltexture signs authlib-injector texture properties with the
// protocol's RSA PKCS#1 v1.5 / SHA-1 signature, with manifest Ed25519.
package yggdrasiltexture

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Signer is immutable; create it at startup and restart the API for key rotation.
type Signer struct {
	key       *rsa.PrivateKey
	PublicPEM string
}

func ParsePrivateKey(pemBytes []byte) (*Signer, error) {
	block, remainder := pem.Decode(pemBytes)
	if block == nil || len(strings.TrimSpace(string(remainder))) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("exactly one unencrypted PEM private key is required")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		value, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = value
	case "PRIVATE KEY":
		value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		parsed, ok := value.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("Yggdrasil requires RSA private key")
		}
		key = parsed
	default:
		return nil, errors.New("unsupported signing key PEM type")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("RSA key must be at least 2048 bits")
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RSA signing key: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, PublicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))}, nil
}

func LoadFile(path string) (*Signer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("Yggdrasil RSA signing key file not configured")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read RSA key metadata: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("RSA signing key must be a regular file")
	}
	if info.Size() > 32*1024 {
		return nil, errors.New("RSA signing key file too large")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("RSA signing key file must not be group/world accessible (chmod 600)")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(content)
}

func (s *Signer) SignValue(value string) (string, error) {
	digest := sha1.Sum([]byte(value))
	signed, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signed), nil
}
func (s *Signer) VerifyValue(value, signature string) error {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	digest := sha1.Sum([]byte(value))
	return rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA1, digest[:], raw)
}

var ephemeral struct {
	once   sync.Once
	signer *Signer
	err    error
}

// Development-only process-local key: production must use a stable on-disk key.
func DevelopmentSigner() (*Signer, error) {
	ephemeral.once.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			ephemeral.err = err
			return
		}
		pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			ephemeral.err = err
			return
		}
		ephemeral.signer = &Signer{key: k, PublicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))}
	})
	return ephemeral.signer, ephemeral.err
}
