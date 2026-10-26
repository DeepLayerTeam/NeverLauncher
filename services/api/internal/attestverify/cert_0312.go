package attestverify

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

func parseAKChain(e Evidence) (*x509.Certificate, *x509.CertPool, error) {
	if len(e.AKCertificatePEM) > 12000 || len(e.IntermediatesPEM) > 6 {
		return nil, nil, errors.New("AK certificate chain too large")
	}
	decodeOne := func(s string) (*x509.Certificate, error) {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
			return nil, errors.New("expected one PEM certificate")
		}
		return x509.ParseCertificate(b.Bytes)
	}
	cert, err := decodeOne(e.AKCertificatePEM)
	if err != nil {
		return nil, nil, err
	}
	p := x509.NewCertPool()
	for _, s := range e.IntermediatesPEM {
		if len(s) > 12000 {
			return nil, nil, errors.New("intermediate too large")
		}
		c, err := decodeOne(s)
		if err != nil {
			return nil, nil, err
		}
		if !c.IsCA {
			return nil, nil, errors.New("intermediate must be CA")
		}
		p.AddCert(c)
	}
	return cert, p, nil
}
