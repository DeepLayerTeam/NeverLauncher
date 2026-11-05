package attestverify

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

func parseAKChain(e Evidence) (*x509.Certificate, *x509.CertPool, error) {
	if len(e.AKCertificatePEM) > 12000 || len(e.IntermediatesPEM) > 6 {
		return nil, nil, errors.New("Превышен допустимый размер: цепочка сертификатов ключа аттестации")
	}
	decodeOne := func(s string) (*x509.Certificate, error) {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
			return nil, errors.New("Ожидается ровно один сертификат PEM")
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
			return nil, nil, errors.New("Превышен допустимый размер: «intermediate»")
		}
		c, err := decodeOne(s)
		if err != nil {
			return nil, nil, err
		}
		if !c.IsCA {
			return nil, nil, errors.New("intermediate: требуется CA")
		}
		p.AddCert(c)
	}
	return cert, p, nil
}
