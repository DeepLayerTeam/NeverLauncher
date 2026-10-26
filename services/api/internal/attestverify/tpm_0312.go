package attestverify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	tpmMagic    uint32 = 0xff544347
	tpmCertify  uint16 = 0x8017
	tpmECC      uint16 = 0x0023
	tpmSHA256   uint16 = 0x000b
	tpmNull     uint16 = 0x0010
	tpmNISTP256 uint16 = 0x0003
	tpmRSASSA   uint16 = 0x0014
	tpmRSAPSS   uint16 = 0x0016
	tpmECDSA    uint16 = 0x0018
)

type Evidence struct {
	TPM2BPublic      string   `json:"tpm2bPublic"`   // base64url of TPM2B_PUBLIC
	TPM2BAttest      string   `json:"tpm2bAttest"`   // base64url of TPM2B_ATTEST
	TPMTSignature    string   `json:"tpmtSignature"` // base64url of TPMT_SIGNATURE
	AKCertificatePEM string   `json:"akCertificatePem"`
	IntermediatesPEM []string `json:"intermediatesPem,omitempty"`
}
type Binding struct {
	UserID          string
	DeviceID        string
	SessionID       string
	BindingEpoch    int64
	ChallengeID     string
	Challenge       string
	DevicePublicKey []byte // registered uncompressed SEC1 P-256
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Platform        string
}
type Result struct {
	RootID          string
	RootFingerprint string
	AKFingerprint   string
	ExpiresAt       time.Time
}

type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.b)-c.pos {
		return nil, errors.New("truncated TPM structure")
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v, nil
}
func (c *cursor) u16() (uint16, error) {
	b, e := c.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (c *cursor) u32() (uint32, error) {
	b, e := c.take(4)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint32(b), nil
}
func (c *cursor) tpm2b(max int) ([]byte, error) {
	n, e := c.u16()
	if e != nil {
		return nil, e
	}
	if int(n) > max {
		return nil, errors.New("oversized TPM2B")
	}
	return c.take(int(n))
}
func (c *cursor) end() error {
	if c.pos != len(c.b) {
		return errors.New("trailing TPM bytes")
	}
	return nil
}
func decode(s string, limit int) ([]byte, error) {
	if len(s) > limit*2 {
		return nil, errors.New("oversized evidence")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) == 0 || len(b) > limit {
		return nil, errors.New("invalid evidence base64url")
	}
	return b, nil
}

// ExpectedExtraData is a domain-separated hash of the entire challenge and
// active session/device binding. TPM2_Commit/Certify extraData has bounded size.
func ExpectedExtraData(b Binding) [32]byte {
	p := fmt.Sprintf("NeverLauncher TPM Certify v1\nuser=%s\ndevice=%s\nsession=%s\nbinding-epoch=%d\nchallenge-id=%s\nchallenge=%s\nissued-at=%s\nexpires-at=%s\n", b.UserID, b.DeviceID, b.SessionID, b.BindingEpoch, b.ChallengeID, b.Challenge, b.IssuedAt.UTC().Format(time.RFC3339Nano), b.ExpiresAt.UTC().Format(time.RFC3339Nano))
	return sha256.Sum256([]byte(p))
}
func parsePublic(raw []byte) ([]byte, []byte, error) {
	c := cursor{b: raw}
	payload, e := c.tpm2b(4096)
	if e != nil {
		return nil, nil, e
	}
	if e = c.end(); e != nil {
		return nil, nil, e
	}
	p := cursor{b: payload}
	typ, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	hash, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	attrs, e := p.u32()
	if e != nil {
		return nil, nil, e
	}
	// FixedTPM, FixedParent, SensitiveDataOrigin, Sign; RSA or exotic ECC is intentionally excluded.
	if typ != tpmECC || hash != tpmSHA256 || attrs&(1<<1|1<<4|1<<5|1<<18) != (1<<1|1<<4|1<<5|1<<18) {
		return nil, nil, errors.New("TPM key must be a fixed TPM-origin signing ECC P-256 key")
	}
	policy, e := p.tpm2b(64)
	if e != nil {
		return nil, nil, e
	}
	_ = policy
	symmetric, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	scheme, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	// Linux hardware-enclave 0.2.10 generates unrestricted P-256 signing
	// children with TPMT_ECC_SCHEME=ECDSA(SHA-256). Windows PCP may encode
	// NULL. Both are valid; accepting ECDSA must consume its mandatory
	// hash parameter, never misinterpret it as the curve identifier.
	if scheme == tpmECDSA {
		schemeHash, err := p.u16()
		if err != nil || schemeHash != tpmSHA256 {
			return nil, nil, errors.New("TPM ECC scheme must use ECDSA SHA-256")
		}
	} else if scheme != tpmNull {
		return nil, nil, errors.New("unsupported TPM ECC signing scheme")
	}
	curve, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	kdf, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	if symmetric != tpmNull || curve != tpmNISTP256 || kdf != tpmNull {
		return nil, nil, errors.New("unsupported TPM ECC public parameters")
	}
	x, e := p.tpm2b(32)
	if e != nil {
		return nil, nil, e
	}
	y, e := p.tpm2b(32)
	if e != nil {
		return nil, nil, e
	}
	if len(x) != 32 || len(y) != 32 || p.end() != nil {
		return nil, nil, errors.New("invalid TPM P-256 point encoding")
	}
	point := make([]byte, 65)
	point[0] = 4
	copy(point[1:33], x)
	copy(point[33:], y)
	X, Y := elliptic.Unmarshal(elliptic.P256(), point)
	if X == nil || Y == nil {
		return nil, nil, errors.New("invalid TPM ECC point")
	}
	h := sha256.Sum256(payload)
	name := make([]byte, 34)
	binary.BigEndian.PutUint16(name, tpmSHA256)
	copy(name[2:], h[:])
	return name, point, nil
}
func parseAttest(raw []byte, expected [32]byte, name []byte) error {
	c := cursor{b: raw}
	inner, e := c.tpm2b(4096)
	if e != nil {
		return e
	}
	if e = c.end(); e != nil {
		return e
	}
	t := cursor{b: inner}
	magic, e := t.u32()
	if e != nil {
		return e
	}
	typ, e := t.u16()
	if e != nil {
		return e
	}
	if magic != tpmMagic || typ != tpmCertify {
		return errors.New("not a TPM2 certify attestation")
	}
	signer, e := t.tpm2b(128)
	if e != nil {
		return e
	}
	_ = signer
	extra, e := t.tpm2b(64)
	if e != nil {
		return e
	}
	if !bytes.Equal(extra, expected[:]) {
		return errors.New("TPM attestation nonce/session/binding mismatch")
	}
	if _, e = t.take(17 + 8); e != nil {
		return e
	} // TPMS_CLOCK_INFO plus firmwareVersion
	certified, e := t.tpm2b(128)
	if e != nil {
		return e
	}
	if !bytes.Equal(certified, name) {
		return errors.New("certified key name mismatch")
	}
	if _, e = t.tpm2b(128); e != nil {
		return e
	} // qualifiedName
	return t.end()
}
func parseSignature(raw []byte, public crypto.PublicKey, attest []byte) error {
	c := cursor{b: raw}
	alg, e := c.u16()
	if e != nil {
		return e
	}
	h, e := c.u16()
	if e != nil {
		return e
	}
	if h != tpmSHA256 {
		return errors.New("TPM signature must use SHA-256")
	}
	// TPM signs the TPMS_ATTEST body, excluding the outer TPM2B length.
	if len(attest) < 2 {
		return errors.New("empty TPM attest")
	}
	digest := sha256.Sum256(attest[2:])
	switch alg {
	case tpmECDSA:
		pub, ok := public.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return errors.New("AK certificate is not P-256 ECDSA")
		}
		r, e := c.tpm2b(66)
		if e != nil {
			return e
		}
		s, e := c.tpm2b(66)
		if e != nil {
			return e
		}
		if c.end() != nil || len(r) == 0 || len(s) == 0 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)) {
			return errors.New("invalid TPM ECDSA certify signature")
		}
	case tpmRSASSA, tpmRSAPSS:
		pub, ok := public.(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 {
			return errors.New("unsupported RSA AK")
		}
		sig, e := c.tpm2b(1024)
		if e != nil {
			return e
		}
		if e = c.end(); e != nil {
			return e
		}
		if alg == tpmRSASSA {
			e = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
		} else {
			e = rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		}
		if e != nil {
			return errors.New("invalid TPM RSA certify signature")
		}
	default:
		return errors.New("unsupported TPM AK signature scheme")
	}
	return nil
}

// Verify authenticates a real TPM2 Certify output from a CA-issued AK and
// binds the certified fixedTPM signing key to the exact registered device key.
// It does not verify measured boot or the integrity of a running user process.
func Verify(e Evidence, b Binding, store *Store, now time.Time) (Result, error) {
	fail := func(msg string) (Result, error) { return Result{}, errors.New(msg) }
	if store == nil {
		return fail("TPM AK trust roots unavailable")
	}
	if b.UserID == "" || b.DeviceID == "" || b.SessionID == "" || b.BindingEpoch < 1 || b.ChallengeID == "" || len(b.Challenge) < 32 || b.Platform != "windows" && b.Platform != "linux" {
		return fail("incomplete TPM challenge binding")
	}
	if now.Before(b.IssuedAt.Add(-10*time.Second)) || !now.Before(b.ExpiresAt) || b.ExpiresAt.Sub(b.IssuedAt) > 2*time.Minute+time.Second {
		return fail("expired/invalid attestation challenge")
	}
	if len(b.DevicePublicKey) != 65 || b.DevicePublicKey[0] != 4 {
		return fail("registered key must be P-256 SEC1")
	}
	tpmPub, err := decode(e.TPM2BPublic, 4098)
	if err != nil {
		return Result{}, err
	}
	name, key, err := parsePublic(tpmPub)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(key, b.DevicePublicKey) {
		return fail("certified public key does not match registered device")
	}
	attest, err := decode(e.TPM2BAttest, 4098)
	if err != nil {
		return Result{}, err
	}
	if err = parseAttest(attest, ExpectedExtraData(b), name); err != nil {
		return Result{}, err
	}
	signature, err := decode(e.TPMTSignature, 2048)
	if err != nil {
		return Result{}, err
	}
	cert, intermediatePool, err := parseAKChain(e)
	if err != nil {
		return Result{}, err
	}
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fail("AK certificate must be a non-CA signing certificate")
	}
	fp := Fingerprint(cert.Raw)
	if store.revokedAK[fp] {
		return fail("AK certificate revoked")
	}
	if err = parseSignature(signature, cert.PublicKey, attest); err != nil {
		return Result{}, err
	}
	for _, root := range store.roots {
		if !store.Active(root.ID, fp, b.Platform, now) {
			continue
		}
		p := x509.NewCertPool()
		p.AddCert(root.certificate)
		_, err = cert.Verify(x509.VerifyOptions{Roots: p, Intermediates: intermediatePool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if err != nil {
			continue
		}
		expires := now.Add(1 * time.Hour)
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
		if root.NotAfter.Before(expires) {
			expires = root.NotAfter
		}
		return Result{RootID: root.ID, RootFingerprint: root.fingerprint, AKFingerprint: fp, ExpiresAt: expires}, nil
	}
	return fail("no trusted, active AK certificate chain")
}
