package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const (
	FlagUP byte = 0x01
	FlagUV byte = 0x04
	FlagBE byte = 0x08
	FlagBS byte = 0x10
	FlagAT byte = 0x40
)

type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}
type RegistrationResult struct {
	CredentialID   []byte
	PublicKeyCOSE  []byte
	Algorithm      int64
	SignCount      uint32
	AAGUID         []byte
	BackupEligible bool
	BackedUp       bool
}
type AssertionResult struct {
	SignCount      uint32
	BackupEligible bool
	BackedUp       bool
	UserVerified   bool
}

type VerifyConfig struct {
	RPID      string
	Origins   map[string]struct{}
	Challenge []byte
	RequireUV bool
}

func VerifyRegistration(cfg VerifyConfig, clientDataJSON, attestationObject, rawID []byte) (RegistrationResult, error) {
	if err := verifyClientData(cfg, clientDataJSON, "webauthn.create"); err != nil {
		return RegistrationResult{}, err
	}
	v, consumed, err := decodeCBOR(attestationObject)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("attestation CBOR: %w", err)
	}
	if consumed != len(attestationObject) {
		return RegistrationResult{}, errors.New("attestation object has trailing data")
	}
	m, ok := v.(map[any]any)
	if !ok {
		return RegistrationResult{}, errors.New("attestation object is not a map")
	}
	fmtV, _ := mapGet(m, "fmt")
	format, _ := fmtV.(string)
	if format != "none" {
		return RegistrationResult{}, fmt.Errorf("attestation format %q is not accepted; server requests none", format)
	}
	stmtV, ok := mapGet(m, "attStmt")
	if !ok {
		return RegistrationResult{}, errors.New("attestation statement missing")
	}
	stmt, ok := stmtV.(map[any]any)
	if !ok || len(stmt) != 0 {
		return RegistrationResult{}, errors.New("none attestation statement must be an empty map")
	}
	authV, ok := mapGet(m, "authData")
	if !ok {
		return RegistrationResult{}, errors.New("attestation authData missing")
	}
	authData, ok := authV.([]byte)
	if !ok {
		return RegistrationResult{}, errors.New("attestation authData invalid")
	}
	parsed, err := parseAuthenticatorData(cfg, authData, true)
	if err != nil {
		return RegistrationResult{}, err
	}
	if !bytes.Equal(rawID, parsed.credentialID) {
		return RegistrationResult{}, errors.New("rawId does not match attested credential id")
	}
	alg, _, err := parseCOSEPublicKey(parsed.publicKeyCOSE)
	if err != nil {
		return RegistrationResult{}, err
	}
	return RegistrationResult{CredentialID: parsed.credentialID, PublicKeyCOSE: parsed.publicKeyCOSE, Algorithm: alg, SignCount: parsed.signCount, AAGUID: parsed.aaguid, BackupEligible: parsed.flags&FlagBE != 0, BackedUp: parsed.flags&FlagBS != 0}, nil
}

func VerifyAssertion(cfg VerifyConfig, clientDataJSON, authenticatorData, signature, storedCOSE []byte, storedSignCount uint32, backupEligible bool) (AssertionResult, error) {
	if err := verifyClientData(cfg, clientDataJSON, "webauthn.get"); err != nil {
		return AssertionResult{}, err
	}
	parsed, err := parseAuthenticatorData(cfg, authenticatorData, false)
	if err != nil {
		return AssertionResult{}, err
	}
	alg, pub, err := parseCOSEPublicKey(storedCOSE)
	if err != nil {
		return AssertionResult{}, err
	}
	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte(nil), authenticatorData...), clientHash[:]...)
	if err := verifySignature(alg, pub, signed, signature); err != nil {
		return AssertionResult{}, err
	}
	if (parsed.flags&FlagBE != 0) != backupEligible {
		return AssertionResult{}, errors.New("WebAuthn backup eligibility flag changed")
	}
	// A zero counter is valid. For non-backup-eligible authenticators, a non-increasing
	// non-zero counter is treated as clone/replay evidence and rejected.
	if !backupEligible && storedSignCount != 0 && parsed.signCount != 0 && parsed.signCount <= storedSignCount {
		return AssertionResult{}, errors.New("WebAuthn signature counter did not increase")
	}
	return AssertionResult{SignCount: parsed.signCount, BackupEligible: parsed.flags&FlagBE != 0, BackedUp: parsed.flags&FlagBS != 0, UserVerified: parsed.flags&FlagUV != 0}, nil
}

func verifyClientData(cfg VerifyConfig, raw []byte, expectedType string) error {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return errors.New("clientDataJSON size invalid")
	}
	var cd ClientData
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&cd); err != nil {
		return fmt.Errorf("clientDataJSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("clientDataJSON has trailing JSON")
	}
	if cd.Type != expectedType {
		return errors.New("WebAuthn clientData type mismatch")
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return errors.New("WebAuthn challenge encoding invalid")
	}
	if !bytes.Equal(got, cfg.Challenge) {
		return errors.New("WebAuthn challenge mismatch")
	}
	if cd.CrossOrigin {
		return errors.New("cross-origin WebAuthn ceremony rejected")
	}
	if _, ok := cfg.Origins[strings.TrimSpace(cd.Origin)]; !ok {
		return errors.New("WebAuthn origin rejected")
	}
	return nil
}

type parsedAuthData struct {
	flags                               byte
	signCount                           uint32
	aaguid, credentialID, publicKeyCOSE []byte
}

func parseAuthenticatorData(cfg VerifyConfig, b []byte, needAttested bool) (parsedAuthData, error) {
	if len(b) < 37 {
		return parsedAuthData{}, errors.New("authenticatorData too short")
	}
	expected := sha256.Sum256([]byte(cfg.RPID))
	if !bytes.Equal(b[:32], expected[:]) {
		return parsedAuthData{}, errors.New("RP ID hash mismatch")
	}
	flags := b[32]
	if flags&FlagUP == 0 {
		return parsedAuthData{}, errors.New("user presence flag missing")
	}
	if cfg.RequireUV && flags&FlagUV == 0 {
		return parsedAuthData{}, errors.New("user verification flag missing")
	}
	if flags&FlagBS != 0 && flags&FlagBE == 0 {
		return parsedAuthData{}, errors.New("invalid backup state flags")
	}
	p := parsedAuthData{flags: flags, signCount: binary.BigEndian.Uint32(b[33:37])}
	if !needAttested {
		return p, nil
	}
	if flags&FlagAT == 0 {
		return parsedAuthData{}, errors.New("attested credential data missing")
	}
	if len(b) < 55 {
		return parsedAuthData{}, errors.New("attested credential data truncated")
	}
	p.aaguid = append([]byte(nil), b[37:53]...)
	n := int(binary.BigEndian.Uint16(b[53:55]))
	if n < 1 || n > 1024 || len(b) < 55+n {
		return parsedAuthData{}, errors.New("credential id length invalid")
	}
	p.credentialID = append([]byte(nil), b[55:55+n]...)
	start := 55 + n
	_, used, err := decodeCBOR(b[start:])
	if err != nil {
		return parsedAuthData{}, fmt.Errorf("credential public key: %w", err)
	}
	if used < 1 {
		return parsedAuthData{}, errors.New("credential public key missing")
	}
	p.publicKeyCOSE = append([]byte(nil), b[start:start+used]...)
	return p, nil
}

func parseCOSEPublicKey(raw []byte) (int64, crypto.PublicKey, error) {
	v, used, err := decodeCBOR(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("COSE key: %w", err)
	}
	if used != len(raw) {
		return 0, nil, errors.New("COSE key trailing data")
	}
	m, ok := v.(map[any]any)
	if !ok {
		return 0, nil, errors.New("COSE key is not a map")
	}
	kty, _ := intValue(m[uint64(1)])
	alg, _ := intValue(m[uint64(3)])
	switch kty {
	case 2: // EC2
		if alg != -7 {
			return 0, nil, fmt.Errorf("unsupported EC algorithm %d", alg)
		}
		crv, _ := intValue(m[int64(-1)])
		if crv != 1 {
			return 0, nil, errors.New("only P-256 is accepted")
		}
		x, _ := m[int64(-2)].([]byte)
		y, _ := m[int64(-3)].([]byte)
		if len(x) != 32 || len(y) != 32 {
			return 0, nil, errors.New("invalid P-256 coordinates")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return 0, nil, errors.New("P-256 point is not on curve")
		}
		return alg, pub, nil
	case 3: // RSA
		if alg != -257 {
			return 0, nil, fmt.Errorf("unsupported RSA algorithm %d", alg)
		}
		n, _ := m[int64(-1)].([]byte)
		eBytes, _ := m[int64(-2)].([]byte)
		if len(n) < 256 || len(eBytes) == 0 || len(eBytes) > 4 {
			return 0, nil, errors.New("invalid RSA key")
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e < 3 {
			return 0, nil, errors.New("invalid RSA exponent")
		}
		return alg, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: e}, nil
	case 1: // OKP / Ed25519
		if alg != -8 {
			return 0, nil, fmt.Errorf("unsupported OKP algorithm %d", alg)
		}
		crv, _ := intValue(m[int64(-1)])
		x, _ := m[int64(-2)].([]byte)
		if crv != 6 || len(x) != ed25519.PublicKeySize {
			return 0, nil, errors.New("invalid Ed25519 key")
		}
		return alg, ed25519.PublicKey(append([]byte(nil), x...)), nil
	default:
		return 0, nil, fmt.Errorf("unsupported COSE key type %d", kty)
	}
}

func verifySignature(alg int64, pub crypto.PublicKey, data, sig []byte) error {
	digest := sha256.Sum256(data)
	switch alg {
	case -7:
		p, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ES256 key mismatch")
		}
		if !ecdsa.VerifyASN1(p, digest[:], sig) {
			return errors.New("WebAuthn ES256 signature invalid")
		}
		return nil
	case -257:
		p, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RS256 key mismatch")
		}
		if err := rsa.VerifyPKCS1v15(p, crypto.SHA256, digest[:], sig); err != nil {
			return errors.New("WebAuthn RS256 signature invalid")
		}
		return nil
	case -8:
		p, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("Ed25519 key mismatch")
		}
		if !ed25519.Verify(p, data, sig) {
			return errors.New("WebAuthn Ed25519 signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported WebAuthn algorithm %d", alg)
	}
}
