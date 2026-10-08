package oidcconnector

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type jwkSet struct {
	Keys []jwk `json:"keys"`
}
type jwk struct {
	Kty    string `json:"kty"`
	Kid    string `json:"kid"`
	Use    string `json:"use,omitempty"`
	Alg    string `json:"alg,omitempty"`
	N      string `json:"n,omitempty"`
	E      string `json:"e,omitempty"`
	Crv    string `json:"crv,omitempty"`
	X      string `json:"x,omitempty"`
	Y      string `json:"y,omitempty"`
	D      string `json:"d,omitempty"`
	P      string `json:"p,omitempty"`
	Q      string `json:"q,omitempty"`
	DP     string `json:"dp,omitempty"`
	DQ     string `json:"dq,omitempty"`
	QI     string `json:"qi,omitempty"`
	K      string `json:"k,omitempty"`
	Issuer string `json:"issuer,omitempty"`
}
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitempty"`
}

type verifiedToken struct {
	Header jwtHeader
	Claims map[string]any
}

func validateJWKS(keys []jwk, cfg RuntimeConfig) error {
	eligible := 0
	for _, key := range keys {
		if key.D != "" || key.P != "" || key.Q != "" || key.DP != "" || key.DQ != "" || key.QI != "" || key.K != "" || key.Kty == "oct" {
			return errors.New("JWKS must not contain private or symmetric key material")
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Alg != "" && !cfg.AlgAllowed(key.Alg) {
			continue
		}
		if _, err := publicKey(key); err == nil {
			eligible++
		}
	}
	if eligible == 0 {
		return errors.New("JWKS contains no usable signing key for configured algorithms")
	}
	return nil
}

func verifyIDToken(raw string, keys []jwk, cfg RuntimeConfig, expectedNonce string, requireNonce bool) (verifiedToken, error) {
	return verifyIDTokenWithPolicy(raw, keys, cfg, cfg.Issuer, ExactIssuerPolicy{}, expectedNonce, requireNonce)
}

func verifyIDTokenWithPolicy(raw string, keys []jwk, cfg RuntimeConfig, discoveredIssuer string, issuerPolicy IssuerPolicy, expectedNonce string, requireNonce bool) (verifiedToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return verifiedToken{}, errors.New("ID token is not a compact JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return verifiedToken{}, fmt.Errorf("decode ID token header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return verifiedToken{}, fmt.Errorf("decode ID token header JSON: %w", err)
	}
	if header.Alg == "" || header.Alg == "none" || strings.HasPrefix(header.Alg, "HS") || !cfg.AlgAllowed(header.Alg) {
		return verifiedToken{}, fmt.Errorf("ID token algorithm %q is not allowed", header.Alg)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return verifiedToken{}, fmt.Errorf("decode ID token claims: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	claims := map[string]any{}
	if err := dec.Decode(&claims); err != nil {
		return verifiedToken{}, fmt.Errorf("decode ID token claims JSON: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return verifiedToken{}, fmt.Errorf("decode ID token signature: %w", err)
	}
	input := []byte(parts[0] + "." + parts[1])
	verified := false
	matchedKeyIssuer := ""
	for _, key := range keys {
		if header.Kid != "" && key.Kid != header.Kid {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Alg != "" && key.Alg != header.Alg {
			continue
		}
		ok, _ := verifySignature(header.Alg, key, input, sig)
		if ok {
			verified = true
			matchedKeyIssuer = strings.TrimSpace(key.Issuer)
			break
		}
	}
	if !verified {
		return verifiedToken{}, errors.New("ID token signature verification failed")
	}
	if issuerPolicy == nil {
		issuerPolicy = ExactIssuerPolicy{}
	}
	if err := issuerPolicy.ValidateTokenIssuer(discoveredIssuer, claims, matchedKeyIssuer); err != nil {
		return verifiedToken{}, err
	}
	if !audienceContains(claims["aud"], cfg.ClientID) {
		return verifiedToken{}, fmt.Errorf("ID token audience does not contain clientId")
	}
	if audiences := audienceCount(claims["aud"]); audiences > 1 {
		azp, _ := claims["azp"].(string)
		if azp != cfg.ClientID {
			return verifiedToken{}, fmt.Errorf("ID token azp is required and must equal clientId for multiple audiences")
		}
	} else if azp, ok := claims["azp"].(string); ok && azp != "" && azp != cfg.ClientID {
		return verifiedToken{}, fmt.Errorf("ID token azp mismatch")
	}
	now := time.Now().UTC()
	exp, ok := numericDate(claims["exp"])
	if !ok || !now.Before(exp.Add(cfg.ClockSkewValue)) {
		return verifiedToken{}, fmt.Errorf("ID token is expired or exp is missing")
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && now.Add(cfg.ClockSkewValue).Before(nbf) {
		return verifiedToken{}, fmt.Errorf("ID token is not valid yet")
	}
	if iat, ok := numericDate(claims["iat"]); ok && iat.After(now.Add(cfg.ClockSkewValue)) {
		return verifiedToken{}, fmt.Errorf("ID token iat is in the future")
	}
	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" || len(sub) > 512 {
		return verifiedToken{}, fmt.Errorf("ID token subject is missing or invalid")
	}
	if requireNonce {
		nonce, _ := claims["nonce"].(string)
		if nonce == "" || nonce != expectedNonce {
			return verifiedToken{}, fmt.Errorf("ID token nonce mismatch")
		}
	}
	return verifiedToken{Header: header, Claims: claims}, nil
}
func validateAccessTokenHash(claims map[string]any, alg, accessToken string) error {
	want, ok := claims["at_hash"].(string)
	if !ok || strings.TrimSpace(want) == "" {
		return nil
	}
	var digest []byte
	switch {
	case strings.HasSuffix(alg, "256"):
		sum := sha256.Sum256([]byte(accessToken))
		digest = sum[:]
	case strings.HasSuffix(alg, "384"):
		sum := sha512.Sum384([]byte(accessToken))
		digest = sum[:]
	case strings.HasSuffix(alg, "512"):
		sum := sha512.Sum512([]byte(accessToken))
		digest = sum[:]
	default:
		return fmt.Errorf("cannot validate at_hash for ID token algorithm %q", alg)
	}
	got := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
	if got != want {
		return errors.New("ID token at_hash mismatch")
	}
	return nil
}

func verifySignature(alg string, key jwk, input, sig []byte) (bool, error) {
	pub, err := publicKey(key)
	if err != nil {
		return false, err
	}
	var hash crypto.Hash
	switch alg {
	case "RS256", "PS256", "ES256":
		hash = crypto.SHA256
	case "RS384", "PS384", "ES384":
		hash = crypto.SHA384
	case "RS512", "PS512", "ES512":
		hash = crypto.SHA512
	case "EdDSA":
		ed, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false, errors.New("EdDSA key is not Ed25519")
		}
		return ed25519.Verify(ed, input, sig), nil
	default:
		return false, fmt.Errorf("unsupported alg %s", alg)
	}
	var digest []byte
	if hash == crypto.SHA256 {
		d := sha256.Sum256(input)
		digest = d[:]
	} else if hash == crypto.SHA384 {
		d := sha512.Sum384(input)
		digest = d[:]
	} else {
		d := sha512.Sum512(input)
		digest = d[:]
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "PS") {
			err = rsa.VerifyPSS(k, hash, digest, sig, nil)
		} else {
			err = rsa.VerifyPKCS1v15(k, hash, digest, sig)
		}
		return err == nil, nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false, nil
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, digest, r, s), nil
	default:
		return false, errors.New("key type does not match algorithm")
	}
}
func publicKey(k jwk) (any, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		if e < 3 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		var c elliptic.Curve
		switch k.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		if !c.IsOnCurve(x, y) {
			return nil, errors.New("EC point is not on curve")
		}
		return &ecdsa.PublicKey{Curve: c, X: x, Y: y}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 key size")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
}
func audienceContains(v any, want string) bool {
	switch a := v.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
func audienceCount(v any) int {
	switch a := v.(type) {
	case string:
		if a != "" {
			return 1
		}
	case []any:
		return len(a)
	}
	return 0
}
func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return time.Unix(i, 0).UTC(), true
		}
		f, err := n.Float64()
		if err == nil {
			return time.Unix(int64(f), 0).UTC(), true
		}
	case float64:
		return time.Unix(int64(n), 0).UTC(), true
	}
	return time.Time{}, false
}
