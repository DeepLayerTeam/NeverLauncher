package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const trustPolicyDomain02312 = "neverlauncher.trust.v1"
const trustPolicyPrefix02312 = "NeverLauncher-Trust-Policy-v1\n"

type TrustKey struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	PublicKey   string `json:"publicKey"`
	Status      string `json:"status"`
	NotBefore   string `json:"notBefore"`
	VerifyUntil string `json:"verifyUntil,omitempty"`
}
type TrustPolicy struct {
	SchemaVersion string     `json:"schemaVersion"`
	Domain        string     `json:"domain"`
	Epoch         uint64     `json:"epoch"`
	IssuedAt      string     `json:"issuedAt"`
	ExpiresAt     string     `json:"expiresAt"`
	Keys          []TrustKey `json:"keys"`
}
type TrustPolicyEnvelope struct {
	SchemaVersion string `json:"schemaVersion"`
	Payload       string `json:"payload"`
	RootSignature string `json:"rootSignature"`
}
type trustPolicyState struct {
	Epoch      uint64 `json:"epoch"`
	Digest     string `json:"digest"`
	RootSHA256 string `json:"rootSha256"`
}

func strictTime02312(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("missing policy time")
	}
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	if e != nil {
		return time.Time{}, e
	}
	return t.UTC(), nil
}
func VerifyTrustPolicy(raw []byte, rootHex string, now time.Time) (TrustPolicy, string, error) {
	var p TrustPolicy
	if len(raw) == 0 || len(raw) > 128*1024 {
		return p, "", errors.New("trust policy absent/oversized")
	}
	root, e := hex.DecodeString(strings.TrimSpace(rootHex))
	if e != nil || len(root) != 32 {
		return p, "", errors.New("trusted embedded root must be 32-byte Ed25519")
	}
	var env TrustPolicyEnvelope
	if e = decodeStrict(raw, &env); e != nil {
		return p, "", e
	}
	if env.SchemaVersion != "1.0" {
		return p, "", errors.New("trust policy envelope version")
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if e != nil || len(payload) > 96*1024 {
		return p, "", errors.New("invalid trust policy payload")
	}
	sig, e := hex.DecodeString(env.RootSignature)
	if e != nil || len(sig) != 64 || !ed25519.Verify(ed25519.PublicKey(root), append([]byte(trustPolicyPrefix02312), payload...), sig) {
		return p, "", errors.New("root-signed policy verification failed")
	}
	if e = decodeStrict(payload, &p); e != nil {
		return p, "", e
	}
	if p.SchemaVersion != "1.0" || p.Domain != trustPolicyDomain02312 || p.Epoch == 0 || len(p.Keys) == 0 || len(p.Keys) > 128 {
		return p, "", errors.New("policy schema/domain/keys invalid")
	}
	issued, e := strictTime02312(p.IssuedAt)
	if e != nil {
		return p, "", e
	}
	expiry, e := strictTime02312(p.ExpiresAt)
	if e != nil {
		return p, "", e
	}
	if issued.After(now.Add(5*time.Minute)) || !expiry.After(now) || !expiry.After(issued) || expiry.Sub(issued) > 90*24*time.Hour {
		return p, "", errors.New("trust policy expired, future-dated or validity exceeds 90 days")
	}
	ids, pubs := map[string]bool{}, map[string]bool{}
	active := 0
	for _, k := range p.Keys {
		if k.ID == "" || len(k.ID) > 100 || !validTrustID02312(k.ID) || (k.Role != "bootstrap" && k.Role != "component" && k.Role != "game" && k.Role != "release") {
			return p, "", errors.New("invalid delegated key id/role")
		}
		key, e := hex.DecodeString(k.PublicKey)
		if e != nil || len(key) != 32 {
			return p, "", errors.New("delegated public key invalid")
		}
		if ids[k.ID] || pubs[strings.ToLower(k.PublicKey)] {
			return p, "", errors.New("duplicate delegated key")
		}
		ids[k.ID] = true
		pubs[strings.ToLower(k.PublicKey)] = true
		if k.Status != "active" && k.Status != "verify-only" && k.Status != "revoked" {
			return p, "", errors.New("invalid delegated key status")
		}
		t, e := strictTime02312(k.NotBefore)
		if e != nil || t.After(expiry) {
			return p, "", errors.New("invalid delegated key activation")
		}
		if k.Status == "verify-only" {
			u, e := strictTime02312(k.VerifyUntil)
			if e != nil || !u.After(t) || u.Sub(t) > 90*24*time.Hour || u.After(expiry) {
				return p, "", errors.New("invalid finite key overlap")
			}
		}
		if k.Status == "active" {
			active++
		}
	}
	if active == 0 {
		return p, "", errors.New("no active delegated keys")
	}
	digest := sha256.Sum256(payload)
	return p, hex.EncodeToString(digest[:]), nil
}
func (p TrustPolicy) Authorize(role, id, pubHex string, signedAt, timeNow time.Time, requireActive bool) error {
	for _, k := range p.Keys {
		if k.Role != role || k.ID != id || !strings.EqualFold(k.PublicKey, pubHex) {
			continue
		}
		if k.Status == "revoked" {
			return fmt.Errorf("%s key %s revoked", role, id)
		}
		if requireActive && k.Status != "active" {
			return fmt.Errorf("%s signer %s retired", role, id)
		}
		t, _ := strictTime02312(k.NotBefore)
		if signedAt.Before(t) || signedAt.After(timeNow.Add(5*time.Minute)) {
			return errors.New("signature timestamp outside delegated key validity")
		}
		if k.Status == "verify-only" {
			until, _ := strictTime02312(k.VerifyUntil)
			if !signedAt.Before(until) || !timeNow.Before(until) {
				return errors.New("delegated key overlap window ended")
			}
		}
		return nil
	}
	return fmt.Errorf("%s signer %s not delegated by trusted root", role, id)
}
func SignedTrustPolicy(payload []byte, rootPrivate ed25519.PrivateKey) ([]byte, error) {
	var p TrustPolicy
	if e := decodeStrict(payload, &p); e != nil {
		return nil, e
	}
	if len(rootPrivate) != 64 {
		return nil, errors.New("root private key must be 64 bytes")
	}
	sig := ed25519.Sign(rootPrivate, append([]byte(trustPolicyPrefix02312), payload...))
	return json.Marshal(TrustPolicyEnvelope{"1.0", base64.StdEncoding.EncodeToString(payload), hex.EncodeToString(sig)})
}
func readPolicyState02312(path string) (trustPolicyState, error) {
	var st trustPolicyState
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return st, nil
	}
	if e != nil {
		return st, e
	}
	if len(b) > 4096 || decodeStrict(b, &st) != nil || st.Epoch == 0 || len(st.Digest) != 64 || len(st.RootSHA256) != 64 {
		return st, errors.New("trust policy state corrupted")
	}
	return st, nil
}

// Called under the existing Prestarter process lock. The watermark and the
// current policy are outside the replaceable launcher/component directories.
func AcceptTrustPolicy(path, rootHex string, raw []byte, now time.Time) (TrustPolicy, error) {
	p, digest, e := VerifyTrustPolicy(raw, rootHex, now)
	if e != nil {
		return p, e
	}
	root, _ := hex.DecodeString(rootHex)
	fp := sha256.Sum256(root)
	statePath := filepath.Join(path, "trust-state.json")
	previous, e := readPolicyState02312(statePath)
	if e != nil {
		return p, e
	}
	if previous.Epoch > p.Epoch || (previous.Epoch == p.Epoch && previous.Epoch > 0 && previous.Digest != digest) || (previous.Epoch > 0 && previous.RootSHA256 != hex.EncodeToString(fp[:])) {
		return p, errors.New("trust policy rollback/equivocation/root change")
	}
	if e = os.MkdirAll(path, 0o700); e != nil {
		return p, e
	}
	if previous.Epoch < p.Epoch {
		// Keep a durable revocation floor even if subsequent component installation fails.
		if e = writeTrustAtomic02312(statePath, trustPolicyState{p.Epoch, digest, hex.EncodeToString(fp[:])}); e != nil {
			return p, e
		}
	}
	if e = writeTrustAtomic02312(filepath.Join(path, "active-policy.json"), json.RawMessage(raw)); e != nil {
		return p, e
	}
	return p, nil
}
func writeTrustAtomic02312(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0o600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	if d, e := os.Open(filepath.Dir(path)); e == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}

func decodeStrict(data []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing policy JSON")
	}
	return nil
}

func validTrustID02312(value string) bool {
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return value != ""
}
