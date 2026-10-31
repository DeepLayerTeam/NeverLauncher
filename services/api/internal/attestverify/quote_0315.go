package attestverify

// TPM2 Quote verification is independent of TPM2 Certify. A valid AK chain
// identifies the attestation key; only a signed PCR digest and an operator
// policy identify an approved measured-boot configuration. Neither implies
// integrity of a user-mode JVM process.
import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const tpmQuote uint16 = 0x8018

type PCRPolicy0315 struct {
	ID        string            `json:"id"`
	Platform  string            `json:"platform"`
	PCRs      map[string]string `json:"pcrs"` // SHA-256 bank: index => exactly 32 bytes hex
	NotBefore time.Time         `json:"notBefore"`
	NotAfter  time.Time         `json:"notAfter"`
}
type PCRPolicyFile0315 struct {
	Schema   string          `json:"schema"`
	Policies []PCRPolicy0315 `json:"policies"`
}

// LoadPCRPolicy0315 reads the policy on every use; no client-controlled path.
// Its SHA-256 digest is bound into the challenge, so an in-flight policy change
// invalidates the challenge. An explicit allowlist is required, never an all-zero
// baseline or TOFU enrollment.
func LoadPCRPolicy0315(path string, now time.Time) (PCRPolicyFile0315, string, error) {
	var out PCRPolicyFile0315
	if !filepath.IsAbs(path) {
		return out, "", errors.New("absolute operator PCR policy path required")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return out, "", err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() <= 0 || st.Size() > 1<<20 {
		return out, "", errors.New("PCR policy file must be regular and non-group/world-writable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return out, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&out); err != nil {
		return out, "", err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return out, "", errors.New("PCR policy trailing data")
	}
	if out.Schema != "launcher/tpm-pcr-policy/v1" || len(out.Policies) == 0 || len(out.Policies) > 64 {
		return out, "", errors.New("invalid PCR policy schema/count")
	}
	seen := map[string]bool{}
	for _, p := range out.Policies {
		if p.ID == "" || len(p.ID) > 96 || seen[p.ID] || (p.Platform != "windows" && p.Platform != "linux") ||
			p.NotBefore.IsZero() || !p.NotAfter.After(p.NotBefore) || len(p.PCRs) == 0 || len(p.PCRs) > 24 {
			return out, "", errors.New("invalid or duplicate PCR policy")
		}
		seen[p.ID] = true
		for k, v := range p.PCRs {
			n, e := strconv.Atoi(k)
			if e != nil || n < 0 || n > 23 || k != strconv.Itoa(n) || !isSHA256(v) {
				return out, "", errors.New("invalid PCR selection/digest in policy")
			}
		}
	}
	h := sha256.Sum256(data)
	_ = now
	return out, hex.EncodeToString(h[:]), nil
}
func (p PCRPolicyFile0315) Find(id, platform string, now time.Time) (PCRPolicy0315, error) {
	for _, v := range p.Policies {
		if v.ID == id && v.Platform == platform && !now.Before(v.NotBefore) && now.Before(v.NotAfter) {
			return v, nil
		}
	}
	return PCRPolicy0315{}, errors.New("PCR policy not active for device platform")
}
func PCRIndices0315(p PCRPolicy0315) []int {
	out := make([]int, 0, len(p.PCRs))
	for k := range p.PCRs {
		n, _ := strconv.Atoi(k)
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

type QuoteEvidence0315 struct {
	TPM2BAttest      string            `json:"tpm2bAttest"`
	TPMTSignature    string            `json:"tpmtSignature"`
	PCRValues        map[string]string `json:"pcrValues"` // hex digests, strictly selected PCR indices
	AKCertificatePEM string            `json:"akCertificatePem"`
	IntermediatesPEM []string          `json:"intermediatesPem,omitempty"`
}

func ExpectedQuoteData0315(b Binding, policyID, policyHash string) [32]byte {
	// Independent, domain-separated nonce (Certify evidence is never a quote).
	return sha256.Sum256([]byte(fmt.Sprintf("Launcher TPM Quote v1\nuser=%s\ndevice=%s\nsession=%s\nbinding-epoch=%d\nchallenge-id=%s\nchallenge=%s\nissued-at=%s\nexpires-at=%s\npolicy-id=%s\npolicy-hash=%s\n", b.UserID, b.DeviceID, b.SessionID, b.BindingEpoch, b.ChallengeID, b.Challenge, b.IssuedAt.UTC().Format(time.RFC3339Nano), b.ExpiresAt.UTC().Format(time.RFC3339Nano), policyID, policyHash)))
}

type QuoteResult0315 struct {
	RootID          string
	RootFingerprint string
	AKFingerprint   string
	PCRDigest       string
	PolicyID        string
	PolicyHash      string
	ExpiresAt       time.Time
}

func VerifyQuote0315(e QuoteEvidence0315, b Binding, p PCRPolicy0315, policyHash string, pinned Result, store *Store, now time.Time) (QuoteResult0315, error) {
	fail := func(s string) (QuoteResult0315, error) { return QuoteResult0315{}, errors.New(s) }
	if store == nil || b.UserID == "" || b.DeviceID == "" || b.SessionID == "" || b.BindingEpoch < 1 || b.ChallengeID == "" || len(b.Challenge) < 32 ||
		(b.Platform != "windows" && b.Platform != "linux") || p.Platform != b.Platform || p.ID == "" || !isSHA256(policyHash) ||
		now.Before(b.IssuedAt.Add(-10*time.Second)) || !now.Before(b.ExpiresAt) || b.ExpiresAt.Sub(b.IssuedAt) > 2*time.Minute+time.Second ||
		now.Before(p.NotBefore) || !now.Before(p.NotAfter) {
		return fail("invalid/expired quote binding or PCR policy")
	}
	if len(p.PCRs) == 0 || len(p.PCRs) > 24 || len(e.PCRValues) != len(p.PCRs) {
		return fail("PCR selection must exactly match policy")
	}
	indices := PCRIndices0315(p)
	h := sha256.New()
	for _, index := range indices {
		k := strconv.Itoa(index)
		got, ok := e.PCRValues[k]
		if !ok || !isSHA256(got) || got != p.PCRs[k] {
			return fail("PCR value not permitted by measured-boot policy")
		}
		raw, _ := hex.DecodeString(got)
		h.Write(raw)
	}
	expectedDigest := h.Sum(nil)
	attest, err := decode(e.TPM2BAttest, 4098)
	if err != nil {
		return QuoteResult0315{}, err
	}
	cur := cursor{b: attest}
	inner, err := cur.tpm2b(4096)
	if err != nil || cur.end() != nil {
		return fail("invalid TPM2B quote")
	}
	q := cursor{b: inner}
	magic, err := q.u32()
	if err != nil {
		return fail("truncated quote")
	}
	typ, err := q.u16()
	if err != nil || magic != tpmMagic || typ != tpmQuote {
		return fail("not a TPM2 quote")
	}
	_, err = q.tpm2b(128)
	if err != nil {
		return fail("bad quote signer")
	}
	qualifier, err := q.tpm2b(64)
	if err != nil {
		return fail("bad quote qualifier")
	}
	expected := ExpectedQuoteData0315(b, p.ID, policyHash)
	if !bytes.Equal(qualifier, expected[:]) {
		return fail("quote nonce/session/epoch/policy mismatch")
	}
	if _, err = q.take(25); err != nil {
		return fail("missing TPM clock/firmware")
	}
	count, err := q.u32()
	if err != nil || count != 1 {
		return fail("quote must select exactly one PCR bank")
	}
	alg, err := q.u16()
	if err != nil || alg != tpmSHA256 {
		return fail("quote must use SHA-256 PCR bank")
	}
	sz, err := q.take(1)
	if err != nil || len(sz) != 1 || sz[0] != 3 {
		return fail("unsupported PCR select bitmap width")
	}
	mask, err := q.take(3)
	if err != nil {
		return fail("missing PCR selection")
	}
	var required [3]byte
	for _, i := range indices {
		if i < 0 || i >= 24 {
			return fail("PCR index out of range")
		}
		required[i/8] |= 1 << uint(i%8)
	}
	if !bytes.Equal(mask, required[:]) {
		return fail("quoted PCR selection differs from policy")
	}
	digest, err := q.tpm2b(64)
	if err != nil || q.end() != nil {
		return fail("invalid quote PCR digest")
	}
	if !bytes.Equal(digest, expectedDigest) {
		return fail("quoted PCR digest does not match supplied selected PCR values")
	}
	sig, err := decode(e.TPMTSignature, 2048)
	if err != nil {
		return QuoteResult0315{}, err
	}
	cert, intermediates, err := parseAKChain(Evidence{AKCertificatePEM: e.AKCertificatePEM, IntermediatesPEM: e.IntermediatesPEM})
	if err != nil {
		return QuoteResult0315{}, err
	}
	fp := Fingerprint(cert.Raw)
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || fp != pinned.AKFingerprint || !store.ActivePinned(pinned.RootID, pinned.RootFingerprint, fp, b.Platform, now) {
		return fail("quote AK differs from active certified hardware identity")
	}
	if err = parseSignature(sig, cert.PublicKey, attest); err != nil {
		return QuoteResult0315{}, err
	}
	rootMatched := false
	for _, root := range store.roots {
		if root.ID != pinned.RootID || root.fingerprint != pinned.RootFingerprint {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(root.certificate)
		if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
			rootMatched = true
			break
		}
	}
	if !rootMatched {
		return fail("quote AK certificate chain no longer trusted")
	}
	expiration := now.Add(5 * time.Minute) // short-lived; revocation checked again on status
	if p.NotAfter.Before(expiration) {
		expiration = p.NotAfter
	}
	if pinned.ExpiresAt.Before(expiration) {
		expiration = pinned.ExpiresAt
	}
	if cert.NotAfter.Before(expiration) {
		expiration = cert.NotAfter
	}
	if !expiration.After(now) {
		return fail("quote verification already expired")
	}
	return QuoteResult0315{RootID: pinned.RootID, RootFingerprint: pinned.RootFingerprint, AKFingerprint: fp, PCRDigest: hex.EncodeToString(expectedDigest), PolicyID: p.ID, PolicyHash: policyHash, ExpiresAt: expiration}, nil
}

// Helper used only for emitting the canonical required PCR list to native clients.
func EncodeQuoteNonce0315(b Binding, p PCRPolicy0315, policyHash string) string {
	x := ExpectedQuoteData0315(b, p.ID, policyHash)
	return base64.RawURLEncoding.EncodeToString(x[:])
}

// For external policy tools and future auditing: value is checked against
// the exact quote selection, never treated as self-reported evidence.
func PCRPolicySelection0315(p PCRPolicy0315) string {
	ids := PCRIndices0315(p)
	xs := make([]string, 0, len(ids))
	for _, i := range ids {
		xs = append(xs, strconv.Itoa(i))
	}
	return "sha256:" + strings.Join(xs, ",")
}
