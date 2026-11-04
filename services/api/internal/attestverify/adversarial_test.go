package attestverify

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAdversarialCertifyReplayAndCrossBinding03114(t *testing.T) {
	evidence, binding, roots, _ := makeCertifyFixture(t)
	now := time.Now().UTC()
	verified, err := Verify(evidence, binding, roots, now)
	if err != nil || !roots.ActivePinned(verified.RootID, verified.RootFingerprint, verified.AKFingerprint, binding.Platform, now) {
		t.Fatalf("positive hardware proof rejected: %+v %v", verified, err)
	}
	for name, modify := range map[string]func(*Evidence, *Binding){
		"replay-device":       func(_ *Evidence, b *Binding) { b.DeviceID = "other" },
		"replay-user":         func(_ *Evidence, b *Binding) { b.UserID = "other" },
		"replay-session":      func(_ *Evidence, b *Binding) { b.SessionID = "other" },
		"replay-nonce":        func(_ *Evidence, b *Binding) { b.Challenge = strings.Repeat("q", len(b.Challenge)) },
		"replay-challenge-id": func(_ *Evidence, b *Binding) { b.ChallengeID = "other" },
		"replay-old-epoch":    func(_ *Evidence, b *Binding) { b.BindingEpoch++ },
		"expired":             func(_ *Evidence, b *Binding) { b.ExpiresAt = now.Add(-time.Second) },
		"foreign-public-key": func(_ *Evidence, b *Binding) {
			b.DevicePublicKey = append([]byte(nil), b.DevicePublicKey...)
			b.DevicePublicKey[12] ^= 1
		},
		"trailing-signed-bytes": func(e *Evidence, _ *Binding) {
			raw, _ := base64.RawURLEncoding.DecodeString(e.TPM2BAttest)
			e.TPM2BAttest = base64.RawURLEncoding.EncodeToString(append(raw, 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, b := evidence, binding
			modify(&candidate, &b)
			if _, err := Verify(candidate, b, roots, now); err == nil {
				t.Fatal("cross-context TPM Certify accepted")
			}
		})
	}
}

func TestAdversarialQuotePCRAndPolicyReplay03114(t *testing.T) {
	evidence, binding, policy, hash, pinned, roots := makeQuoteFixture0315(t)
	now := time.Now().UTC()
	if _, err := VerifyQuote0315(evidence, binding, policy, hash, pinned, roots, now); err != nil {
		t.Fatalf("valid quote rejected: %v", err)
	}
	for name, mutate := range map[string]func(*QuoteEvidence0315, *Binding, *PCRPolicy0315, *string, *Result){
		"new-nonce": func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result) {
			b.Challenge = strings.Repeat("x", len(b.Challenge))
		},
		"old-epoch": func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result) { b.BindingEpoch++ },
		"foreign-session": func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result) {
			b.SessionID = "foreign"
		},
		"policy-rotation": func(_ *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, h *string, _ *Result) {
			*h = strings.Repeat("b", 64)
		},
		"PCR-bitflip": func(e *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, _ *Result) {
			v := map[string]string{}
			for k, x := range e.PCRValues {
				v[k] = x
			}
			v["0"] = strings.Repeat("0", 64)
			e.PCRValues = v
		},
		"foreign-AK": func(_ *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, p *Result) {
			p.AKFingerprint = strings.Repeat("f", 64)
		},
		"expired-policy": func(_ *QuoteEvidence0315, _ *Binding, p *PCRPolicy0315, _ *string, _ *Result) {
			p.NotAfter = now.Add(-time.Second)
		},
		"attest-trailing-data": func(e *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, _ *Result) {
			raw, _ := base64.RawURLEncoding.DecodeString(e.TPM2BAttest)
			e.TPM2BAttest = base64.RawURLEncoding.EncodeToString(append(raw, 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, b, p, h, pin := evidence, binding, policy, hash, pinned
			mutate(&e, &b, &p, &h, &pin)
			if _, err := VerifyQuote0315(e, b, p, h, pin, roots, now); err == nil {
				t.Fatal("replayed or altered quote accepted")
			}
		})
	}
}
