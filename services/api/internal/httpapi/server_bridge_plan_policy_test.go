package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifiedPlanHardwareDeviceSignatureAndBinding02412(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	decoded, err := decodeDevicePublicKey0123(base64.RawURLEncoding.EncodeToString(pub), "p256")
	if err != nil {
		t.Fatal(err)
	}
	e := verifiedPlanEvidence02412{ChallengeID: "one-use-id", Challenge: "secure-secret", UserID: "user", DeviceID: "device", SessionID: "session", BindingEpoch: 5, ServerID: "server", ProjectID: "project", ProfileID: "profile", Channel: "stable", ReleaseSignature: strings.Repeat("a", 128), CatalogDigest: strings.Repeat("b", 64), PlanSHA256: strings.Repeat("c", 64), GuardAttestationSHA256: strings.Repeat("d", 64)}
	sign := func(v verifiedPlanEvidence02412) string {
		t.Helper()
		h := sha256.Sum256([]byte(planEvidencePayload02412(v)))
		r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
		if err != nil {
			t.Fatal(err)
		}
		out := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	e.Signature = sign(e)
	if err := verifyDeviceSignature0123(decoded, planEvidencePayload02412(e), e.Signature); err != nil {
		t.Fatal(err)
	}
	wrong := e
	wrong.PlanSHA256 = strings.Repeat("0", 64)
	if err := verifyDeviceSignature0123(decoded, planEvidencePayload02412(wrong), e.Signature); err == nil {
		t.Fatal("plan changed after signature")
	}
	wrong = e
	wrong.SessionID = "other-session"
	if err := verifyDeviceSignature0123(decoded, planEvidencePayload02412(wrong), e.Signature); err == nil {
		t.Fatal("session swapped")
	}
	wrong = e
	wrong.GuardAttestationSHA256 = strings.Repeat("0", 64)
	if err := verifyDeviceSignature0123(decoded, planEvidencePayload02412(wrong), e.Signature); err == nil {
		t.Fatal("Guard binding changed")
	}
}
