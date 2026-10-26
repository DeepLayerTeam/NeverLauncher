package attestverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeQuoteFixture0315(t *testing.T) (QuoteEvidence0315, Binding, PCRPolicy0315, string, Result, *Store) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	akKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test AK"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &akKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "roots.json")
	contents, _ := json.Marshal(RootFile{Schema: rootSchema, Roots: []Root{{ID: "test", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), Status: "active", NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), Platforms: []string{"linux", "windows"}}}})
	if err = os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	roots, err := Load(path, now)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{UserID: "user", DeviceID: "device", SessionID: "session", BindingEpoch: 7, ChallengeID: "id", Challenge: strings.Repeat("n", 64), IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), Platform: "linux"}
	pcrs := map[string]string{"0": strings.Repeat("11", 32), "2": strings.Repeat("33", 32), "7": strings.Repeat("ff", 32)}
	policy := PCRPolicy0315{ID: "approved", Platform: "linux", PCRs: pcrs, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	policyHash := strings.Repeat("a", 64)
	extra := ExpectedQuoteData0315(binding, policy.ID, policyHash)
	body := append(be32(tpmMagic), be16(tpmQuote)...)
	body = append(body, sized(nil)...)
	body = append(body, sized(extra[:])...)
	body = append(body, make([]byte, 25)...)
	body = append(body, be32(1)...)
	body = append(body, be16(tpmSHA256)...)
	body = append(body, byte(3), byte(0x85), byte(0), byte(0))
	h := sha256.New()
	for _, key := range []string{"0", "2", "7"} {
		b, _ := hex.DecodeString(pcrs[key])
		h.Write(b)
	}
	body = append(body, sized(h.Sum(nil))...)
	digest := sha256.Sum256(body)
	r, s, err := ecdsa.Sign(rand.Reader, akKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(be16(tpmECDSA), be16(tpmSHA256)...)
	signature = append(signature, sized(r.Bytes())...)
	signature = append(signature, sized(s.Bytes())...)
	ev := QuoteEvidence0315{TPM2BAttest: b64(sized(body)), TPMTSignature: b64(signature), PCRValues: pcrs,
		AKCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))}
	pinned := Result{RootID: "test", RootFingerprint: Fingerprint(caDER), AKFingerprint: Fingerprint(leafDER), ExpiresAt: now.Add(time.Hour)}
	return ev, binding, policy, policyHash, pinned, roots
}
func TestQuote0315ValidAndAdversarial(t *testing.T) {
	ev, b, p, ph, pin, roots := makeQuoteFixture0315(t)
	verify := func(ev QuoteEvidence0315, b Binding, p PCRPolicy0315, ph string, pin Result, roots *Store) error {
		_, err := VerifyQuote0315(ev, b, p, ph, pin, roots, time.Now().UTC())
		return err
	}
	if err := verify(ev, b, p, ph, pin, roots); err != nil {
		t.Fatalf("valid quote rejected: %v", err)
	}
	accepted, err := VerifyQuote0315(ev, b, p, ph, pin, roots, time.Now().UTC())
	if err != nil || accepted.ExpiresAt.Sub(time.Now().UTC()) > 5*time.Minute || accepted.ExpiresAt.Before(time.Now()) {
		t.Fatalf("invalid quote validity period: %+v %v", accepted, err)
	}

	cases := []struct {
		name   string
		change func(*QuoteEvidence0315, *Binding, *PCRPolicy0315, *string, *Result, *Store)
	}{
		{"other user", func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			b.UserID = "other"
		}},
		{"other session", func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			b.SessionID = "other"
		}},
		{"old binding epoch", func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			b.BindingEpoch--
		}},
		{"other device", func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			b.DeviceID = "other"
		}},
		{"replay nonce", func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			b.Challenge = "unrelated" + b.Challenge
		}},
		{"expired", func(_ *QuoteEvidence0315, b *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			b.ExpiresAt = time.Now().Add(-time.Second)
		}},
		{"policy hash rotation", func(_ *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, h *string, _ *Result, _ *Store) {
			*h = strings.Repeat("b", 64)
		}},
		{"foreign AK", func(_ *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, p *Result, _ *Store) {
			p.AKFingerprint = strings.Repeat("f", 64)
		}},
		{"foreign root", func(_ *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, p *Result, _ *Store) {
			p.RootFingerprint = strings.Repeat("f", 64)
		}},
		{"wrong PCR value", func(e *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			e.PCRValues = map[string]string{"0": strings.Repeat("ff", 32), "2": ev.PCRValues["2"], "7": ev.PCRValues["7"]}
		}},
		{"missing PCR", func(e *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			e.PCRValues = map[string]string{"0": ev.PCRValues["0"]}
		}},
		{"extra PCR", func(e *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			e.PCRValues = map[string]string{"0": ev.PCRValues["0"], "2": ev.PCRValues["2"], "7": ev.PCRValues["7"], "8": strings.Repeat("0", 64)}
		}},
		{"signed quote modified", func(e *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			e.TPM2BAttest = e.TPM2BAttest[:len(e.TPM2BAttest)-4] + "AAAA"
		}},
		{"signature modified", func(e *QuoteEvidence0315, _ *Binding, _ *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			e.TPMTSignature = "AAAA"
		}},
		{"policy ID mismatch", func(_ *QuoteEvidence0315, _ *Binding, p *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			p.ID = "other"
		}},
		{"policy platform mismatch", func(_ *QuoteEvidence0315, _ *Binding, p *PCRPolicy0315, _ *string, _ *Result, _ *Store) {
			p.Platform = "windows"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, bb, pp, hh, pn, rr := ev, b, p, ph, pin, *roots
			c.change(&a, &bb, &pp, &hh, &pn, &rr)
			if err := verify(a, bb, pp, hh, pn, &rr); err == nil {
				t.Fatal("forged or unapproved quote accepted")
			}
		})
	}
	roots.revokedAK[pin.AKFingerprint] = true
	if err := verify(ev, b, p, ph, pin, roots); err == nil {
		t.Fatal("revoked AK accepted")
	}
}
func TestPCRPolicy0315FailClosed(t *testing.T) {
	now := time.Now().UTC()
	file := PCRPolicyFile0315{Schema: "neverlauncher/tpm-pcr-policy/v1", Policies: []PCRPolicy0315{{ID: "approved", Platform: "linux", PCRs: map[string]string{"0": strings.Repeat("11", 32), "2": strings.Repeat("22", 32)}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}}}
	path := filepath.Join(t.TempDir(), "policy.json")
	write := func() {
		raw, _ := json.Marshal(file)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	policy, hash, err := LoadPCRPolicy0315(path, now)
	if err != nil || len(hash) != 64 {
		t.Fatalf("policy failed: %v", err)
	}
	selected, err := policy.Find("approved", "linux", now)
	if err != nil || PCRPolicySelection0315(selected) != "sha256:0,2" {
		t.Fatal("wrong PCR selection")
	}
	file.Policies[0].PCRs = map[string]string{"24": strings.Repeat("11", 32)}
	write()
	if _, _, err := LoadPCRPolicy0315(path, now); err == nil {
		t.Fatal("out-of-range PCR accepted")
	}
	file.Policies[0].PCRs = map[string]string{"0": strings.Repeat("11", 32)}
	write()
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPCRPolicy0315(path, now); err == nil {
		t.Fatal("world writable policy accepted")
	}
}
