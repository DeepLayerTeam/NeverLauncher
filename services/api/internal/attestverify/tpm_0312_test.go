package attestverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func be16(v uint16) []byte  { return []byte{byte(v >> 8), byte(v)} }
func be32(v uint32) []byte  { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
func sized(b []byte) []byte { return append(be16(uint16(len(b))), b...) }
func b64(b []byte) string   { return base64.RawURLEncoding.EncodeToString(b) }
func makeCertifyFixture(t *testing.T) (Evidence, Binding, *Store, func(RootFile)) {
	return makeCertifyFixtureWithScheme(t, false)
}
func makeCertifyFixtureWithScheme(t *testing.T, linuxEcdsaScheme bool) (Evidence, Binding, *Store, func(RootFile)) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	akKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	deviceKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test TPM AK issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	caCert, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	akTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Certified AK"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	akDER, e := x509.CreateCertificate(rand.Reader, akTemplate, caCert, &akKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	storePath := filepath.Join(t.TempDir(), "roots.json")
	original := RootFile{Schema: rootSchema, Roots: []Root{{ID: "operator-ca", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), Status: "active", NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * time.Hour), Platforms: []string{"linux", "windows"}}}}
	write := func(v RootFile) {
		t.Helper()
		data, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(storePath, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(original)
	store, e := Load(storePath, now)
	if e != nil {
		t.Fatal(e)
	}
	pubPoint := elliptic.Marshal(elliptic.P256(), deviceKey.X, deviceKey.Y)
	payload := make([]byte, 0, 256)
	payload = append(payload, be16(tpmECC)...)
	payload = append(payload, be16(tpmSHA256)...)
	payload = append(payload, be32(1<<1|1<<4|1<<5|1<<18)...)
	payload = append(payload, sized(nil)...)
	payload = append(payload, be16(tpmNull)...)
	if linuxEcdsaScheme {
		payload = append(payload, be16(tpmECDSA)...)
		payload = append(payload, be16(tpmSHA256)...)
	} else {
		payload = append(payload, be16(tpmNull)...)
	}
	payload = append(payload, be16(tpmNISTP256)...)
	payload = append(payload, be16(tpmNull)...)
	payload = append(payload, sized(pubPoint[1:33])...)
	payload = append(payload, sized(pubPoint[33:])...)
	nameHash := sha256.Sum256(payload)
	name := append(be16(tpmSHA256), nameHash[:]...)
	binding := Binding{UserID: "owner", DeviceID: "device", SessionID: "session", BindingEpoch: 7, ChallengeID: "ch1", Challenge: strings.Repeat("x", 64), DevicePublicKey: pubPoint, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), Platform: "linux"}
	extra := ExpectedExtraData(binding)
	body := append(be32(tpmMagic), be16(tpmCertify)...)
	body = append(body, sized(nil)...)
	body = append(body, sized(extra[:])...)
	body = append(body, make([]byte, 25)...)
	body = append(body, sized(name)...)
	body = append(body, sized(nil)...)
	digest := sha256.Sum256(body)
	r, s, e := ecdsa.Sign(rand.Reader, akKey, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	signature := append(be16(tpmECDSA), be16(tpmSHA256)...)
	signature = append(signature, sized(r.Bytes())...)
	signature = append(signature, sized(s.Bytes())...)
	ev := Evidence{TPM2BPublic: b64(sized(payload)), TPM2BAttest: b64(sized(body)), TPMTSignature: b64(signature), AKCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: akDER}))}
	return ev, binding, store, func(v RootFile) {
		write(v)
		store2, err := Load(storePath, now)
		if err != nil {
			t.Fatal(err)
		}
		*store = *store2
	}
}
func TestRealTPMCertifyChainAndExactDevice0312(t *testing.T) {
	ev, b, store, _ := makeCertifyFixture(t)
	r, e := Verify(ev, b, store, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if r.RootID != "operator-ca" || !store.Active(r.RootID, r.AKFingerprint, "linux", time.Now().UTC()) || !r.ExpiresAt.After(time.Now()) {
		t.Fatalf("result=%+v", r)
	}
	cases := []struct {
		name   string
		change func(*Evidence, *Binding)
	}{
		{"foreign key", func(_ *Evidence, b *Binding) {
			b.DevicePublicKey = append([]byte{}, b.DevicePublicKey...)
			b.DevicePublicKey[1] ^= 1
		}},
		{"foreign session", func(_ *Evidence, b *Binding) { b.SessionID = "foreign" }},
		{"old epoch", func(_ *Evidence, b *Binding) { b.BindingEpoch-- }},
		{"foreign device", func(_ *Evidence, b *Binding) { b.DeviceID = "other" }},
		{"foreign user", func(_ *Evidence, b *Binding) { b.UserID = "attacker" }},
		{"replayed challenge nonce", func(_ *Evidence, b *Binding) { b.Challenge = "different random nonce" + b.Challenge }},
		{"replayed challenge id", func(_ *Evidence, b *Binding) { b.ChallengeID = "other-id" }},
		{"expired", func(_ *Evidence, b *Binding) { b.ExpiresAt = time.Now().Add(-time.Minute) }},
		{"future", func(_ *Evidence, b *Binding) { b.IssuedAt = time.Now().Add(time.Hour) }},
		{"invalid attestation", func(e *Evidence, _ *Binding) {
			raw, _ := base64.RawURLEncoding.DecodeString(e.TPM2BAttest)
			raw[4] ^= 1
			e.TPM2BAttest = b64(raw)
		}},
		{"forged TPM cert", func(e *Evidence, _ *Binding) { e.AKCertificatePEM = strings.ReplaceAll(e.AKCertificatePEM, "A", "B") }},
		{"signature", func(e *Evidence, _ *Binding) {
			raw, _ := base64.RawURLEncoding.DecodeString(e.TPMTSignature)
			raw[len(raw)-1] ^= 1
			e.TPMTSignature = b64(raw)
		}},
		{"public changed", func(e *Evidence, _ *Binding) {
			raw, _ := base64.RawURLEncoding.DecodeString(e.TPM2BPublic)
			raw[len(raw)-1] ^= 1
			e.TPM2BPublic = b64(raw)
		}},
		{"unsupported platform", func(_ *Evidence, b *Binding) { b.Platform = "macos" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, y := ev, b
			tc.change(&x, &y)
			if _, err := Verify(x, y, store, time.Now()); err == nil {
				t.Fatal("forged evidence accepted")
			}
		})
	}
}
func TestRootRevocationAndPlatform0312(t *testing.T) {
	ev, b, store, reload := makeCertifyFixture(t)
	r, e := Verify(ev, b, store, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	config := RootFile{Schema: rootSchema, Roots: []Root{store.roots[0].Root}}
	config.RevokedAKFingerprints = []string{r.AKFingerprint}
	reload(config)
	if store.Active(r.RootID, r.AKFingerprint, b.Platform, time.Now()) {
		t.Fatal("AK revocation not immediate")
	}
	if _, err := Verify(ev, b, store, time.Now()); err == nil {
		t.Fatal("revoked AK accepted")
	}
	config.RevokedAKFingerprints = nil
	config.Roots[0].Status = "revoked"
	reload(config)
	if _, err := Verify(ev, b, store, time.Now()); err == nil {
		t.Fatal("revoked root accepted")
	}
	config.Roots[0].Status = "active"
	config.Roots[0].Platforms = []string{"windows"}
	reload(config)
	if _, err := Verify(ev, b, store, time.Now()); err == nil {
		t.Fatal("cross-platform root accepted")
	}
	config.Roots[0].Platforms = []string{"linux"}
	reload(config)
	if _, err := Verify(ev, b, store, time.Now()); err != nil {
		t.Fatalf("recovered trust: %v", err)
	}
}
func TestMalformedTPMRejectsTrailingBytes0312(t *testing.T) {
	ev, b, store, _ := makeCertifyFixture(t)
	for _, field := range []string{"pub", "attest", "signature"} {
		t.Run(field, func(t *testing.T) {
			x := ev
			switch field {
			case "pub":
				v, _ := base64.RawURLEncoding.DecodeString(x.TPM2BPublic)
				x.TPM2BPublic = b64(append(v, 0))
			case "attest":
				v, _ := base64.RawURLEncoding.DecodeString(x.TPM2BAttest)
				x.TPM2BAttest = b64(append(v, 0))
			case "signature":
				v, _ := base64.RawURLEncoding.DecodeString(x.TPMTSignature)
				x.TPMTSignature = b64(append(v, 0))
			}
			if _, err := Verify(x, b, store, time.Now()); err == nil {
				t.Fatal("trailing bytes accepted")
			}
		})
	}
}

func TestLinuxHardwareEnclaveECDSAKeyScheme0314(t *testing.T) {
	ev, binding, roots, _ := makeCertifyFixtureWithScheme(t, true)
	if _, err := Verify(ev, binding, roots, time.Now().UTC()); err != nil {
		t.Fatalf("real Linux TPM key template rejected: %v", err)
	}
	orig, _ := base64.RawURLEncoding.DecodeString(ev.TPM2BPublic)
	// TPMT_PUBLIC offsets: type[2], nameAlg[2], attrs[4], authPolicy[2],
	// symmetric[2], scheme[2], schemeHash[2]. Reject SHA-1 and unknown.
	for _, tc := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"sha1", 17, 0x04}, {"unknown-scheme", 15, 0xff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := append([]byte(nil), orig...)
			corrupted[tc.offset] = tc.value
			if _, _, err := parsePublic(corrupted); err == nil {
				t.Fatal("unsupported TPM ECC scheme/hash accepted")
			}
		})
	}
	// The root, AK and signed cert still do not establish Guard/PCR trust.
}
