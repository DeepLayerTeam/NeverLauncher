package attestverify

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Эти регрессии выполняют настоящие криптографические верификаторы, а не
// доверяют заявленному клиентом состоянию TPM или неподписанной метке платформы.
func TestCertifyUnsafeTPMClock0436(t *testing.T) {
	evidence, binding, roots, _ := makeCertifyFixture(t)
	now := time.Now().UTC()
	if _, err := Verify(evidence, binding, roots, now); err != nil {
		t.Fatalf("Отклонено безопасное доказательство TPM: %v", err)
	}
	pub, err := decode(evidence.TPM2BPublic, 4098)
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := parsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	original, err := decode(evidence.TPM2BAttest, 4098)
	if err != nil {
		t.Fatal(err)
	}
	body := original[2:]
	c := cursor{b: body}
	_, _ = c.take(6)    // magic and type
	_, _ = c.tpm2b(128) // qualifiedSigner
	_, _ = c.tpm2b(64)  // extraData
	safeOffset := c.pos + 16
	for _, invalid := range []byte{0, 2, 255} {
		mutated := append([]byte(nil), original...)
		mutated[2+safeOffset] = invalid
		if err := parseAttest(mutated, ExpectedExtraData(binding), name); err == nil || !strings.Contains(strings.ToLower(err.Error()), "час") {
			t.Fatalf("Ошибочно принято небезопасное время TPM %d: %v", invalid, err)
		}
		modified := evidence
		modified.TPM2BAttest = base64.RawURLEncoding.EncodeToString(mutated)
		if _, err := Verify(modified, binding, roots, now); err == nil {
			t.Fatalf("Ошибочно принята небезопасная аппаратная аттестация при safe=%d", invalid)
		}
	}
}

func TestQuoteUnsafeTPMClock0436(t *testing.T) {
	evidence, binding, policy, hash, pinned, roots := makeQuoteFixture0315(t)
	now := time.Now().UTC()
	if _, err := VerifyQuote0315(evidence, binding, policy, hash, pinned, roots, now); err != nil {
		t.Fatalf("Отклонено корректное свидетельство TPM: %v", err)
	}
	original, err := decode(evidence.TPM2BAttest, 4098)
	if err != nil {
		t.Fatal(err)
	}
	c := cursor{b: original[2:]}
	_, _ = c.take(6)
	_, _ = c.tpm2b(128)
	_, _ = c.tpm2b(64)
	safeOffset := c.pos + 16
	for _, invalid := range []byte{0, 2, 255} {
		mutated := append([]byte(nil), original...)
		mutated[2+safeOffset] = invalid
		modified := evidence
		modified.TPM2BAttest = base64.RawURLEncoding.EncodeToString(mutated)
		if _, err := VerifyQuote0315(modified, binding, policy, hash, pinned, roots, now); err == nil || !strings.Contains(strings.ToLower(err.Error()), "час") {
			t.Fatalf("Небезопасное время свидетельства TPM %d принято либо не проверено: %v", invalid, err)
		}
	}
}
