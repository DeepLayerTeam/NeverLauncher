package attestverify

// Проверка TPM2 Quote независима от TPM2 Certify. Действительная цепочка AK
// идентифицирует ключ аттестации; только подписанный дайджест PCR и политика
// оператора определяют одобренную конфигурацию измеренной загрузки. Ни одно из
// них не доказывает целостность JVM в пользовательском режиме.
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
	PCRs      map[string]string `json:"pcrs"` // банк SHA-256: для каждого индекса — ровно 32 байта в шестнадцатеричном представлении
	NotBefore time.Time         `json:"notBefore"`
	NotAfter  time.Time         `json:"notAfter"`
}
type PCRPolicyFile0315 struct {
	Schema   string          `json:"schema"`
	Policies []PCRPolicy0315 `json:"policies"`
}

// LoadPCRPolicy0315 читает политику при каждом использовании; пути под контролем
// клиента нет. Её SHA-256 связан с запросом, так что изменение политики во время
// проверки аннулирует запрос. Обязателен явный список разрешений, а не нулевая базовая
// линия или регистрация TOFU.
func LoadPCRPolicy0315(path string, now time.Time) (PCRPolicyFile0315, string, error) {
	var out PCRPolicyFile0315
	if !filepath.IsAbs(path) {
		return out, "", errors.New("Требуется: «absolute operator PCR policy path»")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return out, "", err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() <= 0 || st.Size() > 1<<20 {
		return out, "", errors.New("PCR policy file: требуется «regular and non-group/world-writable»")
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
		return out, "", errors.New("Политика PCR содержит лишние данные")
	}
	if out.Schema != "launcher/tpm-pcr-policy/v1" || len(out.Policies) == 0 || len(out.Policies) > 64 {
		return out, "", errors.New("Некорректное значение: PCR политика schema/count")
	}
	seen := map[string]bool{}
	for _, p := range out.Policies {
		if p.ID == "" || len(p.ID) > 96 || seen[p.ID] || (p.Platform != "windows" && p.Platform != "linux") ||
			p.NotBefore.IsZero() || !p.NotAfter.After(p.NotBefore) || len(p.PCRs) == 0 || len(p.PCRs) > 24 {
			return out, "", errors.New("Некорректное значение: «or duplicate PCR policy»")
		}
		seen[p.ID] = true
		for k, v := range p.PCRs {
			n, e := strconv.Atoi(k)
			if e != nil || n < 0 || n > 23 || k != strconv.Itoa(n) || !isSHA256(v) {
				return out, "", errors.New("Некорректное значение: «PCR selection/digest in policy»")
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
	return PCRPolicy0315{}, errors.New("Политика PCR неактивна для платформы устройства")
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
	PCRValues        map[string]string `json:"pcrValues"` // хеши в шестнадцатеричном виде, только явно выбранные индексы PCR
	AKCertificatePEM string            `json:"akCertificatePem"`
	IntermediatesPEM []string          `json:"intermediatesPem,omitempty"`
}

func ExpectedQuoteData0315(b Binding, policyID, policyHash string) [32]byte {
	// Независимый nonce с разделением доменов (доказательство Certify никогда не
	// является Quote).
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
		return fail("Недействительная или просроченная привязка TPM Quote либо политика PCR")
	}
	if len(p.PCRs) == 0 || len(p.PCRs) > 24 || len(e.PCRValues) != len(p.PCRs) {
		return fail("Набор регистров PCR должен точно соответствовать политике")
	}
	indices := PCRIndices0315(p)
	h := sha256.New()
	for _, index := range indices {
		k := strconv.Itoa(index)
		got, ok := e.PCRValues[k]
		if !ok || !isSHA256(got) || got != p.PCRs[k] {
			return fail("Значение PCR запрещено политикой измеряемой загрузки")
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
		return fail("Недействительный TPM2B Quote")
	}
	q := cursor{b: inner}
	magic, err := q.u32()
	if err != nil {
		return fail("Неполные данные TPM Quote")
	}
	typ, err := q.u16()
	if err != nil || magic != tpmMagic || typ != tpmQuote {
		return fail("Не является свидетельством TPM2 Quote")
	}
	_, err = q.tpm2b(128)
	if err != nil {
		return fail("Недействительная подпись TPM Quote")
	}
	qualifier, err := q.tpm2b(64)
	if err != nil {
		return fail("Недействительный квалификатор TPM Quote")
	}
	expected := ExpectedQuoteData0315(b, p.ID, policyHash)
	if !bytes.Equal(qualifier, expected[:]) {
		return fail("Несовпадение nonce, сеанса, эпохи или политики TPM Quote")
	}
	if err = verifyTPMClockInfo(&q); err != nil {
		return fail("Небезопасные или неполные данные часов либо прошивки TPM Quote")
	}
	count, err := q.u32()
	if err != nil || count != 1 {
		return fail("TPM Quote должен выбирать ровно один банк PCR")
	}
	alg, err := q.u16()
	if err != nil || alg != tpmSHA256 {
		return fail("TPM Quote должен использовать банк PCR SHA-256")
	}
	sz, err := q.take(1)
	if err != nil || len(sz) != 1 || sz[0] != 3 {
		return fail("Неподдерживаемая ширина битовой маски выбора PCR")
	}
	mask, err := q.take(3)
	if err != nil {
		return fail("Не указан набор PCR")
	}
	var required [3]byte
	for _, i := range indices {
		if i < 0 || i >= 24 {
			return fail("Индекс PCR вне допустимого диапазона")
		}
		required[i/8] |= 1 << uint(i%8)
	}
	if !bytes.Equal(mask, required[:]) {
		return fail("Набор PCR в TPM Quote отличается от указанного в политике")
	}
	digest, err := q.tpm2b(64)
	if err != nil || q.end() != nil {
		return fail("Недействительный хеш PCR в TPM Quote")
	}
	if !bytes.Equal(digest, expectedDigest) {
		return fail("Хеш PCR в TPM Quote не соответствует переданным значениям выбранных PCR")
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
		return fail("Ключ AK в TPM Quote отличается от действующего сертифицированного аппаратного идентификатора")
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
		return fail("Цепочка сертификатов AK для TPM Quote больше не является доверенной")
	}
	expiration := now.Add(5 * time.Minute) // краткосрочный объект; статус отзыва повторно проверяется при запросе состояния
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
		return fail("Срок действия проверки TPM Quote уже истёк")
	}
	return QuoteResult0315{RootID: pinned.RootID, RootFingerprint: pinned.RootFingerprint, AKFingerprint: fp, PCRDigest: hex.EncodeToString(expectedDigest), PolicyID: p.ID, PolicyHash: policyHash, ExpiresAt: expiration}, nil
}

// Вспомогательная функция только для передачи канонического списка обязательных PCR
// нативным клиентам.
func EncodeQuoteNonce0315(b Binding, p PCRPolicy0315, policyHash string) string {
	x := ExpectedQuoteData0315(b, p.ID, policyHash)
	return base64.RawURLEncoding.EncodeToString(x[:])
}

// Для внешних инструментов политики и будущего аудита: значение сверяется с
// точным выбором Quote, а не считается самостоятельно заявленным
// доказательством.
func PCRPolicySelection0315(p PCRPolicy0315) string {
	ids := PCRIndices0315(p)
	xs := make([]string, 0, len(ids))
	for _, i := range ids {
		xs = append(xs, strconv.Itoa(i))
	}
	return "sha256:" + strings.Join(xs, ",")
}
