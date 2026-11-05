package attestverify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	tpmMagic    uint32 = 0xff544347
	tpmCertify  uint16 = 0x8017
	tpmECC      uint16 = 0x0023
	tpmSHA256   uint16 = 0x000b
	tpmNull     uint16 = 0x0010
	tpmNISTP256 uint16 = 0x0003
	tpmRSASSA   uint16 = 0x0014
	tpmRSAPSS   uint16 = 0x0016
	tpmECDSA    uint16 = 0x0018
)

type Evidence struct {
	TPM2BPublic      string   `json:"tpm2bPublic"`   // base64url of TPM2B_PUBLIC
	TPM2BAttest      string   `json:"tpm2bAttest"`   // base64url of TPM2B_ATTEST
	TPMTSignature    string   `json:"tpmtSignature"` // base64url of TPMT_SIGNATURE
	AKCertificatePEM string   `json:"akCertificatePem"`
	IntermediatesPEM []string `json:"intermediatesPem,omitempty"`
}
type Binding struct {
	UserID          string
	DeviceID        string
	SessionID       string
	BindingEpoch    int64
	ChallengeID     string
	Challenge       string
	DevicePublicKey []byte // зарегистрированный открытый ключ SEC1 P-256 без сжатия
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Platform        string
}
type Result struct {
	RootID          string
	RootFingerprint string
	AKFingerprint   string
	ExpiresAt       time.Time
}

type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.b)-c.pos {
		return nil, errors.New("Структура TPM обрезана")
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v, nil
}
func (c *cursor) u16() (uint16, error) {
	b, e := c.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (c *cursor) u32() (uint32, error) {
	b, e := c.take(4)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint32(b), nil
}
func (c *cursor) tpm2b(max int) ([]byte, error) {
	n, e := c.u16()
	if e != nil {
		return nil, e
	}
	if int(n) > max {
		return nil, errors.New("Превышен допустимый размер: TPM2B")
	}
	return c.take(int(n))
}
func (c *cursor) end() error {
	if c.pos != len(c.b) {
		return errors.New("После структуры TPM обнаружены лишние байты")
	}
	return nil
}
func decode(s string, limit int) ([]byte, error) {
	if len(s) > limit*2 {
		return nil, errors.New("Превышен допустимый размер: подтверждающие данные")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) == 0 || len(b) > limit {
		return nil, errors.New("Некорректное значение: «evidence base64url»")
	}
	return b, nil
}

// ExpectedExtraData — хеш с разделением доменов от всего запроса и привязки активной
// сессии/устройства. Поле TPM2_Commit/Certify extraData ограничено размером.
func ExpectedExtraData(b Binding) [32]byte {
	p := fmt.Sprintf("Launcher TPM Certify v1\nuser=%s\ndevice=%s\nsession=%s\nbinding-epoch=%d\nchallenge-id=%s\nchallenge=%s\nissued-at=%s\nexpires-at=%s\n", b.UserID, b.DeviceID, b.SessionID, b.BindingEpoch, b.ChallengeID, b.Challenge, b.IssuedAt.UTC().Format(time.RFC3339Nano), b.ExpiresAt.UTC().Format(time.RFC3339Nano))
	return sha256.Sum256([]byte(p))
}
func parsePublic(raw []byte) ([]byte, []byte, error) {
	c := cursor{b: raw}
	payload, e := c.tpm2b(4096)
	if e != nil {
		return nil, nil, e
	}
	if e = c.end(); e != nil {
		return nil, nil, e
	}
	p := cursor{b: payload}
	typ, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	hash, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	attrs, e := p.u32()
	if e != nil {
		return nil, nil, e
	}
	// FixedTPM, FixedParent, SensitiveDataOrigin, Sign; RSA и экзотические варианты ECC намеренно
	// исключены.
	if typ != tpmECC || hash != tpmSHA256 || attrs&(1<<1|1<<4|1<<5|1<<18) != (1<<1|1<<4|1<<5|1<<18) {
		return nil, nil, errors.New("Ключ TPM: требуется «a fixed TPM-origin signing ECC P-256 key»")
	}
	policy, e := p.tpm2b(64)
	if e != nil {
		return nil, nil, e
	}
	_ = policy
	symmetric, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	scheme, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	// Linux hardware-enclave 0.2.10 создаёт неограниченные дочерние ключи подписи
	// P-256 со схемой TPMT_ECC_SCHEME=ECDSA(SHA-256). Windows PCP может
	// кодировать NULL. Оба варианта допустимы; при принятии ECDSA нужно прочитать
	// обязательный параметр хеша и не принять его ошибочно за идентификатор
	// кривой.
	if scheme == tpmECDSA {
		schemeHash, err := p.u16()
		if err != nil || schemeHash != tpmSHA256 {
			return nil, nil, errors.New("Схема TPM ECC должна использовать ECDSA SHA-256")
		}
	} else if scheme != tpmNull {
		return nil, nil, errors.New("Не поддерживается: схема подписи ECC в TPM")
	}
	curve, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	kdf, e := p.u16()
	if e != nil {
		return nil, nil, e
	}
	if symmetric != tpmNull || curve != tpmNISTP256 || kdf != tpmNull {
		return nil, nil, errors.New("Не поддерживается: «TPM ECC public parameters»")
	}
	x, e := p.tpm2b(32)
	if e != nil {
		return nil, nil, e
	}
	y, e := p.tpm2b(32)
	if e != nil {
		return nil, nil, e
	}
	if len(x) != 32 || len(y) != 32 || p.end() != nil {
		return nil, nil, errors.New("Некорректное значение: «TPM P-256 point encoding»")
	}
	point := make([]byte, 65)
	point[0] = 4
	copy(point[1:33], x)
	copy(point[33:], y)
	X, Y := elliptic.Unmarshal(elliptic.P256(), point)
	if X == nil || Y == nil {
		return nil, nil, errors.New("Некорректное значение: «TPM ECC point»")
	}
	h := sha256.Sum256(payload)
	name := make([]byte, 34)
	binary.BigEndian.PutUint16(name, tpmSHA256)
	copy(name[2:], h[:])
	return name, point, nil
}

// verifyTPMClockInfo проверяет подписанный TPMS_CLOCK_INFO (17 байт) и
// следующий firmwareVersion (8 байт). После неопределённости часов TPM
// выставляет safe=0; такие данные не доказывают актуальную надёжность
// платформы.
func verifyTPMClockInfo(c *cursor) error {
	info, err := c.take(17)
	if err != nil {
		return err
	}
	if info[16] != 1 {
		return errors.New("Часы TPM находятся в небезопасном состоянии")
	}
	_, err = c.take(8) // firmwareVersion
	return err
}

func parseAttest(raw []byte, expected [32]byte, name []byte) error {
	c := cursor{b: raw}
	inner, e := c.tpm2b(4096)
	if e != nil {
		return e
	}
	if e = c.end(); e != nil {
		return e
	}
	t := cursor{b: inner}
	magic, e := t.u32()
	if e != nil {
		return e
	}
	typ, e := t.u16()
	if e != nil {
		return e
	}
	if magic != tpmMagic || typ != tpmCertify {
		return errors.New("Данные не являются аттестацией TPM2 Certify")
	}
	signer, e := t.tpm2b(128)
	if e != nil {
		return e
	}
	_ = signer
	extra, e := t.tpm2b(64)
	if e != nil {
		return e
	}
	if !bytes.Equal(extra, expected[:]) {
		return errors.New("Несоответствие: TPM аттестация nonce/session/binding")
	}
	if e = verifyTPMClockInfo(&t); e != nil {
		return e
	}
	certified, e := t.tpm2b(128)
	if e != nil {
		return e
	}
	if !bytes.Equal(certified, name) {
		return errors.New("Несовпадение: «certified key name»")
	}
	if _, e = t.tpm2b(128); e != nil {
		return e
	} // qualifiedName
	return t.end()
}
func parseSignature(raw []byte, public crypto.PublicKey, attest []byte) error {
	c := cursor{b: raw}
	alg, e := c.u16()
	if e != nil {
		return e
	}
	h, e := c.u16()
	if e != nil {
		return e
	}
	if h != tpmSHA256 {
		return errors.New("Подпись TPM должна использовать SHA-256")
	}
	// TPM подписывает тело TPMS_ATTEST без внешнего поля длины TPM2B.
	if len(attest) < 2 {
		return errors.New("Пустое значение: «TPM attest»")
	}
	digest := sha256.Sum256(attest[2:])
	switch alg {
	case tpmECDSA:
		pub, ok := public.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return errors.New("Сертификат ключа подтверждения AK не использует P-256 ECDSA")
		}
		r, e := c.tpm2b(66)
		if e != nil {
			return e
		}
		s, e := c.tpm2b(66)
		if e != nil {
			return e
		}
		if c.end() != nil || len(r) == 0 || len(s) == 0 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)) {
			return errors.New("Некорректное значение: «TPM ECDSA certify signature»")
		}
	case tpmRSASSA, tpmRSAPSS:
		pub, ok := public.(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 {
			return errors.New("Не поддерживается: RSA AK")
		}
		sig, e := c.tpm2b(1024)
		if e != nil {
			return e
		}
		if e = c.end(); e != nil {
			return e
		}
		if alg == tpmRSASSA {
			e = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
		} else {
			e = rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		}
		if e != nil {
			return errors.New("Некорректное значение: «TPM RSA certify signature»")
		}
	default:
		return errors.New("Не поддерживается: «TPM AK signature scheme»")
	}
	return nil
}

// Verify аутентифицирует настоящий результат TPM2 Certify от AK, выпущенного CA, и
// связывает сертифицированный ключ подписи fixedTPM с точно зарегистрированным
// ключом устройства. Это не проверка измеренной загрузки или целостности
// работающего пользовательского процесса.
func Verify(e Evidence, b Binding, store *Store, now time.Time) (Result, error) {
	fail := func(msg string) (Result, error) { return Result{}, errors.New(msg) }
	if store == nil {
		return fail("Недоступны корневые сертификаты доверия TPM AK")
	}
	if b.UserID == "" || b.DeviceID == "" || b.SessionID == "" || b.BindingEpoch < 1 || b.ChallengeID == "" || len(b.Challenge) < 32 || b.Platform != "windows" && b.Platform != "linux" {
		return fail("Неполная привязка запроса проверки TPM")
	}
	if now.Before(b.IssuedAt.Add(-10*time.Second)) || !now.Before(b.ExpiresAt) || b.ExpiresAt.Sub(b.IssuedAt) > 2*time.Minute+time.Second {
		return fail("Запрос аттестации недействителен или срок его действия истёк")
	}
	if len(b.DevicePublicKey) != 65 || b.DevicePublicKey[0] != 4 {
		return fail("Зарегистрированный ключ должен иметь формат P-256 SEC1")
	}
	tpmPub, err := decode(e.TPM2BPublic, 4098)
	if err != nil {
		return Result{}, err
	}
	name, key, err := parsePublic(tpmPub)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(key, b.DevicePublicKey) {
		return fail("Сертифицированный открытый ключ не соответствует зарегистрированному устройству")
	}
	attest, err := decode(e.TPM2BAttest, 4098)
	if err != nil {
		return Result{}, err
	}
	if err = parseAttest(attest, ExpectedExtraData(b), name); err != nil {
		return Result{}, err
	}
	signature, err := decode(e.TPMTSignature, 2048)
	if err != nil {
		return Result{}, err
	}
	cert, intermediatePool, err := parseAKChain(e)
	if err != nil {
		return Result{}, err
	}
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fail("Сертификат AK должен быть сертификатом подписи, а не удостоверяющего центра")
	}
	fp := Fingerprint(cert.Raw)
	if store.revokedAK[fp] {
		return fail("Сертификат AK отозван")
	}
	if err = parseSignature(signature, cert.PublicKey, attest); err != nil {
		return Result{}, err
	}
	for _, root := range store.roots {
		if !store.Active(root.ID, fp, b.Platform, now) {
			continue
		}
		p := x509.NewCertPool()
		p.AddCert(root.certificate)
		_, err = cert.Verify(x509.VerifyOptions{Roots: p, Intermediates: intermediatePool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if err != nil {
			continue
		}
		expires := now.Add(1 * time.Hour)
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
		if root.NotAfter.Before(expires) {
			expires = root.NotAfter
		}
		return Result{RootID: root.ID, RootFingerprint: root.fingerprint, AKFingerprint: fp, ExpiresAt: expires}, nil
	}
	return fail("Отсутствует доверенная действующая цепочка сертификатов AK")
}
