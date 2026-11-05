package sqlconnector

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// Проверки digest и doubleDigest в Gravit — исторические форматы CMS БЕЗ СОЛИ.
// Использовать только при явном включении allowLegacyHashes. Не угадывать дайджест/кодировку.
func gravHash(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("Не поддерживается: «Gravit digest» %q", algorithm)
	}
}

func digestLength(algorithm string) int {
	h, err := gravHash(algorithm)
	if err != nil {
		return 0
	}
	return h.Size()
}

func verifyGravitDigest(secret, encoded string, cfg PasswordConfig) (bool, error) {
	h, err := gravHash(cfg.DigestAlgorithm)
	if err != nil {
		return false, err
	}
	// Отклоняйте префиксы соли, смешанные кодировки, префиксы вроде sha256: и
	// неканонические хеши. Повреждённая строка должна прерывать вход, а не
	// снижать защиту.
	var expected []byte
	switch cfg.DigestEncoding {
	case "hex":
		if len(encoded) != h.Size()*2 {
			return false, errors.New("Некорректное значение: «digest hex length»")
		}
		expected, err = hex.DecodeString(encoded)
	case "base64":
		expected, err = base64.StdEncoding.Strict().DecodeString(encoded)
		if err == nil && base64.StdEncoding.EncodeToString(expected) != encoded {
			err = errors.New("Дайджест имеет неканоническую кодировку base64")
		}
	default:
		return false, errors.New("digest encoding: требуется «configured as hex or base64»")
	}
	if err != nil || len(expected) != h.Size() {
		return false, errors.New("Некорректное значение: «digest encoding or length»")
	}
	h.Write([]byte(secret))
	computed := h.Sum(nil)
	if cfg.Algorithm == "double-digest" {
		h.Reset()
		if cfg.DoubleDigestHex {
			h.Write([]byte(hex.EncodeToString(computed)))
		} else {
			h.Write(computed)
		}
		computed = h.Sum(nil)
	}
	return subtle.ConstantTimeCompare(computed, expected) == 1, nil
}

const phpassAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// verifyPHPass поддерживает переносимые MD5-хеши $P$/$H$, используемые WordPress и
// Gravit AdditionalHash. Хеши Blowfish ($2y$) проверяются явным bcrypt-валидатором.
// Чрезмерная стоимость отклоняется до выполнения работы для защиты от DoS.
func verifyPHPass(secret, encoded string) (bool, error) {
	if len(encoded) != 34 || !(strings.HasPrefix(encoded, "$P$") || strings.HasPrefix(encoded, "$H$")) {
		return false, errors.New("Некорректное значение: «PHPass portable hash format»")
	}
	countLog2 := strings.IndexByte(phpassAlphabet, encoded[3])
	if countLog2 < 7 || countLog2 > 17 {
		return false, errors.New("Число итераций PHPass вне разрешённого диапазона 7..17")
	}
	salt := encoded[4:12]
	for i := 0; i < len(salt); i++ {
		if strings.IndexByte(phpassAlphabet, salt[i]) < 0 {
			return false, errors.New("Некорректное значение: «PHPass salt»")
		}
	}
	for i := 12; i < len(encoded); i++ {
		if strings.IndexByte(phpassAlphabet, encoded[i]) < 0 {
			return false, errors.New("Некорректное значение: «PHPass encoding»")
		}
	}
	input := append([]byte(salt), []byte(secret)...)
	digest := md5.Sum(input)
	for i := 0; i < 1<<uint(countLog2); i++ {
		h := md5.New()
		h.Write(digest[:])
		h.Write([]byte(secret))
		copy(digest[:], h.Sum(nil))
	}
	actual := phpassEncode64(digest[:])
	return hmac.Equal([]byte(actual), []byte(encoded[12:])), nil
}

func phpassEncode64(input []byte) string {
	var b strings.Builder
	for i := 0; i < len(input); {
		value := uint(input[i])
		i++
		b.WriteByte(phpassAlphabet[value&0x3f])
		if i < len(input) {
			value |= uint(input[i]) << 8
		}
		b.WriteByte(phpassAlphabet[(value>>6)&0x3f])
		if i >= len(input) {
			break
		}
		i++
		if i < len(input) {
			value |= uint(input[i]) << 16
		}
		b.WriteByte(phpassAlphabet[(value>>12)&0x3f])
		if i >= len(input) {
			break
		}
		i++
		b.WriteByte(phpassAlphabet[(value>>18)&0x3f])
	}
	return b.String()
}
