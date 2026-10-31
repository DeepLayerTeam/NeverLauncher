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

// Gravit's digest and doubleDigest verifiers are UNSALTED historical CMS formats.
// Use only with explicit allowLegacyHashes opt-in. guess a digest/encoding.
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
		return nil, fmt.Errorf("unsupported Gravit digest %q", algorithm)
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
	// Reject salt prefixes, mixed encodings, prefixes such as "sha256:", and
	// non-canonical digests. A malformed row must stop login, not downgrade.
	var expected []byte
	switch cfg.DigestEncoding {
	case "hex":
		if len(encoded) != h.Size()*2 {
			return false, errors.New("invalid digest hex length")
		}
		expected, err = hex.DecodeString(encoded)
	case "base64":
		expected, err = base64.StdEncoding.Strict().DecodeString(encoded)
		if err == nil && base64.StdEncoding.EncodeToString(expected) != encoded {
			err = errors.New("non-canonical digest base64")
		}
	default:
		return false, errors.New("digest encoding must be configured as hex or base64")
	}
	if err != nil || len(expected) != h.Size() {
		return false, errors.New("invalid digest encoding or length")
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

// verifyPHPass supports the portable $P$/$H$ MD5 hashes used by WordPress and
// Gravit AdditionalHash. Blowfish ($2y$) hashes use the explicit bcrypt verifier.
// Very high cost settings are rejected before doing any work (DoS protection).
func verifyPHPass(secret, encoded string) (bool, error) {
	if len(encoded) != 34 || !(strings.HasPrefix(encoded, "$P$") || strings.HasPrefix(encoded, "$H$")) {
		return false, errors.New("invalid PHPass portable hash format")
	}
	countLog2 := strings.IndexByte(phpassAlphabet, encoded[3])
	if countLog2 < 7 || countLog2 > 17 {
		return false, errors.New("PHPass iteration count outside allowed range 7..17")
	}
	salt := encoded[4:12]
	for i := 0; i < len(salt); i++ {
		if strings.IndexByte(phpassAlphabet, salt[i]) < 0 {
			return false, errors.New("invalid PHPass salt")
		}
	}
	for i := 12; i < len(encoded); i++ {
		if strings.IndexByte(phpassAlphabet, encoded[i]) < 0 {
			return false, errors.New("invalid PHPass encoding")
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
