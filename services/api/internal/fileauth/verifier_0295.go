package fileauth

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strings"
)

// VerifyDigest is the portable Gravit digest/doubleDigest verifier for explicit
// algorithms. Gravit toHexMode hashes the lowercase hex *text* of pass one;
// binary mode hashes the original digest bytes.
func VerifyDigest(password, format, stored string) bool {
	algorithm := format
	doubled := strings.HasPrefix(algorithm, "double-")
	algorithm = strings.TrimPrefix(algorithm, "double-")
	binarySecond := strings.HasSuffix(algorithm, "-binary-hex")
	algorithm = strings.TrimSuffix(algorithm, "-binary-hex")
	algorithm = strings.TrimSuffix(algorithm, "-hex")
	var h hash.Hash
	switch algorithm {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return false
	}
	if !SupportedFormat(format) || len(stored) != h.Size()*2 {
		return false
	}
	h.Write([]byte(password))
	first := h.Sum(nil)
	if doubled {
		h.Reset()
		if binarySecond {
			h.Write(first)
		} else {
			h.Write([]byte(hex.EncodeToString(first)))
		}
		first = h.Sum(nil)
	}
	return hmac.Equal([]byte(hex.EncodeToString(first)), []byte(strings.ToLower(stored)))
}

const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func validPHPass(hash string) bool {
	if len(hash) != 34 || !(strings.HasPrefix(hash, "$P$") || strings.HasPrefix(hash, "$H$")) {
		return false
	}
	count := strings.IndexByte(alphabet, hash[3])
	if count < 7 || count > 17 {
		return false
	}
	for i := 4; i < len(hash); i++ {
		if strings.IndexByte(alphabet, hash[i]) < 0 {
			return false
		}
	}
	return true
}

func VerifyPHPass(password, encoded string) bool {
	if !validPHPass(encoded) {
		return false
	}
	iterations := 1 << uint(strings.IndexByte(alphabet, encoded[3]))
	digest := md5.Sum(append([]byte(encoded[4:12]), []byte(password)...))
	for i := 0; i < iterations; i++ {
		h := md5.New()
		h.Write(digest[:])
		h.Write([]byte(password))
		copy(digest[:], h.Sum(nil))
	}
	return hmac.Equal([]byte(phpass64(digest[:])), []byte(encoded[12:]))
}

func phpass64(data []byte) string {
	var out strings.Builder
	for i := 0; i < len(data); {
		value := int(data[i])
		i++
		out.WriteByte(alphabet[value&0x3f])
		if i < len(data) {
			value |= int(data[i]) << 8
		}
		out.WriteByte(alphabet[(value>>6)&0x3f])
		if i >= len(data) {
			break
		}
		i++
		if i < len(data) {
			value |= int(data[i]) << 16
		}
		out.WriteByte(alphabet[(value>>12)&0x3f])
		if i >= len(data) {
			break
		}
		i++
		out.WriteByte(alphabet[(value>>18)&0x3f])
	}
	return out.String()
}
