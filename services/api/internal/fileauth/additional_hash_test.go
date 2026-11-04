package fileauth

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strings"
	"testing"
)

func TestAdditionalHashAllSupportedDoubleDigest0426(t *testing.T) {
	for _, test := range []struct {
		name     string
		makeHash func() hash.Hash
	}{
		{"md5", md5.New}, {"sha1", sha1.New}, {"sha256", sha256.New}, {"sha512", sha512.New},
	} {
		h := test.makeHash()
		h.Write([]byte("Gravit-Password-426"))
		raw := h.Sum(nil)
		for _, binary := range []bool{false, true} {
			h.Reset()
			data := []byte(hex.EncodeToString(raw))
			if binary {
				data = raw
			}
			h.Write(data)
			expected := hex.EncodeToString(h.Sum(nil))
			format := "double-" + test.name + "-hex"
			if binary {
				format = "double-" + test.name + "-binary-hex"
			}
			if !VerifyDigest("Gravit-Password-426", format, expected) {
				t.Fatalf("%s rejected", format)
			}
			if VerifyDigest("wrong", format, expected) {
				t.Fatalf("%s wrong password accepted", format)
			}
			stored, err := EncodeCredential(format, expected)
			if err != nil {
				t.Fatalf("%s cannot import: %v", format, err)
			}
			if alg, hash, ok := DecodeCredential(stored); !ok || alg != format || hash != expected {
				t.Fatalf("%s lost during storage", format)
			}
		}
		if _, err := EncodeCredential("double-"+test.name+"-hex", strings.Repeat("f", h.Size()*2-2)); err == nil {
			t.Fatal("invalid digest length accepted")
		}
	}
}
