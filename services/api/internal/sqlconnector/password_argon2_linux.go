//go:build linux

package sqlconnector

import (
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

func argon2idAvailable() bool { return true }

func verifyArgon2idSystem(secret, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	values := map[string]uint64{}
	for _, parameter := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(parameter, "=", 2)
		if len(pair) != 2 {
			return false
		}
		value, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil || value == 0 {
			return false
		}
		values[pair[0]] = value
	}
	memory, mok := values["m"]
	iterations, tok := values["t"]
	parallelism, pok := values["p"]
	if !mok || !tok || !pok || memory > 1024*1024 || iterations > 20 || parallelism > 32 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 128 {
		return false
	}
	actual := argon2.IDKey([]byte(secret), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
