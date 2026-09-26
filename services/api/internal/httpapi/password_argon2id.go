package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2idTimeCost    = 3
	argon2idMemoryKiB   = 64 * 1024
	argon2idParallelism = 1
	argon2idSaltLength  = 16
	argon2idHashLength  = 32
)

func hashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, argon2idSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("не удалось создать salt для Argon2id: %w", err)
	}
	digest := argon2.IDKey(
		[]byte(password),
		salt,
		argon2idTimeCost,
		argon2idMemoryKiB,
		argon2idParallelism,
		argon2idHashLength,
	)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2idMemoryKiB,
		argon2idTimeCost,
		argon2idParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

func verifyPasswordArgon2id(password, encoded string) bool {
	memory, iterations, parallelism, salt, expected, ok := parseArgon2idPHC(encoded)
	if !ok {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func parseArgon2idPHC(encoded string) (uint32, uint32, uint8, []byte, []byte, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, false
	}

	values := map[string]uint64{}
	for _, parameter := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(parameter, "=", 2)
		if len(pair) != 2 || (pair[0] != "m" && pair[0] != "t" && pair[0] != "p") {
			return 0, 0, 0, nil, nil, false
		}
		if _, duplicate := values[pair[0]]; duplicate {
			return 0, 0, 0, nil, nil, false
		}
		value, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil || value == 0 {
			return 0, 0, 0, nil, nil, false
		}
		values[pair[0]] = value
	}
	memory, mok := values["m"]
	iterations, tok := values["t"]
	parallelism, pok := values["p"]
	if !mok || !tok || !pok || memory > 1024*1024 || iterations > 20 || parallelism > 32 {
		return 0, 0, 0, nil, nil, false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 1024 {
		return 0, 0, 0, nil, nil, false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 128 {
		return 0, 0, 0, nil, nil, false
	}
	return uint32(memory), uint32(iterations), uint8(parallelism), salt, expected, true
}
