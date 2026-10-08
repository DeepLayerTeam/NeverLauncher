package sqlconnector

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func verifyPassword(secret, encoded string, cfg PasswordConfig) (bool, error) {
	switch cfg.Algorithm {
	case "argon2id":
		if err := validateArgon2idPHC(encoded); err != nil {
			return false, err
		}
		return verifyArgon2idSystem(secret, encoded), nil
	case "bcrypt":
		if !strings.HasPrefix(encoded, "$2a$") && !strings.HasPrefix(encoded, "$2b$") && !strings.HasPrefix(encoded, "$2y$") {
			return false, errors.New("invalid bcrypt hash prefix")
		}
		cost, err := bcryptCost(encoded)
		if err != nil {
			return false, err
		}
		if cost < 4 || cost > 16 {
			return false, fmt.Errorf("bcrypt cost %d is outside NeverLauncher safety range 4..16", cost)
		}
		return verifyBcryptSystem(secret, encoded), nil
	case "pbkdf2-sha256":
		return verifyPBKDF2SHA256(secret, encoded, cfg.PBKDF2MinIterations)
	case "legacy-sha256":
		if !cfg.AllowLegacySHA256 {
			return false, errors.New("legacy SHA-256 verification is disabled")
		}
		return verifyLegacySHA256(secret, encoded), nil
	default:
		return false, fmt.Errorf("unsupported password algorithm %q", cfg.Algorithm)
	}
}

func consumePasswordWork(secret string, cfg PasswordConfig) {
	// Unknown identifiers deliberately perform algorithm-appropriate work so a remote
	// caller cannot trivially distinguish "user missing" from "password wrong" by
	// comparing password-hash latency. Errors/results are intentionally discarded.
	var encoded string
	switch cfg.Algorithm {
	case "argon2id":
		salt := base64.RawStdEncoding.EncodeToString([]byte("neverlauncher-dummy-salt"))
		digest := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
		encoded = "$argon2id$v=19$m=65536,t=3,p=1$" + salt + "$" + digest
	case "bcrypt":
		encoded = "$2y$10$xskAkxff64efsclNY8HUa.BoeuCiSQFbUuLnwNQc8krReAyjtKS3e"
	case "pbkdf2-sha256":
		iterations := cfg.PBKDF2MinIterations
		if iterations <= 0 {
			iterations = 10000
		}
		salt := []byte("neverlauncher-dummy-salt")
		encoded = "$pbkdf2-sha256$" + strconv.Itoa(iterations) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	case "legacy-sha256":
		encoded = strings.Repeat("0", sha256.Size*2)
	default:
		return
	}
	_, _ = verifyPassword(secret, encoded, cfg)
}

func validateArgon2idPHC(encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("invalid argon2id PHC string")
	}
	if parts[2] != "v=19" {
		return fmt.Errorf("unsupported argon2 version %q", parts[2])
	}
	var memory uint64
	var iterations uint64
	var parallelism uint64
	for _, parameter := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(parameter, "=", 2)
		if len(pair) != 2 {
			return errors.New("invalid argon2id parameters")
		}
		value, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil || value == 0 {
			return errors.New("invalid argon2id parameter value")
		}
		switch pair[0] {
		case "m":
			memory = value
		case "t":
			iterations = value
		case "p":
			parallelism = value
		}
	}
	if memory == 0 || iterations == 0 || parallelism == 0 {
		return errors.New("argon2id parameters m/t/p are required")
	}
	if memory > 1024*1024 || iterations > 20 || parallelism > 32 {
		return errors.New("argon2id parameters exceed NeverLauncher safety limits")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return errors.New("invalid argon2id salt")
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(digest) < 16 || len(digest) > 128 {
		return errors.New("invalid argon2id digest")
	}
	return nil
}

func bcryptCost(encoded string) (int, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) < 4 {
		return 0, errors.New("invalid bcrypt hash")
	}
	cost, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, errors.New("invalid bcrypt cost")
	}
	return cost, nil
}

func verifyPBKDF2SHA256(secret, encoded string, minIterations int) (bool, error) {
	var iterations int
	var salt []byte
	var expected []byte

	if strings.HasPrefix(encoded, "$pbkdf2-sha256$") {
		parts := strings.Split(encoded, "$")
		if len(parts) != 5 {
			return false, errors.New("invalid pbkdf2-sha256 hash")
		}
		parsed, err := strconv.Atoi(parts[2])
		if err != nil {
			return false, errors.New("invalid pbkdf2 iteration count")
		}
		iterations = parsed
		salt, err = decodeBase64Flexible(parts[3])
		if err != nil {
			return false, errors.New("invalid pbkdf2 salt")
		}
		expected, err = decodeBase64Flexible(parts[4])
		if err != nil {
			return false, errors.New("invalid pbkdf2 digest")
		}
	} else if strings.HasPrefix(encoded, "pbkdf2_sha256$") {
		parts := strings.Split(encoded, "$")
		if len(parts) != 4 {
			return false, errors.New("invalid Django pbkdf2_sha256 hash")
		}
		parsed, err := strconv.Atoi(parts[1])
		if err != nil {
			return false, errors.New("invalid pbkdf2 iteration count")
		}
		iterations = parsed
		salt = []byte(parts[2])
		expected, err = decodeBase64Flexible(parts[3])
		if err != nil {
			return false, errors.New("invalid pbkdf2 digest")
		}
	} else {
		return false, errors.New("unsupported pbkdf2-sha256 hash format")
	}
	if iterations < minIterations {
		return false, fmt.Errorf("pbkdf2 iteration count %d is below configured minimum %d", iterations, minIterations)
	}
	if iterations > 10_000_000 {
		return false, errors.New("pbkdf2 iteration count exceeds NeverLauncher safety limit")
	}
	if len(salt) < 8 || len(expected) < 16 || len(expected) > 128 {
		return false, errors.New("invalid pbkdf2 salt/digest length")
	}
	actual := pbkdf2SHA256([]byte(secret), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	hashLength := sha256.Size
	blocks := (keyLength + hashLength - 1) / hashLength
	result := make([]byte, 0, blocks*hashLength)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLength]
}

func verifyLegacySHA256(secret, encoded string) bool {
	encoded = strings.TrimSpace(strings.ToLower(encoded))
	encoded = strings.TrimPrefix(encoded, "sha256:")
	if len(encoded) != sha256.Size*2 {
		return false
	}
	expected, err := hex.DecodeString(encoded)
	if err != nil {
		return false
	}
	actual := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(actual[:], expected) == 1
}

func decodeBase64Flexible(value string) ([]byte, error) {
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
