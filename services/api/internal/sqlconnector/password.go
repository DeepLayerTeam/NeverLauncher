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
			return false, errors.New("недопустимый bcrypt хеш prefix")
		}
		cost, err := bcryptCost(encoded)
		if err != nil {
			return false, err
		}
		if cost < 4 || cost > 16 {
			return false, fmt.Errorf("bcrypt cost %d является вне NeverLauncher безопасность диапазон 4..16", cost)
		}
		return verifyBcryptSystem(secret, encoded), nil
	case "pbkdf2-sha256":
		return verifyPBKDF2SHA256(secret, encoded, cfg.PBKDF2MinIterations)
	case "legacy-sha256":
		if !cfg.AllowLegacySHA256 {
			return false, errors.New("устаревший SHA-256 проверка является отключённый")
		}
		return verifyLegacySHA256(secret, encoded), nil
	default:
		return false, fmt.Errorf("неподдерживаемый пароль algorithm %q", cfg.Algorithm)
	}
}

func consumePasswordWork(secret string, cfg PasswordConfig) {
	// Неизвестный identifiers намеренно perform algorithm-appropriate работа так удалённый
	// вызывающая сторона не может trivially distinguish "пользователь отсутствующий" из "пароль неверный" через
	// сравнивать пароль-хеш latency. Errors/results являются намеренно discarded.
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
		return errors.New("недопустимый argon2ID PHC string")
	}
	if parts[2] != "v=19" {
		return fmt.Errorf("неподдерживаемый argon2 версия %q", parts[2])
	}
	var memory uint64
	var iterations uint64
	var parallelism uint64
	for _, parameter := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(parameter, "=", 2)
		if len(pair) != 2 {
			return errors.New("недопустимый argon2ID parameters")
		}
		value, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil || value == 0 {
			return errors.New("недопустимый argon2ID parameter value")
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
		return errors.New("argon2ID parameters m/t/p являются обязательный")
	}
	if memory > 1024*1024 || iterations > 20 || parallelism > 32 {
		return errors.New("argon2ID parameters exceed NeverLauncher безопасность ограничения")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return errors.New("недопустимый argon2ID salt")
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(digest) < 16 || len(digest) > 128 {
		return errors.New("недопустимый argon2ID хеш")
	}
	return nil
}

func bcryptCost(encoded string) (int, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) < 4 {
		return 0, errors.New("недопустимый bcrypt хеш")
	}
	cost, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, errors.New("недопустимый bcrypt cost")
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
			return false, errors.New("недопустимый pbkdf2-sha256 хеш")
		}
		parsed, err := strconv.Atoi(parts[2])
		if err != nil {
			return false, errors.New("недопустимый pbkdf2 iteration счётчик")
		}
		iterations = parsed
		salt, err = decodeBase64Flexible(parts[3])
		if err != nil {
			return false, errors.New("недопустимый pbkdf2 salt")
		}
		expected, err = decodeBase64Flexible(parts[4])
		if err != nil {
			return false, errors.New("недопустимый pbkdf2 хеш")
		}
	} else if strings.HasPrefix(encoded, "pbkdf2_sha256$") {
		parts := strings.Split(encoded, "$")
		if len(parts) != 4 {
			return false, errors.New("недопустимый Django pbkdf2_sha256 хеш")
		}
		parsed, err := strconv.Atoi(parts[1])
		if err != nil {
			return false, errors.New("недопустимый pbkdf2 iteration счётчик")
		}
		iterations = parsed
		salt = []byte(parts[2])
		expected, err = decodeBase64Flexible(parts[3])
		if err != nil {
			return false, errors.New("недопустимый pbkdf2 хеш")
		}
	} else {
		return false, errors.New("неподдерживаемый pbkdf2-sha256 хеш формат")
	}
	if iterations < minIterations {
		return false, fmt.Errorf("pbkdf2 iteration счётчик %d является ниже настраивать minimum %d", iterations, minIterations)
	}
	if iterations > 10_000_000 {
		return false, errors.New("pbkdf2 iteration счётчик exceeds NeverLauncher безопасность ограничение")
	}
	if len(salt) < 8 || len(expected) < 16 || len(expected) > 128 {
		return false, errors.New("недопустимый pbkdf2 salt/digest length")
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
