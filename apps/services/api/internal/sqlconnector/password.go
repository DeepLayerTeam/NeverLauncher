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
			return false, errors.New("Некорректное значение: префикс хеша bcrypt")
		}
		cost, err := bcryptCost(encoded)
		if err != nil {
			return false, err
		}
		if cost < 4 || cost > 16 {
			return false, fmt.Errorf("Стоимость bcrypt %d выходит за безопасный диапазон Launcher 4–16", cost)
		}
		return verifyBcryptSystem(secret, encoded), nil
	case "pbkdf2-sha256":
		return verifyPBKDF2SHA256(secret, encoded, cfg.PBKDF2MinIterations)
	case "digest", "double-digest":
		if !cfg.AllowLegacyHashes {
			return false, errors.New("Устаревшие контрольные суммы отключены")
		}
		return verifyGravitDigest(secret, encoded, cfg)
	case "phpass":
		if !cfg.AllowLegacyHashes {
			return false, errors.New("Устаревший PHPass отключён")
		}
		return verifyPHPass(secret, encoded)
	case "legacy-sha256":
		if !cfg.AllowLegacySHA256 {
			return false, errors.New("Проверка устаревших SHA-256 отключена")
		}
		return verifyLegacySHA256(secret, encoded), nil
	default:
		return false, fmt.Errorf("Не поддерживается: алгоритм хеширования пароля %q", cfg.Algorithm)
	}
}

func consumePasswordWork(secret string, cfg PasswordConfig) {
	// Для неизвестных идентификаторов намеренно выполняется подходящая для алгоритма работа,
	// чтобы удалённый клиент не мог легко отличить «пользователь не найден» от «неверный
	// пароль» по длительности хеширования. Ошибки и результаты намеренно отбрасываются.
	var encoded string
	switch cfg.Algorithm {
	case "argon2id":
		salt := base64.RawStdEncoding.EncodeToString([]byte("launcher-dummy-salt"))
		digest := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
		encoded = "$argon2id$v=19$m=65536,t=3,p=1$" + salt + "$" + digest
	case "bcrypt":
		encoded = "$2y$10$xskAkxff64efsclNY8HUa.BoeuCiSQFbUuLnwNQc8krReAyjtKS3e"
	case "pbkdf2-sha256":
		iterations := cfg.PBKDF2MinIterations
		if iterations <= 0 {
			iterations = 10000
		}
		salt := []byte("launcher-dummy-salt")
		encoded = "$pbkdf2-sha256$" + strconv.Itoa(iterations) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	case "digest", "double-digest":
		size := digestLength(cfg.DigestAlgorithm)
		if size == 0 {
			return
		}
		encoded = strings.Repeat("0", size*2)
		if cfg.DigestEncoding == "base64" {
			encoded = base64.StdEncoding.EncodeToString(make([]byte, size))
		}
	case "phpass":
		// Допустимый dummy-хеш с фиксированной стоимостью; не проверять и не раскрывать существование аккаунта.
		encoded = "$P$B12345678QjY5zqJqT433Q3av7QGRM/"
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
		return errors.New("Некорректное значение: строка PHC алгоритма argon2id")
	}
	if parts[2] != "v=19" {
		return fmt.Errorf("Не поддерживается: версия argon2 %q", parts[2])
	}
	var memory uint64
	var iterations uint64
	var parallelism uint64
	for _, parameter := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(parameter, "=", 2)
		if len(pair) != 2 {
			return errors.New("Некорректное значение: параметры argon2id")
		}
		value, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil || value == 0 {
			return errors.New("Некорректное значение: значение параметра argon2id")
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
		return errors.New("Требуется: параметры m/t/p алгоритма argon2id")
	}
	if memory > 1024*1024 || iterations > 20 || parallelism > 32 {
		return errors.New("Параметры argon2id превышают безопасные пределы Launcher")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return errors.New("Некорректное значение: соль argon2id")
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(digest) < 16 || len(digest) > 128 {
		return errors.New("Некорректное значение: хеш argon2id")
	}
	return nil
}

func bcryptCost(encoded string) (int, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) < 4 {
		return 0, errors.New("Некорректное значение: хеш bcrypt")
	}
	cost, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, errors.New("Некорректное значение: стоимость вычисления bcrypt")
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
			return false, errors.New("Некорректное значение: хеш pbkdf2-sha256")
		}
		parsed, err := strconv.Atoi(parts[2])
		if err != nil {
			return false, errors.New("Некорректное значение: число итераций PBKDF2")
		}
		iterations = parsed
		salt, err = decodeBase64Flexible(parts[3])
		if err != nil {
			return false, errors.New("Некорректное значение: соль pbkdf2")
		}
		expected, err = decodeBase64Flexible(parts[4])
		if err != nil {
			return false, errors.New("Некорректное значение: дайджест PBKDF2")
		}
	} else if strings.HasPrefix(encoded, "pbkdf2_sha256$") {
		parts := strings.Split(encoded, "$")
		if len(parts) != 4 {
			return false, errors.New("Некорректное значение: хеш Django pbkdf2_sha256")
		}
		parsed, err := strconv.Atoi(parts[1])
		if err != nil {
			return false, errors.New("Некорректное значение: число итераций PBKDF2")
		}
		iterations = parsed
		salt = []byte(parts[2])
		expected, err = decodeBase64Flexible(parts[3])
		if err != nil {
			return false, errors.New("Некорректное значение: дайджест PBKDF2")
		}
	} else {
		return false, errors.New("Не поддерживается: формат хеша pbkdf2-sha256")
	}
	if iterations < minIterations {
		return false, fmt.Errorf("Число итераций pbkdf2 %d меньше заданного минимума %d", iterations, minIterations)
	}
	if iterations > 10_000_000 {
		return false, errors.New("Число итераций pbkdf2 превышает безопасный предел Launcher")
	}
	if len(salt) < 8 || len(expected) < 16 || len(expected) > 128 {
		return false, errors.New("Некорректное значение: длина соли или хеша pbkdf2")
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
