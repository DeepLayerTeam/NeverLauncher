package localpassword

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/fileauth"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const saltSize = 16
const memoryKiB = 64 * 1024
const timeCost = 3
const parallelism = 1

func Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, parallelism, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memoryKiB, timeCost, parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func NeedsRehash(stored string) bool {
	return strings.HasPrefix(stored, "sha256:") || strings.HasPrefix(stored, "$never-gravit$v1$")
}

func Verify(password, stored string) bool {
	if password == "" || stored == "" {
		return false
	}
	if strings.HasPrefix(stored, "$argon2id$") {
		return verifyArgon(password, stored)
	}
	if strings.HasPrefix(stored, "sha256:") {
		if len(stored) != 71 {
			return false
		}
		sum := sha256.Sum256([]byte(password))
		return hmac.Equal([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(stored))
	}
	format, legacy, ok := fileauth.DecodeCredential(stored)
	if !ok {
		return false
	}
	switch format {
	case "bcrypt":
		return bcrypt.CompareHashAndPassword([]byte(legacy), []byte(password)) == nil
	case "phpass":
		return fileauth.VerifyPHPass(password, legacy)
	default:
		return fileauth.VerifyDigest(password, format, legacy)
	}
}

// Verify PHC without trusting cost parameters from the imported database.
// The upper limits prevent a malicious JSON import from exhausting memory.
func verifyArgon(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := map[string]uint64{}
	for _, v := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(v, "=", 2)
		if len(pair) != 2 || (pair[0] != "m" && pair[0] != "t" && pair[0] != "p") {
			return false
		}
		if _, exists := params[pair[0]]; exists {
			return false
		}
		n, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil || n == 0 {
			return false
		}
		params[pair[0]] = n
	}
	if len(params) != 3 || params["m"] > 1024*1024 || params["t"] > 20 || params["p"] > 32 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 1024 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 128 {
		return false
	}
	if params["p"] > 255 {
		return false
	}
	key := argon2.IDKey([]byte(password), salt, uint32(params["t"]), uint32(params["m"]), uint8(params["p"]), uint32(len(expected)))
	return subtle.ConstantTimeCompare(key, expected) == 1
}
