// Package fileauth читает настоящую базу GravitLauncher FileAuthSystem
// Database.json. Sessions.json с токенами OAuth и Minecraft намеренно никогда не
// используется.
package fileauth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const MaxDatabaseBytes = 16 << 20
const MaxAccounts = 20000
const EmailDomain = "fileauth.invalid"
const credentialPrefix = "$gravit$v1$"

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)
var uuidPattern = regexp.MustCompile(`^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$`)

// Account представляет лишь поля, необходимые для миграции пользователя
// FileAuthSystem. Поля прав и ролей Gravit намеренно НЕ считаются доверенными для
// систему контроля доступа RBAC NeverLauncher.
type Account struct {
	UUID         string
	Username     string
	Email        string
	PasswordHash string
}

type rawUser struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Parse читает JSON Gravit в формате Map<UUID, UserEntity> с ключами UUID. Пароли
// никогда не проверяются угадыванием алгоритма: формат обязательно выбирает
// оператор.
func Parse(r io.Reader, format string) ([]Account, error) {
	if !SupportedFormat(format) {
		return nil, errors.New("Формат пароля Gravit не поддерживается или отсутствует")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxDatabaseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDatabaseBytes {
		return nil, errors.New("База данных FileAuth превышает 16 МиБ")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	startToken, err := decoder.Token()
	if err != nil || startToken != json.Delim('{') {
		return nil, errors.New("Файл Database.json системы FileAuth должен содержать объект JSON с ключами UUID")
	}
	items := make([]Account, 0)
	names := map[string]bool{}
	uuids := map[string]bool{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("Некорректное значение: FileAuth ключ: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("Ключи JSON системы FileAuth должны быть строками")
		}
		var src rawUser
		if err := decoder.Decode(&src); err != nil {
			return nil, fmt.Errorf("Некорректное значение: FileAuth пользователь: %w", err)
		}
		uuid := strings.ToLower(strings.TrimSpace(key))
		if !uuidPattern.MatchString(uuid) || (src.UUID != "" && !strings.EqualFold(src.UUID, uuid)) {
			return nil, errors.New("Ключ FileAuth не соответствует UUID либо UUID недопустим")
		}
		name := src.Username
		if !usernamePattern.MatchString(name) {
			return nil, errors.New("Имя пользователя FileAuth не соответствует правилам Minecraft")
		}
		if names[strings.ToLower(name)] || uuids[uuid] {
			return nil, errors.New("Обнаружен дубликат имени пользователя или UUID в FileAuth")
		}
		names[strings.ToLower(name)] = true
		uuids[uuid] = true
		encoded, err := EncodeCredential(format, src.Password)
		if err != nil {
			return nil, fmt.Errorf("Некорректный формат учётных данных FileAuth для %q: %w", name, err)
		}
		items = append(items, Account{UUID: uuid, Username: name, Email: strings.ToLower(name) + "@" + EmailDomain, PasswordHash: encoded})
		if len(items) > MaxAccounts {
			return nil, errors.New("Количество учётных записей FileAuth превышает лимит")
		}
	}
	endToken, err := decoder.Token()
	if err != nil || endToken != json.Delim('}') {
		return nil, errors.New("Некорректный завершающий разделитель JSON в FileAuth")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("В Database.json FileAuth обнаружены лишние данные")
	}
	if len(items) == 0 {
		return nil, errors.New("База учётных записей FileAuth пуста")
	}

	sort.Slice(items, func(i, j int) bool { return items[i].UUID < items[j].UUID })
	return items, nil
}

func SupportedFormat(format string) bool {
	switch format {
	case "sha256-hex", "sha256-base64url", "md5-hex", "sha1-hex", "sha512-hex",
		"double-md5-hex", "double-md5-binary-hex", "double-sha1-hex", "double-sha1-binary-hex",
		"double-sha256-hex", "double-sha256-binary-hex", "double-sha512-hex", "double-sha512-binary-hex",
		"phpass", "bcrypt", "argon2id":
		return true
	default:
		return false
	}
}

// EncodeCredential детерминированно сохраняет исходный верификатор; открытого
// пароля у него НИКОГДА нет, и неизвестные пароли он не пытается перехешировать.
func EncodeCredential(format, hash string) (string, error) {
	if !SupportedFormat(format) || len(hash) == 0 || len(hash) > 1024 {
		return "", errors.New("Неизвестный формат пароля или некорректная длина хеша")
	}
	switch format {
	case "sha256-base64url":
		raw, err := base64.RawURLEncoding.Strict().DecodeString(hash)
		if err != nil && strings.HasSuffix(hash, "=") {
			raw, err = base64.URLEncoding.Strict().DecodeString(hash)
		}
		if err != nil || len(raw) != 32 || (base64.RawURLEncoding.EncodeToString(raw) != hash && base64.URLEncoding.EncodeToString(raw) != hash) {
			return "", errors.New("Некорректное значение: SHA256 Base64URL дайджест")
		}
		hash = hex.EncodeToString(raw)
		format = "sha256-hex"
	case "md5-hex", "sha1-hex", "sha256-hex", "sha512-hex",
		"double-md5-hex", "double-md5-binary-hex", "double-sha1-hex", "double-sha1-binary-hex",
		"double-sha256-hex", "double-sha256-binary-hex", "double-sha512-hex", "double-sha512-binary-hex":
		algorithm := strings.TrimSuffix(strings.TrimPrefix(format, "double-"), "-binary-hex")
		algorithm = strings.TrimSuffix(algorithm, "-hex")
		length := map[string]int{"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}[algorithm]
		if length == 0 || len(hash) != length {
			return "", errors.New("Длина контрольной суммы не соответствует выбранному алгоритму")
		}
		raw, err := hex.DecodeString(hash)
		if err != nil || len(raw)*2 != len(hash) {
			return "", errors.New("Некорректный шестнадцатеричный хеш")
		}
		hash = strings.ToLower(hash)
	case "phpass":
		if len(hash) != 34 || !(strings.HasPrefix(hash, "$P$") || strings.HasPrefix(hash, "$H$")) {
			return "", errors.New("Некорректное значение: PHPass хеш")
		}
		if !validPHPass(hash) {
			return "", errors.New("Небезопасный или повреждённый хеш PHPass")
		}
	case "bcrypt":
		if len(hash) != 60 || !(strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")) {
			return "", errors.New("Некорректное значение: хеш bcrypt")
		}
		if hash[4] < '0' || hash[4] > '1' || hash[5] < '0' || hash[5] > '9' || hash[6] != '$' {
			return "", errors.New("Некорректное значение: стоимость вычисления bcrypt")
		}
		cost := int(hash[4]-'0')*10 + int(hash[5]-'0')
		if cost < 4 || cost > 16 {
			return "", errors.New("Параметр стоимости bcrypt находится вне диапазона 4..16")
		}
	case "argon2id":
		if !ValidateArgon2id(hash) {
			return "", errors.New("Некорректные или небезопасные параметры Argon2id/PHC")
		}
		return hash, nil
	}
	return credentialPrefix + format + "$" + base64.RawURLEncoding.EncodeToString([]byte(hash)), nil
}

func DecodeCredential(encoded string) (format, hash string, ok bool) {
	if !strings.HasPrefix(encoded, credentialPrefix) {
		return "", "", false
	}
	values := strings.Split(strings.TrimPrefix(encoded, credentialPrefix), "$")
	if len(values) != 2 || !SupportedFormat(values[0]) || len(values[1]) > 1500 {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(values[1])
	if err != nil {
		return "", "", false
	}
	original := string(raw)
	normalized, err := EncodeCredential(values[0], original)
	if err != nil || normalized != encoded {
		return "", "", false
	}
	return values[0], original, true
}

// UsernameEmail выводит email только из явно проверенного имени Gravit;
// произвольные идентификаторы, похожие на email, не переписываются для другого
// аккаунта.
func UsernameEmail(identifier string) (string, bool) {
	if !usernamePattern.MatchString(identifier) {
		return "", false
	}
	return strings.ToLower(identifier) + "@" + EmailDomain, true
}

// ValidateArgon2id проверяет полную строку PHC до импорта записи. Ограничения стоимости
// предотвращают чрезмерный расход RAM на входе при вредоносном импорте.
func ValidateArgon2id(stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	seen := map[string]bool{}
	values := map[string]uint64{}
	for _, v := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(v, "=", 2)
		if len(pair) != 2 || (pair[0] != "m" && pair[0] != "t" && pair[0] != "p") || seen[pair[0]] {
			return false
		}
		n, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil || n == 0 {
			return false
		}
		values[pair[0]] = n
		seen[pair[0]] = true
	}
	if len(values) != 3 || values["m"] < 8 || values["m"] > 256*1024 || values["t"] > 10 || values["p"] > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	digest, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(digest) < 16 || len(digest) > 64 {
		return false
	}
	return true
}

// ValidateAccount защищает прямые вызовы репозитория, а также парсер CLI.
func ValidateAccount(a Account) error {
	if !uuidPattern.MatchString(a.UUID) || !usernamePattern.MatchString(a.Username) {
		return errors.New("Некорректные UUID или имя пользователя FileAuth")
	}
	email, ok := UsernameEmail(a.Username)
	if !ok || a.Email != email {
		return errors.New("Некорректное сопоставление электронной почты FileAuth")
	}
	if strings.HasPrefix(a.PasswordHash, "$argon2id$") {
		if ValidateArgon2id(a.PasswordHash) {
			return nil
		}
	} else {
		if _, _, ok := DecodeCredential(a.PasswordHash); ok {
			return nil
		}
	}
	return errors.New("Учётные данные FileAuth не поддерживаются или повреждены")
}
