package fileauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

const aliceUUID = "37a144c1-263e-4e9b-820f-917640f95b2d"
const bobUUID = "4eaa8b1a-3456-4de9-8d1d-123d6052489a"

func fixture(username, uuid, pw string) string {
	return fmt.Sprintf(`{"%s":{"username":%q,"uuid":%q,"password":%q,"permissions":{"permissions":["launchserver.*"],"roles":["ADMIN"]},"skin":{"url":"https://example.invalid/skin"}}}`, uuid, username, uuid, pw)
}
func TestParseFileAuthRealShapeAndNoPrivilegeImport0295(t *testing.T) {
	sum := sha256.Sum256([]byte("Truly-Private-Password"))
	entries, err := Parse(strings.NewReader(fixture("Alice_001", aliceUUID, hex.EncodeToString(sum[:]))), "sha256-hex")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Email != "alice_001@fileauth.invalid" || entries[0].UUID != aliceUUID {
		t.Fatalf("Неверная каноническая идентичность: %#v", entries)
	}
	if !VerifyDigest("Truly-Private-Password", "sha256-hex", hex.EncodeToString(sum[:])) {
		t.Fatal("Отклонён действительный старый пароль")
	}
	if _, pw, ok := DecodeCredential(entries[0].PasswordHash); !ok || pw != hex.EncodeToString(sum[:]) {
		t.Fatal("Невозможно проверить формат хеша")
	}
	if strings.Contains(fmt.Sprintf("%#v", entries), "ADMIN") {
		t.Fatal("Привилегированная роль Gravit не должна импортироваться")
	}
}
func TestImportLegacyBase64AndBadInputs0295(t *testing.T) {
	digest := sha256.Sum256([]byte("password"))
	file := fixture("Player_99", aliceUUID, base64.RawURLEncoding.EncodeToString(digest[:]))
	entries, err := Parse(strings.NewReader(file), "sha256-base64url")
	if err != nil {
		t.Fatal(err)
	}
	alg, hash, ok := DecodeCredential(entries[0].PasswordHash)
	if !ok || alg != "sha256-hex" || hash != hex.EncodeToString(digest[:]) {
		t.Fatalf("Неверная нормализация старой контрольной суммы %q %q %v", alg, hash, ok)
	}
	negative := []struct{ name, data, format string }{
		{"unknown-hash", file, "auto"},
		{"wrong-encoding", file, "sha256-hex"},
		{"uuid-mismatch", strings.Replace(file, aliceUUID, bobUUID, 1), "sha256-base64url"},
		{"invalid-username", strings.Replace(file, "Player_99", "a/b", 1), "sha256-base64url"},
		{"sessions", `[{"refreshToken":"s"}]`, "sha256-hex"},
		{"trailing-json", file + `{}`, "sha256-base64url"},
		{"duplicate-keys", fmt.Sprintf(`{"%s":{"username":"Alice","uuid":"%s","password":"%s"},"%s":{"username":"Bob","uuid":"%s","password":"%s"}}`, aliceUUID, aliceUUID, strings.Repeat("a", 64), aliceUUID, aliceUUID, strings.Repeat("a", 64)), "sha256-hex"},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tc.data), tc.format); err == nil {
				t.Fatal("Принят некорректный импорт")
			}
		})
	}
}
func TestDuplicateCaseInsensitiveName0295(t *testing.T) {
	h := strings.Repeat("a", 64)
	data := fmt.Sprintf(`{"%s":{"username":"Alice","uuid":"%s","password":"%s"},"%s":{"username":"alice","uuid":"%s","password":"%s"}}`, aliceUUID, aliceUUID, h, bobUUID, bobUUID, h)
	if _, err := Parse(strings.NewReader(data), "sha256-hex"); err == nil {
		t.Fatal("Импортировано неоднозначное имя игрока")
	}
}
func TestPHPassVectorsAndUnknownFormat0295(t *testing.T) {
	// Тестовый вектор portable PHPass с фиксированной стоимостью, совместимый с
	// WordPress/Gravit.
	hash := "$P$712345678o0hL6WBuvF/R0TpeZunPm0"
	if !validPHPass(hash) {
		t.Fatal("Тестовый вектор не прошёл проверку")
	}
	if !VerifyPHPass("Known-WordPress-Password", hash) {
		t.Fatal("Отклонён известный пароль PHPass")
	}
	if VerifyPHPass("wrong", hash) {
		t.Fatal("Принят неверный пароль")
	}
	if _, err := EncodeCredential("phpass", strings.Replace(hash, "$P$7", "$P$Z", 1)); err == nil {
		t.Fatal("Принята небезопасная стоимость вычисления PHPass")
	}
	if _, err := EncodeCredential("unknown", hash); err == nil {
		t.Fatal("Принят неизвестный пользовательский проверяющий модуль")
	}
}
func TestDigestVectors0295(t *testing.T) {
	plain := "password"
	sum := sha256.Sum256([]byte(plain))
	first := hex.EncodeToString(sum[:])
	second := sha256.Sum256([]byte(first))
	if !VerifyDigest(plain, "double-sha256-hex", hex.EncodeToString(second[:])) {
		t.Fatal("Ошибка двойного хеширования в шестнадцатеричном формате")
	}
	binary := sha256.Sum256(sum[:])
	if !VerifyDigest(plain, "double-sha256-binary-hex", hex.EncodeToString(binary[:])) {
		t.Fatal("Ошибка двойного хеширования двоичных данных")
	}
	if VerifyDigest(plain, "sha256-hex", hex.EncodeToString(second[:])) {
		t.Fatal("Путаница алгоритмов")
	}
}
func TestFileSizeLimit0295(t *testing.T) {
	if _, err := Parse(strings.NewReader(strings.Repeat("x", MaxDatabaseBytes+1)), "sha256-hex"); err == nil {
		t.Fatal("Принята база данных недопустимого размера")
	}
}
