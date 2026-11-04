// Пакет bridgeidentity проверяет соответствие наблюдаемого Minecraft Runtime UUID
// идентичности, авторизованной одноразовым билетом ServerBridge. Пустой наблюдаемый
// UUID допускается на прокси до входа, где аутентификация Mojang/authlib ещё не
// завершена и UUID нельзя утверждать.
package bridgeidentity

import (
	"errors"
	"strings"
)

var (
	ErrInvalidAuthorizedUUID = errors.New("serverbridge_authorized_uuid_invalid")
	ErrInvalidObservedUUID   = errors.New("serverbridge_player_uuid_invalid")
	ErrIdentityMismatch      = errors.New("serverbridge_player_uuid_mismatch")
)

// CanonicalUUID принимает только форматы UUID Minecraft: 32 шестнадцатеричные
// цифры или канонический формат 8-4-4-4-12. Произвольные строки после удаления
// знаков и префиксы UUID недопустимы.
func CanonicalUUID(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 36 {
		for _, i := range []int{8, 13, 18, 23} {
			if raw[i] != '-' {
				return "", false
			}
		}
		raw = raw[:8] + raw[9:13] + raw[14:18] + raw[19:23] + raw[24:]
	}
	if len(raw) != 32 {
		return "", false
	}
	for _, ch := range raw {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return "", false
		}
	}
	return strings.ToLower(raw), true
}

// Validate возвращает стабильный код отказа. Никогда не выводите авторизованный
// UUID игрока из недоверенного запроса Runtime. Отсутствующий UUID до входа не
// доказывает личность игрока: платформа ОБЯЗАНА самостоятельно аутентифицировать
// игровое рукопожатие до допуска соединения.
func Validate(observed, authorized string) error {
	expected, valid := CanonicalUUID(authorized)
	if !valid {
		return ErrInvalidAuthorizedUUID
	}
	if strings.TrimSpace(observed) == "" {
		return nil
	}
	actual, valid := CanonicalUUID(observed)
	if !valid {
		return ErrInvalidObservedUUID
	}
	if actual != expected {
		return ErrIdentityMismatch
	}
	return nil
}

// ValidateVerified используется только после сообщения доверенного узла Minecraft
// в онлайн-режиме о том, что наблюдаемый профиль относится к аутентифицированному
// входу. В отличие от прокси-пути до входа, пустой UUID не подтверждает
// идентичность.
func ValidateVerified(observed, authorized string) error {
	if strings.TrimSpace(observed) == "" {
		return ErrInvalidObservedUUID
	}
	return Validate(observed, authorized)
}
