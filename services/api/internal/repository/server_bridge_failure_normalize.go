package repository

import "unicode/utf8"

// normalizeServerBridgeControlFailure ограничивает сохраняемый текст PostgreSQL
// 1024 байтами UTF-8 с сохранением целых Unicode-символов. Нормализуйте до первого
// ACK и повторных идемпотентных запросов, чтобы одинаковые обращения сравнивались
// одинаково.
func normalizeServerBridgeControlFailure(failure string) string {
	if len(failure) <= 1024 {
		return failure
	}
	cut := 1024
	for cut > 0 && !utf8.RuneStart(failure[cut]) {
		cut--
	}
	return failure[:cut]
}
