// Пакет authrequest разбирает критичные для безопасности запросы авторизации.
// Точка входа не должна неоднозначно трактовать JSON, принимать
// неограниченные пароли или случайно игнорировать второй JSON-документ.
package authrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const MaxBytes = 16 * 1024

var ErrTooLarge = errors.New("authentication request exceeds 16 KiB")

// Decode принимает строго один объект JSON, отклоняет повторяющиеся ключи
// (включая варианты регистра и вложенные объекты), неизвестные свойства и лишние
// данные после объекта. Ограничение байтов применяется до любого выделения
// памяти под JSON или вызова внешнего сервиса.
func Decode(src io.Reader, destination any) error {
	if src == nil {
		return errors.New("authentication request body is missing")
	}
	raw, err := io.ReadAll(io.LimitReader(src, MaxBytes+1))
	if err != nil {
		return fmt.Errorf("read authentication request: %w", err)
	}
	if len(raw) > MaxBytes {
		return ErrTooLarge
	}
	if !json.Valid(raw) {
		return errors.New("invalid authentication JSON")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueObject(check); err != nil {
		return err
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return errors.New("authentication JSON must contain one object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(destination); err != nil {
		return fmt.Errorf("decode authentication JSON: %w", err)
	}
	return nil
}

func uniqueObject(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("authentication JSON must be an object")
	}
	return consumeObject(dec)
}

func consumeObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid authentication JSON key")
		}
		// encoding/json разрешает поля структур без учёта регистра. Применяйте такую
		// же эквивалентность, чтобы запрос не мог дважды присвоить одно поле.
		key = strings.ToLower(key)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate authentication JSON key")
		}
		seen[key] = struct{}{}
		if err := consumeValue(dec); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing brace
	return err
}

func consumeValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeObject(dec)
	case '[':
		for dec.More() {
			if err := consumeValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return errors.New("unexpected authentication JSON delimiter")
	}
}
