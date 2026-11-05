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

var ErrTooLarge = errors.New("Запрос авторизации превышает 16 КиБ")

// Decode принимает строго один объект JSON, отклоняет повторяющиеся ключи
// (включая варианты регистра и вложенные объекты), неизвестные свойства и лишние
// данные после объекта. Ограничение байтов применяется до любого выделения
// памяти под JSON или вызова внешнего сервиса.
func Decode(src io.Reader, destination any) error {
	if src == nil {
		return errors.New("Тело запроса авторизации отсутствует")
	}
	raw, err := io.ReadAll(io.LimitReader(src, MaxBytes+1))
	if err != nil {
		return fmt.Errorf("Ошибка чтения запроса авторизации: %w", err)
	}
	if len(raw) > MaxBytes {
		return ErrTooLarge
	}
	if !json.Valid(raw) {
		return errors.New("Недопустимый JSON запроса авторизации")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueObject(check); err != nil {
		return err
	}
	if _, err := check.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON запроса авторизации должен содержать один объект")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(destination); err != nil {
		return fmt.Errorf("Ошибка декодирования JSON запроса авторизации: %w", err)
	}
	return nil
}

func uniqueObject(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("JSON запроса авторизации должен быть объектом")
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
			return errors.New("Недопустимый ключ JSON запроса авторизации")
		}
		// encoding/json разрешает поля структур без учёта регистра. Применяйте такую
		// же эквивалентность, чтобы запрос не мог дважды присвоить одно поле.
		key = strings.ToLower(key)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("Повторяющийся ключ JSON запроса авторизации")
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
		return errors.New("Неожиданный разделитель в JSON запроса авторизации")
	}
}
