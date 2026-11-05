package repository

import (
	"errors"
	"fmt"
)

// authIdentityConflict0293 преобразует параллельный конфликт уникальности PostgreSQL
// в явную коллизию привязки. Не зависит от импортов конкретного драйвера, сохраняя
// остальные ошибки БД без изменений.
func authIdentityConflict0293(err error) error {
	if err == nil {
		return nil
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "23505", "23P01":
			return fmt.Errorf("%w: нарушена уникальность идентификатора авторизации: %w", ErrConflict, err)
		}
	}
	return err
}
