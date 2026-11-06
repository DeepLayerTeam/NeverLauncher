package repository

import (
	"errors"
	"testing"
)

type fakeSQLState0293 string

func (s fakeSQLState0293) Error() string    { return "database error" }
func (s fakeSQLState0293) SQLState() string { return string(s) }

func TestAuthIdentityConflict0293(t *testing.T) {
	if !errors.Is(authIdentityConflict0293(fakeSQLState0293("23505")), ErrConflict) {
		t.Fatal("Конфликт уникального идентификатора аутентификации не обнаружен")
	}
	original := fakeSQLState0293("57014")
	if converted := authIdentityConflict0293(original); converted != original {
		t.Fatalf("Изменился тип ошибки нарушения уникальности базы данных: %v", converted)
	}
}
