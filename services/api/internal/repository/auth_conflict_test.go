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
		t.Fatal("unique auth identity not recognized as collision")
	}
	original := fakeSQLState0293("57014")
	if converted := authIdentityConflict0293(original); converted != original {
		t.Fatalf("non-uniqueness database error changed: %v", converted)
	}
}
