package repository

import (
	"errors"
	"fmt"
)

// authIdentityConflict0293 converts a concurrent PostgreSQL uniqueness conflict
// into an explicit linkage collision. It avoids relying on driver-specific
// imports and preserves all other database failures unchanged.
func authIdentityConflict0293(err error) error {
	if err == nil {
		return nil
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "23505", "23P01":
			return fmt.Errorf("%w: auth identity uniqueness violation: %w", ErrConflict, err)
		}
	}
	return err
}
