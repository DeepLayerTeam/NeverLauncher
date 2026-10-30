package bridgeidentity

import (
	"errors"
	"testing"
)

func TestValidateMinecraftUUID(t *testing.T) {
	authorized := "123E4567-E89B-42D3-A456-426614174000"
	for _, test := range []struct {
		reported string
		want     error
	}{
		{"", nil},
		{"123e4567e89b42d3a456426614174000", nil},
		{"123e4567-e89b-42d3-a456-426614174000", nil},
		{"123e4567-e89b-42d3-a456-426614174001", ErrIdentityMismatch},
		{"123e4567--e89b-42d3-a456-426614174000", ErrInvalidObservedUUID},
		{"123e4567e89b42d3a45642661417400z", ErrInvalidObservedUUID},
		{"123e4567e89b42d3a456426614174000extra", ErrInvalidObservedUUID},
	} {
		if got := Validate(test.reported, authorized); !errors.Is(got, test.want) || (test.want == nil && got != nil) {
			t.Errorf("observed %q: got %v want %v", test.reported, got, test.want)
		}
	}
}

func TestInvalidTicketIdentityFailsClosed(t *testing.T) {
	for _, authorized := range []string{"", "not-a-uuid", "123e4567-e89b-42d3-a456-426614174000-extra"} {
		if got := Validate("", authorized); !errors.Is(got, ErrInvalidAuthorizedUUID) {
			t.Errorf("authorized %q: got %v", authorized, got)
		}
	}
}

func TestVerifiedOnlineModeRequiresActualUUID0398(t *testing.T) {
	const uuid = "123e4567-e89b-42d3-a456-426614174000"
	for _, row := range []struct {
		observed string
		expected error
	}{
		{"", ErrInvalidObservedUUID},
		{"  ", ErrInvalidObservedUUID},
		{"123e4567e89b42d3a456426614174000", nil},
		{"123e4567-e89b-42d3-a456-426614174001", ErrIdentityMismatch},
		{"invalid", ErrInvalidObservedUUID},
	} {
		got := ValidateVerified(row.observed, uuid)
		if !errors.Is(got, row.expected) || (row.expected == nil && got != nil) {
			t.Errorf("observed=%q returned %v, expected %v", row.observed, got, row.expected)
		}
	}
}
