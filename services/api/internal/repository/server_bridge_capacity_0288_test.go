package repository

import "testing"

func TestEffectiveBridgeCapacity0288(t *testing.T) {
	capOf := func(i int) *int { return &i }
	for _, tc := range []struct {
		signed   int
		limit    *int
		expected int
	}{
		{0, nil, 0}, {40, nil, 40}, {40, capOf(20), 20},
		{40, capOf(0), 0}, {40, capOf(90), 40}, {0, capOf(15), 15},
	} {
		if got := effectiveBridgeCapacity0288(tc.signed, tc.limit); got != tc.expected {
			t.Errorf("signed=%d got=%d want=%d", tc.signed, got, tc.expected)
		}
	}
}
