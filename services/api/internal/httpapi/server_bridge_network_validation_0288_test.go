package httpapi

import "testing"

func TestNetworkCapacityValidation0288(t *testing.T) {
	tests := []struct {
		in       string
		ok       bool
		nilValue bool
		value    int
	}{
		{"null", true, true, 0}, {"0", true, false, 0}, {"1", true, false, 1},
		{"1000000", true, false, 1000000}, {"", false, false, 0},
		{"-1", false, false, 0}, {"1000001", false, false, 0},
		{"1.5", false, false, 0}, {"\"1\"", false, false, 0},
		{"true", false, false, 0}, {"1 2", false, false, 0},
	}
	for _, tc := range tests {
		value, err := parseNetworkCapacity0288([]byte(tc.in))
		if (err == nil) != tc.ok {
			t.Errorf("%q: err=%v", tc.in, err)
			continue
		}
		if !tc.ok {
			continue
		}
		if (value == nil) != tc.nilValue {
			t.Errorf("%q: nil mismatch", tc.in)
			continue
		}
		if value != nil && *value != tc.value {
			t.Errorf("%q: got %d", tc.in, *value)
		}
	}
}
