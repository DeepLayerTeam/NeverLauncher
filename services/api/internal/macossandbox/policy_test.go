package macossandbox

import "testing"

func TestValidateGrants(t *testing.T) {
	good := []struct{ r, w, n, s []string }{{[]string{"package", "shared:assets"}, []string{"scratch", "shared:work"}, []string{"example.org:443"}, []string{"api_key"}}, {nil, nil, nil, nil}}
	for _, tc := range good {
		if err := ValidateGrants(tc.r, tc.w, tc.n, tc.s); err != nil {
			t.Fatal(err)
		}
	}
	bad := []struct{ r, w, n, s []string }{{[]string{"/etc"}, nil, nil, nil}, {nil, []string{"../secret"}, nil, nil}, {nil, nil, []string{"https://example.com"}, nil}, {nil, nil, nil, []string{"../../secret"}}}
	for _, tc := range bad {
		if ValidateGrants(tc.r, tc.w, tc.n, tc.s) == nil {
			t.Fatal("dangerous grant accepted", tc)
		}
	}
}
func TestPathContainment(t *testing.T) {
	for _, p := range []string{"/tmp/extension/../secrets", "/tmp/other", "/tmp/extension"} {
		if IsInside("/tmp/extension", p) {
			t.Fatalf("path accepted: %s", p)
		}
	}
	if !IsInside("/tmp/extension", "/tmp/extension/runner") {
		t.Fatal("valid path refused")
	}
}
