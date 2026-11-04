package model

import "testing"

func TestCanonicalIssuer0291(t *testing.T) {
	checks := []struct{ provider, issuer, want string }{
		{"local", "", "launcher"},
		{"HTTP", "", "provider:http"},
		{"oidc", "https://Login.Example/tenant/v2.0", "https://Login.Example/tenant/v2.0"},
	}
	for _, tc := range checks {
		got, err := CanonicalAuthIssuer(tc.provider, tc.issuer)
		if err != nil || got != tc.want {
			t.Fatalf("%+v -> %q / %v", tc, got, err)
		}
	}
	for _, tc := range []struct{ provider, issuer string }{
		{"local", "https://evil.example"}, {"", "test"}, {"oidc", "https://issuer/with space"},
		{"oidc", "issuer\x00untrusted"},
	} {
		if got, err := CanonicalAuthIssuer(tc.provider, tc.issuer); err == nil {
			t.Fatalf("invalid issuer %q accepted as %q", tc.issuer, got)
		}
	}
}
