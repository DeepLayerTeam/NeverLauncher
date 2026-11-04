package authconnector

import (
	"strings"
	"testing"
)

func TestSafeUpstreamAuthMethods0296(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"local password", []string{"password"}, []string{"password"}},
		{"oidc amr", []string{"pwd", "mfa", "fido", "webauthn"}, []string{"pwd", "upstream:mfa", "upstream:fido", "upstream:webauthn"}},
		{"http assertions", []string{"passkey", "totp", "recovery-code", "phishing-resistant"}, []string{"upstream:passkey", "upstream:totp", "upstream:recovery-code", "upstream:phishing-resistant"}},
		{"issuer normalizes", []string{" Microsoft ", "microsoft", "OAUTH"}, []string{"microsoft", "oauth"}},
		{"unknown custom", []string{"privileged"}, []string{"upstream:privileged"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeUpstreamAuthMethods(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("methods=%q want=%q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("methods=%q want=%q", got, tc.want)
				}
			}
		})
	}
	long := SafeUpstreamAuthMethods([]string{strings.Repeat("x", 64)})
	if len(long) != 1 || len(long[0]) > 64 || !strings.HasPrefix(long[0], "upstream:") {
		t.Fatalf("method bounds not enforced: %q", long)
	}
}
