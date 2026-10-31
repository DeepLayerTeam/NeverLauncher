package httpapi

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

func TestProviderRuntimeParity0296UpstreamCannotSatisfyNeverMFA(t *testing.T) {
	user := model.User{ID: "parity-user", Status: "active", RoleID: "player"}
	server := Server{State: NewRuntimeState()}
	if err := server.State.Passkeys.setPolicy(user.ID, mfaRequired117); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		provider string
		methods  []string
	}{
		{"HTTP", []string{"password", "mfa", "passkey", "totp"}},
		{"OIDC", []string{"pwd", "mfa", "webauthn"}},
		{"Microsoft", []string{"microsoft", "mfa", "phishing-resistant"}},
		{"SQL", []string{"password", "mfa"}},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			if result, err := server.evaluateLoginMFA117(user, tc.methods, "", ""); err == nil || result.Strength == "mfa" || result.Strength == "phishing-resistant" {
				t.Fatalf("upstream MFA claim bypassed Never MFA policy: result=%+v err=%v", result, err)
			}
		})
	}
	// Without a local MFA requirement, the login can proceed but the signed
	// Never session must remain single-factor, regardless of upstream amr.
	if err := server.State.Passkeys.setPolicy(user.ID, mfaOptional117); err != nil {
		t.Fatal(err)
	}
	login, err := server.evaluateLoginMFA117(user, []string{"mfa", "passkey", "totp", "oidc"}, "", "")
	if err != nil || login.Strength != "single-factor" || login.NeedPasskey {
		t.Fatalf("unexpected Never auth strength: %+v err=%v", login, err)
	}
	for _, method := range login.Methods {
		if method == "mfa" || method == "passkey" || method == "totp" {
			t.Fatalf("upstream factor appeared as local factor: %+v", login.Methods)
		}
	}
	if !strings.Contains(strings.Join(login.Methods, ","), "upstream:passkey") {
		t.Fatalf("missing external assurance provenance: %+v", login.Methods)
	}
}
