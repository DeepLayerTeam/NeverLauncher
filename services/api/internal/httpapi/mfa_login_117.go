package httpapi

import (
	"errors"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type loginMFAResult117 struct {
	Methods     []string
	Strength    string
	NeedPasskey bool
}

func authMethodStrength117(methods []string) string {
	strength := "single-factor"
	for _, raw := range methods {
		v := strings.ToLower(strings.TrimSpace(raw))
		switch v {
		case "passkey", "webauthn", "user-verification", "phishing-resistant":
			return "phishing-resistant"
		case "mfa", "totp", "otp", "recovery-code":
			strength = "mfa"
		}
	}
	return strength
}

// evaluateLoginMFA117 preserves the pre-0.11.7 rule that an enabled local TOTP
// method is mandatory, while allowing a registered passkey to satisfy that
// second factor. A per-user MFA policy can additionally require any MFA or a
// phishing-resistant passkey.
func (s Server) evaluateLoginMFA117(user model.User, baseMethods []string, totp, recovery string) (loginMFAResult117, error) {
	methods := mergeAuthMethods117(baseMethods)
	strength := authMethodStrength117(methods)
	policy := s.State.Passkeys.policy(user.ID)
	passkeys := s.State.Passkeys.countByUser(user.ID)
	totpEnabled := s.State.Security.totpEnabled(user.ID)
	suppliedSecondFactor := strings.TrimSpace(totp) != "" || strings.TrimSpace(recovery) != ""

	// PHISHING_RESISTANT is intentionally local-policy controlled. An upstream
	// IdP saying "mfa" does not prove that the NeverLauncher RP saw a passkey.
	if policy == mfaPhishingResistant117 {
		if passkeys == 0 {
			return loginMFAResult117{}, errors.New("phishing-resistant MFA is required but no passkey is registered")
		}
		return loginMFAResult117{Methods: methods, Strength: strength, NeedPasskey: true}, nil
	}

	if totpEnabled {
		if suppliedSecondFactor {
			ok, reason := s.State.Security.verifySecondFactor(user.ID, totp, recovery)
			if !ok {
				return loginMFAResult117{}, errors.New("invalid local second factor")
			}
			switch reason {
			case "totp-ok":
				methods = mergeAuthMethods117(methods, "totp")
			case "recovery-ok":
				methods = mergeAuthMethods117(methods, "recovery-code")
			default:
				return loginMFAResult117{}, errors.New("invalid local second factor state")
			}
			strength = "mfa"
		} else if passkeys > 0 {
			return loginMFAResult117{Methods: methods, Strength: strength, NeedPasskey: true}, nil
		} else {
			return loginMFAResult117{}, errors.New("local second factor is required")
		}
	}

	if policy == mfaRequired117 && authStrengthLevel117(strength) < authStrengthLevel117("mfa") {
		if passkeys > 0 {
			return loginMFAResult117{Methods: methods, Strength: strength, NeedPasskey: true}, nil
		}
		return loginMFAResult117{}, errors.New("MFA is required but no usable method is configured")
	}
	return loginMFAResult117{Methods: methods, Strength: strength}, nil
}
