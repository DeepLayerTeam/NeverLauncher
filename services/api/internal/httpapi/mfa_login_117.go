package httpapi

import (
	"errors"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
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

// evaluateLoginMFA117 сохраняет правило до 0.11.7: включённый
// локальный TOTP обязателен, но зарегистрированный passkey может
// удовлетворить второму фактору. Политика пользователя также
// может требовать любой MFA или устойчивый к фишингу passkey.
func (s Server) evaluateLoginMFA117(user model.User, baseMethods []string, totp, recovery string) (loginMFAResult117, error) {
	// A connector's authMethods (including signed HTTP claims and verified OIDC
	// amr) report what the *upstream* provider did. They are not evidence that
	// NeverLauncher verified a local TOTP, recovery code or passkey. In
	// particular a remote "passkey"/"mfa" string must never satisfy the local
	// MFA policy or produce a privileged Never authStrength.
	methods := mergeAuthMethods117(authconnector.SafeUpstreamAuthMethods(baseMethods))
	strength := authMethodStrength117(methods)
	policy := s.State.Passkeys.policy(user.ID)
	passkeys := s.State.Passkeys.countByUser(user.ID)
	totpEnabled := s.State.Security.totpEnabled(user.ID)
	suppliedSecondFactor := strings.TrimSpace(totp) != "" || strings.TrimSpace(recovery) != ""

	// PHISHING_RESISTANT специально контролируется локальной политикой. Заявление
	// внешнего IdP о "mfa" не доказывает, что RP NeverLauncher проверил passkey.
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
