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

// evaluateLoginMFA117 сохраняет pre-0.11.7 правило тот включённый локальный TOTP
// метод является обязательный, пока разрешать регистрировать ключ доступа к satisfy тот
// второй factor. на-пользователь MFA политика может additionally требовать любой MFA или 
// устойчивый к фишингу ключ доступа.
func (s Server) evaluateLoginMFA117(user model.User, baseMethods []string, totp, recovery string) (loginMFAResult117, error) {
	methods := mergeAuthMethods117(baseMethods)
	strength := authMethodStrength117(methods)
	policy := s.State.Passkeys.policy(user.ID)
	passkeys := s.State.Passkeys.countByUser(user.ID)
	totpEnabled := s.State.Security.totpEnabled(user.ID)
	suppliedSecondFactor := strings.TrimSpace(totp) != "" || strings.TrimSpace(recovery) != ""

	// PHISHING_RESISTANT является намеренно локальный-политика controlled. вышестоящий проект
	// IdP saying "MFA" делает не prove тот NeverLauncher RP saw ключ доступа.
	if policy == mfaPhishingResistant117 {
		if passkeys == 0 {
			return loginMFAResult117{}, errors.New("устойчивый к фишингу MFA является обязательный но нет ключ доступа является регистрировать")
		}
		return loginMFAResult117{Methods: methods, Strength: strength, NeedPasskey: true}, nil
	}

	if totpEnabled {
		if suppliedSecondFactor {
			ok, reason := s.State.Security.verifySecondFactor(user.ID, totp, recovery)
			if !ok {
				return loginMFAResult117{}, errors.New("недопустимый локальный второй factor")
			}
			switch reason {
			case "totp-ok":
				methods = mergeAuthMethods117(methods, "totp")
			case "recovery-ok":
				methods = mergeAuthMethods117(methods, "recovery-code")
			default:
				return loginMFAResult117{}, errors.New("недопустимый локальный второй factor состояние")
			}
			strength = "mfa"
		} else if passkeys > 0 {
			return loginMFAResult117{Methods: methods, Strength: strength, NeedPasskey: true}, nil
		} else {
			return loginMFAResult117{}, errors.New("локальный второй factor является обязательный")
		}
	}

	if policy == mfaRequired117 && authStrengthLevel117(strength) < authStrengthLevel117("mfa") {
		if passkeys > 0 {
			return loginMFAResult117{Methods: methods, Strength: strength, NeedPasskey: true}, nil
		}
		return loginMFAResult117{}, errors.New("MFA является обязательный но нет usable метод является настраивать")
	}
	return loginMFAResult117{Methods: methods, Strength: strength}, nil
}
