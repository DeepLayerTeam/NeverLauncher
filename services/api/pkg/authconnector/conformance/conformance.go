// Пакет conformance запускает структурные и интеграционные тесты с реальными фикстурами для
// тех же интерфейсов, которые федерация Launcher использует в production.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}
type Report struct {
	ConnectorID string  `json:"connectorId"`
	Mode        string  `json:"mode"`
	Passed      bool    `json:"passed"`
	Checks      []Check `json:"checks"`
}

type BrowserFixture struct {
	Start authconnector.BrowserAuthRequest
	// Complete должен завершить реальную транзакцию авторизации тестового IdP.
	// Не журналировать интерактивный браузер, пароли пользователей или refresh-токены.
	Complete func(context.Context, authconnector.BrowserAuthStart) (authconnector.BrowserAuthCallback, error)
}

// Fixture ДОЛЖНА ссылаться на одноразовую или явно выделенную тестовую
// учётную запись. Отзыв разрушителен и может включаться только явно.
// Отсутствие фикстур для заявленных возможностей означает провал проверки поведения.
type Fixture struct {
	Password     *authconnector.PasswordRequest
	Browser      *BrowserFixture
	Subject      string
	Issuer       string
	RefreshToken string
	RevokeToken  string
	AllowRevoke  bool
	// Провайдер может поддерживать привязку, но федерация владеет
	// канонической привязкой аккаунтов и требует нового доказательства (тестируется отдельно).
	VerifyRevokedToken bool
}

func (r *Report) add(name string, err error) {
	c := Check{Name: name, Passed: err == nil}
	if err != nil {
		r.Passed = false
		// Не включать ошибки провайдера или их обёрнутые причины: сторонний
		// ошибки могут содержать секреты, подписанные URL, токены доступа или PII.
		var e *authconnector.Error
		if errors.As(err, &e) && e.Code != "" {
			c.Message = "provider error: " + string(e.Code)
		} else {
			c.Message = "check failed"
		}
	}
	r.Checks = append(r.Checks, c)
}

// Run выполняет недеструктивные проверки регистрации/работоспособности. Успешный
// структурный отчёт НЕ является успешным отчётом проверки поведения.
func Run(ctx context.Context, connector authconnector.Connector) Report {
	r := Report{Mode: "structural", Passed: true}
	if err := authconnector.ValidateConnector(connector); err != nil {
		r.add("registration", err)
		return r
	}
	meta := connector.Metadata()
	r.ConnectorID = meta.ID
	r.add("registration", authconnector.ValidateConnector(connector))
	healthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r.add("health", connector.Health(healthCtx))
	return r
}

// RunBehavioral вызывает реальные методы провайдера, проверяет инварианты после
// каждого ответа и не раскрывает значения токенов/учётных данных/идентичностей. Он не
// создаёт и не привязывает аккаунт; доказательство привязки тестируется на уровне федерации.
func RunBehavioral(ctx context.Context, connector authconnector.Connector, fixture Fixture) Report {
	r := Run(ctx, connector)
	r.Mode = "behavioral"
	if connector == nil || !r.Passed {
		return r
	}
	meta := connector.Metadata()
	var auth authconnector.Authentication
	var haveAuth bool
	var subject string
	if authconnector.HasCapability(meta, authconnector.CapabilityPasswordAuth) {
		if fixture.Password == nil || strings.TrimSpace(fixture.Password.Identifier) == "" || fixture.Password.Secret == "" {
			r.add("authenticate:password", fmt.Errorf("Отсутствуют тестовые учётные данные"))
		} else {
			result, err := connector.(authconnector.PasswordAuthenticator).AuthenticatePassword(ctx, *fixture.Password)
			if err == nil {
				err = authconnector.ValidateAuthentication(result)
			}
			if err == nil {
				err = expectIdentity(result.Identity, fixture.Subject, fixture.Issuer)
			}
			r.add("authenticate:password", err)
			if err == nil {
				auth = result
				haveAuth = true
				subject = result.Identity.Subject
			}
			// Неправильные учётные данные должны отклоняться: поведение fail-open запрещено.
			invalid := *fixture.Password
			invalid.Secret += "-launcher-invalid-proof"
			_, invalidErr := connector.(authconnector.PasswordAuthenticator).AuthenticatePassword(ctx, invalid)
			if invalidErr == nil {
				r.add("authenticate:wrong-password", fmt.Errorf("Недействительные учётные данные были приняты"))
			} else if code := authconnector.CodeOf(invalidErr); code != authconnector.ErrInvalidCredentials && code != authconnector.ErrIdentityDisabled {
				r.add("authenticate:wrong-password", fmt.Errorf("Ошибка не классифицирована как отклонение учётных данных"))
			} else {
				r.add("authenticate:wrong-password", nil)
			}
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		if fixture.Browser == nil || fixture.Browser.Complete == nil {
			r.add("authenticate:browser", fmt.Errorf("Отсутствуют тестовые данные браузера"))
		} else {
			start, err := connector.(authconnector.BrowserAuthenticator).BeginBrowserAuth(ctx, fixture.Browser.Start)
			if err == nil && (start.AuthorizationURL == "" || start.State != fixture.Browser.Start.State) {
				err = fmt.Errorf("Недопустимая браузерная транзакция")
			}
			if err == nil {
				var cb authconnector.BrowserAuthCallback
				cb, err = fixture.Browser.Complete(ctx, start)
				if err == nil {
					var result authconnector.Authentication
					result, err = connector.(authconnector.BrowserAuthenticator).CompleteBrowserAuth(ctx, cb)
					if err == nil {
						err = authconnector.ValidateAuthentication(result)
					}
					if err == nil {
						err = expectIdentity(result.Identity, fixture.Subject, fixture.Issuer)
					}
					if err == nil {
						if haveAuth && (auth.Identity.Subject != result.Identity.Subject || auth.Identity.Issuer != result.Identity.Issuer) {
							err = fmt.Errorf("Идентификаторы при входе через браузер и пароль не совпадают")
						}
						if !haveAuth {
							auth = result
							haveAuth = true
							subject = result.Identity.Subject
						}
					}
				}
			}
			r.add("authenticate:browser", err)
		}
	}
	if subject == "" {
		subject = fixture.Subject
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityUserLookup) {
		if subject == "" {
			r.add("resolve:identity", fmt.Errorf("missing subject"))
		} else {
			identity, err := connector.(authconnector.IdentityResolver).ResolveIdentity(ctx, authconnector.ResolveRequest{Subject: subject})
			if err == nil {
				err = authconnector.ValidateIdentity(identity)
			}
			if err == nil {
				err = expectIdentity(identity, subject, fixture.Issuer)
			}
			r.add("resolve:identity", err)
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityProfile) {
		if subject == "" {
			r.add("resolve:profile", fmt.Errorf("missing subject"))
		} else {
			profile, err := connector.(authconnector.ProfileResolver).ResolveProfile(ctx, authconnector.ResolveRequest{Subject: subject})
			if err == nil {
				err = authconnector.ValidateProfile(profile, subject)
			}
			r.add("resolve:profile", err)
		}
	}
	token := fixture.RefreshToken
	if token == "" && haveAuth {
		token = auth.ProviderToken
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityTokenRefresh) {
		if token == "" || subject == "" {
			r.add("refresh", fmt.Errorf("Отсутствуют тестовые данные для обновления токена"))
		} else {
			refreshed, err := connector.(authconnector.TokenRefresher).Refresh(ctx, token)
			if err == nil {
				err = authconnector.ValidateAuthentication(refreshed)
			}
			if err == nil {
				err = expectIdentity(refreshed.Identity, subject, fixture.Issuer)
			}
			r.add("refresh", err)
			if err == nil && refreshed.ProviderToken != "" {
				token = refreshed.ProviderToken
			}
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityTokenRevoke) {
		if !fixture.AllowRevoke || subject == "" {
			r.add("revoke", fmt.Errorf("Тестовый сценарий отзыва не включён"))
		} else {
			revokeToken := fixture.RevokeToken
			if revokeToken == "" {
				revokeToken = token
			}
			if revokeToken == "" {
				r.add("revoke", fmt.Errorf("Отсутствует токен для отзыва"))
			} else {
				err := connector.(authconnector.Revoker).Revoke(ctx, authconnector.RevokeRequest{Subject: subject, ProviderToken: revokeToken})
				r.add("revoke", err)
				if err == nil && fixture.VerifyRevokedToken {
					if refresher, ok := connector.(authconnector.TokenRefresher); ok && authconnector.HasCapability(meta, authconnector.CapabilityTokenRefresh) {
						_, err = refresher.Refresh(ctx, revokeToken)
						if err == nil {
							r.add("revoke:invalidation", fmt.Errorf("Отозванные учётные данные по-прежнему действительны"))
						} else if code := authconnector.CodeOf(err); code != authconnector.ErrInvalidCredentials && code != authconnector.ErrIdentityDisabled {
							r.add("revoke:invalidation", fmt.Errorf("Отзыв учётных данных не подтверждён"))
						} else {
							r.add("revoke:invalidation", nil)
						}
					}
				}
			}
		}
	}
	if !authconnector.HasCapability(meta, authconnector.CapabilityPasswordAuth) && !authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		r.add("authenticate", fmt.Errorf("Нет поддерживаемого способа авторизации"))
	}
	return r
}

func expectIdentity(identity authconnector.Identity, subject, issuer string) error {
	if subject != "" && identity.Subject != subject {
		return fmt.Errorf("Субъект идентификации изменился")
	}
	if issuer != "" && identity.Issuer != issuer {
		return fmt.Errorf("Источник идентификации изменился")
	}
	return nil
}
