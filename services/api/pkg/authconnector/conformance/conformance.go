// Package conformance executes structural and live-fixture tests against the
// same interfaces the Launcher federation uses in production.
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
	// Complete must complete the test IdP's actual authorization transaction.
	// No interactive browser, user passwords or refresh tokens are logged.
	Complete func(context.Context, authconnector.BrowserAuthStart) (authconnector.BrowserAuthCallback, error)
}

// Fixture MUST refer to a disposable or otherwise explicitly dedicated test
// account. Revocation is destructive and can be enabled only explicitly.
// Missing fixtures for advertised capabilities fail behavioral conformance.
type Fixture struct {
	Password     *authconnector.PasswordRequest
	Browser      *BrowserFixture
	Subject      string
	Issuer       string
	RefreshToken string
	RevokeToken  string
	AllowRevoke  bool
	// The provider may support linking, but the Never federation owns the
	// canonical account link and requires fresh proof (tested separately).
	VerifyRevokedToken bool
}

func (r *Report) add(name string, err error) {
	c := Check{Name: name, Passed: err == nil}
	if err != nil {
		r.Passed = false
		// Do not embed provider errors or their wrapped causes: third-party
		// errors may contain secrets, signed URLs, access tokens or PII.
		var e *authconnector.Error
		if errors.As(err, &e) && e.Code != "" {
			c.Message = "provider error: " + string(e.Code)
		} else {
			c.Message = "check failed"
		}
	}
	r.Checks = append(r.Checks, c)
}

// Run performs non-destructive registration/health checks. A passing
// structural report is NOT a passing behavioral conformance report.
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

// RunBehavioral exercises the actual provider methods, tests invariants after
// every response, and reports no token/credential/identity values. It does not
// create or link a Never account; linking proof is tested at federation level.
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
			r.add("authenticate:password", fmt.Errorf("missing test credentials"))
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
			// Must reject incorrect credentials: no fail-open behavior.
			invalid := *fixture.Password
			invalid.Secret += "-launcher-invalid-proof"
			_, invalidErr := connector.(authconnector.PasswordAuthenticator).AuthenticatePassword(ctx, invalid)
			if invalidErr == nil {
				r.add("authenticate:wrong-password", fmt.Errorf("accepted invalid credentials"))
			} else if code := authconnector.CodeOf(invalidErr); code != authconnector.ErrInvalidCredentials && code != authconnector.ErrIdentityDisabled {
				r.add("authenticate:wrong-password", fmt.Errorf("did not reject as credentials"))
			} else {
				r.add("authenticate:wrong-password", nil)
			}
		}
	}
	if authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		if fixture.Browser == nil || fixture.Browser.Complete == nil {
			r.add("authenticate:browser", fmt.Errorf("missing browser fixture"))
		} else {
			start, err := connector.(authconnector.BrowserAuthenticator).BeginBrowserAuth(ctx, fixture.Browser.Start)
			if err == nil && (start.AuthorizationURL == "" || start.State != fixture.Browser.Start.State) {
				err = fmt.Errorf("invalid browser transaction")
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
							err = fmt.Errorf("browser and password identities disagree")
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
			r.add("refresh", fmt.Errorf("missing refresh fixture"))
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
			r.add("revoke", fmt.Errorf("revoke fixture not enabled"))
		} else {
			revokeToken := fixture.RevokeToken
			if revokeToken == "" {
				revokeToken = token
			}
			if revokeToken == "" {
				r.add("revoke", fmt.Errorf("missing revoke token"))
			} else {
				err := connector.(authconnector.Revoker).Revoke(ctx, authconnector.RevokeRequest{Subject: subject, ProviderToken: revokeToken})
				r.add("revoke", err)
				if err == nil && fixture.VerifyRevokedToken {
					if refresher, ok := connector.(authconnector.TokenRefresher); ok && authconnector.HasCapability(meta, authconnector.CapabilityTokenRefresh) {
						_, err = refresher.Refresh(ctx, revokeToken)
						if err == nil {
							r.add("revoke:invalidation", fmt.Errorf("revoked credential still valid"))
						} else if code := authconnector.CodeOf(err); code != authconnector.ErrInvalidCredentials && code != authconnector.ErrIdentityDisabled {
							r.add("revoke:invalidation", fmt.Errorf("revocation not proved"))
						} else {
							r.add("revoke:invalidation", nil)
						}
					}
				}
			}
		}
	}
	if !authconnector.HasCapability(meta, authconnector.CapabilityPasswordAuth) && !authconnector.HasCapability(meta, authconnector.CapabilityBrowserAuth) {
		r.add("authenticate", fmt.Errorf("no supported authentication flow"))
	}
	return r
}

func expectIdentity(identity authconnector.Identity, subject, issuer string) error {
	if subject != "" && identity.Subject != subject {
		return fmt.Errorf("identity subject changed")
	}
	if issuer != "" && identity.Issuer != issuer {
		return fmt.Errorf("identity issuer changed")
	}
	return nil
}
