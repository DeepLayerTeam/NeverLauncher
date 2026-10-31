package httpapi

import (
	"encoding/json"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"strings"
	"testing"
)

func TestProviderWizardStrictSecrets02910(t *testing.T) {
	cases := []struct {
		kind, config string
		valid        bool
	}{
		{"sql", `{"id":"company","driver":"postgresql","dsnEnv":"COMPANY_DSN","table":"users","columns":{"id":"id","password":"password"},"password":{"algorithm":"bcrypt"}}`, true},
		{"sql", `{"id":"company","driver":"postgresql","dsn":"postgres://admin:password@db","table":"users"}`, false},
		{"sql", `{"id":"company","dsnEnv":"COMPANY_DSN","passwordRaw":"hidden"}`, false},
		{"http", `{"id":"company","issuer":"https://issuer.example","baseUrl":"https://issuer.example","hmac":{"secretEnv":"EXTERNAL_HMAC"}}`, true},
		{"http", `{"id":"company","issuer":"https://issuer.example","baseUrl":"https://issuer.example","hmac":{"secretFile":"/var/secrets/key"}}`, false},
		{"oidc", `{"id":"company","issuer":"https://issuer.example","clientId":"app","clientSecretEnv":"EXTERNAL_SECRET","redirectUris":[]}`, true},
		{"oidc", `{"id":"company","clientSecret":"plaintext"}`, false},
		{"microsoft", `{"id":"company","tenant":"consumers","clientId":"app","redirectUris":[]}`, true},
		{"microsoft", `{"id":"company","clientSecretFile":"/secrets"}`, false},
		{"sql", `{"id":"wrong","dsnEnv":"COMPANY_DSN"}`, false},
	}
	for i, c := range cases {
		v := repository.ManagedProviderRevision02910{ID: "company", Kind: c.kind, Config: json.RawMessage(c.config), Reason: "test connection"}
		err := validateManagedSecrets02910(v)
		if (err == nil) != c.valid {
			t.Errorf("case %d: expected valid=%v got err=%v", i, c.valid, err)
		}
	}
}
func TestProviderWizardSecretDetectionIsRecursive02910(t *testing.T) {
	v := repository.ManagedProviderRevision02910{ID: "company", Kind: "http", Config: json.RawMessage(`{"id":"company","hmac":{"secretEnv":"EXTERNAL_HMAC","clientSecret":"password"}}`), Reason: "test"}
	if err := validateManagedSecrets02910(v); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
}
