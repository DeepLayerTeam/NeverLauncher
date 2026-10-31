package configmigration_test

import (
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector/configmigration"
	"strings"
	"testing"
)

type provider struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	SecretEnv string `json:"secretEnv"`
}

func TestUpgradeLegacyAndVersionedProviderConfiguration(t *testing.T) {
	entries := `[{"id":"auth", "issuer":"https://id.example", "secretEnv":"NL_SECRET"}]`
	inputs := []string{entries, `{"schemaVersion":1,"configs":` + entries + `}`, `{"schemaVersion":2,"providers":` + entries + `}`}
	for _, input := range inputs {
		got, err := configmigration.Decode[provider]([]byte(input))
		if err != nil || len(got) != 1 || got[0].ID != "auth" || got[0].Issuer != "https://id.example" || got[0].SecretEnv != "NL_SECRET" {
			t.Fatalf("configured issuer or secret reference corrupted during migration: %+v %v", got, err)
		}
	}
}
func TestRejectUnsafeProviderConfigurationMigration(t *testing.T) {
	cases := []string{
		`{"schemaVersion":3,"providers":[{"id":"a"}]}`,
		`{"schemaVersion":1,"providers":[{"id":"a"}]}`,
		`{"schemaVersion":2,"configs":[{"id":"a"}]}`,
		`{"schemaVersion":2,"providers":[{"id":"a"}],"configs":[{"id":"b"}]}`,
		`{"schemaVersion":2,"providers":[]}`,
		`{"schemaVersion":2,"providers":[{"id":"a","unexpected":"value"}]}`,
		`{"schemaVersion":2,"providers":[{"id":"a"}]} garbage`,
		`null`, `[]`,
	}
	for _, input := range cases {
		if _, err := configmigration.Decode[provider]([]byte(input)); err == nil {
			t.Errorf("invalid configured migration accepted: %s", input)
		}
	}
	if configmigration.CurrentSchemaVersion != 2 {
		t.Fatal("schema was silently changed")
	}
}
func TestMigrationErrorsIncludeSecretValues(t *testing.T) {
	secret := "super-secret-password-value"
	raw := `{"schemaVersion":99,"providers":[{"id":"a","secretEnv":"` + secret + `"}]}`
	_, err := configmigration.Decode[provider]([]byte(raw))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("config error exposed a secret: %v", err)
	}
}
