package model

import (
	"strings"
	"testing"
)

func TestValidationDetailsRedactSecretsAndIdentifiers03412(t *testing.T) {
	cases := []string{
		`Authorization: Bearer ghp_secrettoken123`,
		`--accessToken secret-abc --username important-person --uuid 123e4567-e89b-12d3-a456-426614174000`,
		`-Dauth.password=verysecret`,
		`https://provider.example/join?access_token=ABC&code=ZXCV`,
		`{"access_token":"secret-json","password":"s3cret"}`,
		`player=123e4567-e89b-12d3-a456-426614174000 account=user@example.com`,
	}
	for _, raw := range cases {
		redacted := RedactValidationDetail03412(raw)
		for _, secret := range []string{"ghp_secrettoken123", "secret-abc", "important-person", "verysecret", "ABC", "ZXCV", "secret-json", "s3cret", "123e4567-e89b-12d3-a456-426614174000", "user@example.com"} {
			if strings.Contains(redacted, secret) {
				t.Errorf("secret leaked in %q: %q", raw, redacted)
			}
		}
	}
	digest := strings.Repeat("a", 64)
	if got := RedactValidationDetail03412("sha256=" + digest); got != "sha256="+digest {
		t.Fatalf("digest redacted: %s", got)
	}
}
