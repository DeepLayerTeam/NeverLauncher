package javaauthconnector

import (
	"encoding/json"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
	"testing"
	"time"
)

func TestJavaConfig0485(t *testing.T) {
	valid := Config{ID: "company", ExtensionID: "company.identity", DisplayName: "Company Identity"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{
		{ID: "local", ExtensionID: "company.identity", DisplayName: "Override"},
		{ID: "company", ExtensionID: "../escape", DisplayName: "Invalid"},
		{ID: "company", ExtensionID: "company.identity", DisplayName: ""},
	} {
		if cfg.Validate() == nil {
			t.Errorf("accepted unsafe config %+v", cfg)
		}
	}
}
func TestJavaIdentityProof0485(t *testing.T) {
	makeJSON := func(subject string, expiry int64) json.RawMessage {
		result, _ := json.Marshal(map[string]any{
			"identity":    map[string]any{"issuer": "https://id.example", "subject": subject, "email": "user@example.org"},
			"authMethods": []string{"pwd"}, "providerToken": "provider-session", "expiresAt": expiry,
		})
		return result
	}
	proof, err := decodeProof(makeJSON("stable-identity", time.Now().Add(time.Hour).Unix()))
	if err != nil || proof.Identity.Subject != "stable-identity" || proof.ProviderToken != "provider-session" {
		t.Fatalf("valid live proof rejected %+v %v", proof, err)
	}
	if _, err = decodeProof(makeJSON("", time.Now().Add(time.Hour).Unix())); authconnector.CodeOf(err) != authconnector.ErrMisconfigured {
		t.Fatalf("empty subject accepted %v", err)
	}
	if _, err = decodeProof(makeJSON("stable-identity", time.Now().Add(-time.Hour).Unix())); authconnector.CodeOf(err) != authconnector.ErrInvalidCredentials {
		t.Fatalf("expired token accepted %v", err)
	}
	if _, err = decodeProof(json.RawMessage(`{"identity":{"issuer":"issuer","subject":"x"},"authMethods":[]}`)); authconnector.CodeOf(err) != authconnector.ErrMisconfigured {
		t.Fatalf("no authentication method accepted %v", err)
	}
	if _, err = decodeProof(json.RawMessage(`null`)); authconnector.CodeOf(err) != authconnector.ErrMisconfigured {
		t.Fatalf("missing proof accepted %v", err)
	}
}
