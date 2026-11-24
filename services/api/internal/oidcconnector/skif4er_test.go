package oidcconnector

import "testing"

func TestSkif4erRegistration(t *testing.T) {
	off, err := WithSkif4erID(nil, "")
	if err != nil || len(off) != 0 {
		t.Fatal("disabled provider registered")
	}
	cfgs, err := WithSkif4erID(nil, "neverlauncher-desktop")
	if err != nil || len(cfgs) != 1 {
		t.Fatal(err)
	}
	cfg, err := Normalize(cfgs[0])
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "https://id.skif4er.ru/realms/skif4er" || !cfg.RedirectAllowed("http://127.0.0.1:8765/callback") || cfg.RedirectAllowed("http://localhost:8765/callback") || !cfg.RequireVerifiedEmail || cfg.Provisioning.DefaultRole != "player" || cfg.ClientSecret != "" {
		t.Fatal("unsafe provider settings")
	}
	if _, err := WithSkif4erID(cfgs, "another"); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestSkif4erAdminRedirect110(t *testing.T) {
	const callback = "https://admin.example.test/auth/skif4er/callback"
	configs, err := WithSkif4erID(nil, "neverlauncher", callback)
	if err != nil || len(configs) != 1 {
		t.Fatal(err)
	}
	cfg, err := Normalize(configs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RedirectAllowed(callback) || !cfg.RedirectAllowed("http://127.0.0.1:8765/callback") || cfg.RedirectAllowed(callback+"?next=evil") || cfg.RedirectAllowed("https://other.example.test/auth/skif4er/callback") {
		t.Fatal("incorrect redirect allowlist")
	}
	for _, raw := range []string{"http://admin.example.test/auth/skif4er/callback", "https://*.example.test/auth/skif4er/callback", "https://admin.example.test/auth/skif4er/callback?x=1", "https://user@admin.example.test/auth/skif4er/callback", "https://admin.example.test/anything", "https://admin.example.test/auth/skif4er/callback#x"} {
		if _, err := WithSkif4erID(nil, "neverlauncher", raw); err == nil {
			t.Errorf("accepted unsafe callback %q", raw)
		}
	}
	if _, err := WithSkif4erID(nil, "", callback); err == nil {
		t.Fatal("callback enabled without client")
	}
}
