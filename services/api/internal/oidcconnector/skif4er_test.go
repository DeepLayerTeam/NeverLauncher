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
