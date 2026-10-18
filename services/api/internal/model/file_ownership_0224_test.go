package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestFileOwnershipRules0224(t *testing.T) {
	m := Manifest{SchemaVersion: "2.0", Files: []ManifestFile{
		{Path: "mods/core.jar", Required: true, Ownership: "required", SHA256: strings.Repeat("a", 64), URL: "https://example.test/core.jar"},
		{Path: "mods/optional.jar", Ownership: "optional", SHA256: strings.Repeat("b", 64), URL: "https://example.test/optional.jar"},
		{Path: "config/client.toml", Ownership: "user-owned"},
	}, FileRules: []FileRule{
		{Pattern: "mods/**", Action: "include", Ownership: "managed"},
		{Pattern: "config/**", Action: "exclude", Ownership: "user-owned"},
	}}
	if err := ValidateFileOwnership0224(m); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if err := ValidatePublishFileOwnership0224(m); err != nil {
		t.Fatalf("valid publish rejected: %v", err)
	}
	cases := map[string]func(*Manifest){
		"saves overwritten":         func(m *Manifest) { m.Files[0].Path = "saves/world/level.dat" },
		"resource pack overwritten": func(m *Manifest) { m.Files[0].Path = "resourcepacks/custom.zip" },
		"settings overwritten":      func(m *Manifest) { m.Files[0].Path = "options.txt" },
		"symlink-like path":         func(m *Manifest) { m.Files[0].Path = "mods/../saves/data" },
		"duplicate":                 func(m *Manifest) { m.Files[1].Path = "mods/CORE.jar" },
		"required owner mismatch":   func(m *Manifest) { m.Files[0].Ownership = "optional" },
		"user-owned required":       func(m *Manifest) { m.Files[2].Required = true },
		"conflicting exclude":       func(m *Manifest) { m.FileRules[0].Action = "exclude"; m.FileRules[0].Ownership = "user-owned" },
		"overlapping rules": func(m *Manifest) {
			m.FileRules = append(m.FileRules, FileRule{Pattern: "mods/extra/**", Action: "include", Ownership: "managed"})
		},
		"protected include": func(m *Manifest) {
			m.FileRules[1] = FileRule{Pattern: "saves/**", Action: "include", Ownership: "managed"}
		},
		"unknown action":   func(m *Manifest) { m.FileRules[0].Action = "ignore" },
		"bad glob":         func(m *Manifest) { m.FileRules[0].Pattern = "mods/*/special" },
		"verify user data": func(m *Manifest) { m.FileRules[1].Action = "verify" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := m
			c.Files = append([]ManifestFile(nil), m.Files...)
			c.FileRules = append([]FileRule(nil), m.FileRules...)
			mutate(&c)
			if err := ValidateFileOwnership0224(c); err == nil {
				t.Fatalf("unsafe rule accepted: %+v", c)
			}
		})
	}
	m.Files[0].SHA256 = ""
	if err := ValidateFileOwnership0224(m); err != nil {
		t.Fatal("draft must be editable", err)
	}
	if err := ValidatePublishFileOwnership0224(m); err == nil {
		t.Fatal("incomplete content published")
	}
}

func TestFileOwnershipSigningCompatibility0224(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v1 := Manifest{SchemaVersion: "1.0", Files: []ManifestFile{{Path: "mods/legacy.jar", Required: true}}}
	v1Raw, _ := json.Marshal(v1)
	if strings.Contains(string(v1Raw), "fileRules") || strings.Contains(string(v1Raw), "ownership") {
		t.Fatal("v1 payload changed")
	}
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), v1Raw, ed25519.Sign(private, v1Raw)) {
		t.Fatal("v1 broke")
	}
	v2 := Manifest{SchemaVersion: "2.0", Files: []ManifestFile{{Path: "mods/a.jar", Required: true, Ownership: "required"}}, FileRules: []FileRule{{Pattern: "mods/**", Action: "include", Ownership: "managed"}}}
	b, _ := json.Marshal(v2)
	sig := ed25519.Sign(private, b)
	v2.FileRules[0].Action = "exclude"
	tampered, _ := json.Marshal(v2)
	if ed25519.Verify(private.Public().(ed25519.PublicKey), tampered, sig) {
		t.Fatal("signed policy tampering accepted")
	}
}
