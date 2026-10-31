package main

import (
	"strings"
	"testing"
)

func TestLoaderGASupport0180ExactCertifiedSurface(t *testing.T) {
	cases := []struct {
		loader, minecraft string
		java              int
		legacy            bool
	}{
		{"fabric", "1.14", 8, false},
		{"fabric", "26.3", 25, false},
		{"quilt", "1.21.11", 21, false},
		{"forge", "1.7.10", 8, true},
		{"forge", "1.12.2", 8, true},
		{"forge", "1.13.2", 8, false},
		{"forge", "26.3", 25, false},
		{"neoforge", "1.20.1", 17, false},
		{"neoforge", "26.2", 25, false},
	}
	for _, tc := range cases {
		entry, ok := loaderGASupport0180(tc.loader, tc.minecraft)
		if !ok || entry.JavaMajor != tc.java || entry.Legacy != tc.legacy {
			t.Fatalf("%s/%s support=%+v ok=%v, want java=%d legacy=%v", tc.loader, tc.minecraft, entry, ok, tc.java, tc.legacy)
		}
	}
	for _, tc := range [][2]string{{"fabric", "1.13.2"}, {"quilt", "1.13.2"}, {"forge", "1.12.1"}, {"forge", "1.20.5"}, {"neoforge", "1.20"}, {"neoforge", "26.3"}} {
		if _, ok := loaderGASupport0180(tc[0], tc[1]); ok {
			t.Fatalf("uncertified combination must be rejected by GA support surface: %s/%s", tc[0], tc[1])
		}
	}
	if err := validateLoaderGASupportPolicy0180(); err != nil {
		t.Fatal(err)
	}
	if len(loaderGASupportEntries0180()) != 163 {
		t.Fatalf("GA support entries=%d want=163", len(loaderGASupportEntries0180()))
	}
	if len(loaderGASupportSHA2560180()) != 64 {
		t.Fatalf("invalid GA support digest %q", loaderGASupportSHA2560180())
	}
}

func TestLoaderGASupport0180RejectsJavaDrift(t *testing.T) {
	if _, err := enforceLoaderGASupport0180("forge", "1.7.10", 17); err == nil || !strings.Contains(err.Error(), "requires Java 8") {
		t.Fatalf("wrong Java must fail closed, got %v", err)
	}
	if _, err := enforceLoaderGASupport0180("neoforge", "26.3", 25); err == nil || !strings.Contains(err.Error(), "outside the certified GA support surface") {
		t.Fatalf("uncertified Minecraft line must fail closed, got %v", err)
	}
}

func TestLoaderGA0180ProductionParsersEnableRuntimeGuard(t *testing.T) {
	meta, err := parseLoaderMaterializeOptions("fabric", []string{"--minecraft", "1.21.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !meta.EnforceGASupport {
		t.Fatal("Fabric production parser must enable GA support guard")
	}
	forge, err := parseForgeMaterializeOptions("forge", []string{"--minecraft", "1.12.2"})
	if err != nil {
		t.Fatal(err)
	}
	if !forge.EnforceGASupport {
		t.Fatal("Forge production parser must enable GA support guard")
	}
}

func TestLoaderGA0180ProductionParsersRejectUnsupportedConcreteVersionBeforeInstall(t *testing.T) {
	old := version
	version = "0.18.0"
	defer func() { version = old }()
	if _, err := parseLoaderMaterializeOptions("fabric", []string{"--minecraft", "1.13.2"}); err == nil {
		t.Fatal("Fabric GA parser must reject unsupported concrete version before upstream access")
	}
	if _, err := parseForgeMaterializeOptions("forge", []string{"--minecraft", "1.20.5"}); err == nil {
		t.Fatal("Forge GA parser must reject uncertified gap before installer access")
	}
	if _, err := parseForgeMaterializeOptions("neoforge", []string{"--minecraft", "26.3"}); err == nil {
		t.Fatal("NeoForge GA parser must reject uncertified future line before installer access")
	}
}
