package repository

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeServerBridgeControlFailure(t *testing.T) {
	cases := []struct {
		name, input string
		length      int
	}{
		{"short unchanged", "already failed", len("already failed")},
		{"exactly 1024", strings.Repeat("a", 1024), 1024},
		{"oversized ASCII", strings.Repeat("z", 1100), 1024},
		{"UTF8 rune boundary", strings.Repeat("a", 1023) + "é" + "more", 1023},
		{"UTF8 complete boundary", strings.Repeat("a", 1022) + "é" + "more", 1024},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			normalized := normalizeServerBridgeControlFailure(tc.input)
			if len(normalized) != tc.length || !utf8.ValidString(normalized) {
				t.Fatalf("normalized bytes=%d valid=%v; want %d", len(normalized), utf8.ValidString(normalized), tc.length)
			}
			if normalized != normalizeServerBridgeControlFailure(normalized) {
				t.Fatal("idempotent normalization violated")
			}
		})
	}
}
