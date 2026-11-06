package main

import (
	"strings"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/texturegravit"
)

func TestTextureApprovalGate0445(t *testing.T) {
	approved := strings.Repeat("a", 64)
	for _, invalid := range []string{"", "not-a-sha", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if isApprovedTexturePlan0445(invalid) {
			t.Fatalf("Ошибочно принят некорректный хеш утверждённого плана %q", invalid)
		}
	}
	if !isApprovedTexturePlan0445(approved) {
		t.Fatal("Корректный SHA-256 отклонён")
	}
	for _, tc := range []struct {
		status string
		ok     bool
	}{
		{"validated-dry-run", true},
		{"already-imported", true},
		{"quarantined", false},
		{"unmatched", false},
		{"blocked", false},
		{"skipped-existing", false},
	} {
		r := texturegravit.Report{Rows: []texturegravit.Record{{Status: tc.status}}, Counts: map[string]int{tc.status: 1}}
		if got := texturePreviewClean0445(r); got != tc.ok {
			t.Errorf("Статус %s: ожидалось %v, получено %v", tc.status, tc.ok, got)
		}
	}
	if texturePreviewClean0445(texturegravit.Report{Counts: map[string]int{}}) {
		t.Fatal("Ошибочно утверждена пустая пробная операция")
	}
}
