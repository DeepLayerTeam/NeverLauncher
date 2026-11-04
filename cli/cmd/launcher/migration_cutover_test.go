package main

import (
	"strings"
	"testing"
)

func TestMigrationCutover03311RejectsUnsafeTransportAndMissingConfirmation(t *testing.T) {
	tests := [][]string{
		{"cutover-stage", "--backend", "http://example.org", "--token", "test", "--run", "migration-xyz", "--confirm", "migration-xyz"},
		{"cutover-activate", "--backend", "https://example.org", "--token", "test", "--run", "migration-xyz", "--confirm", "wrong-id"},
		{"cutover-activate", "--backend", "https://example.org", "--token", "test", "--run", "migration-xyz", "--confirm", "migration-xyz", "--source-fenced", "false"},
		{"cutover-stage", "--backend", "http://127.0.0.1:12345", "--token", "test", "--run", "migration-xyz", "--confirm", "migration-xyz", "--head-revision", "invalid"},
	}
	for _, args := range tests {
		if err := handleMigrationCutover03311(args); err == nil {
			t.Fatalf("unsafe request accepted: %v", args)
		}
	}
}
func TestMigrationCutover03311RequiresBackend(t *testing.T) {
	e := handleMigrationCutover03311([]string{"cutover-list", "--run", "abc"})
	if e == nil || !strings.Contains(e.Error(), "--backend") {
		t.Fatalf("bad validation: %v", e)
	}
}
