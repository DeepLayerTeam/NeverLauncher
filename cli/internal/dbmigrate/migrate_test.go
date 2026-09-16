package dbmigrate

import (
	"strings"
	"testing"
)

func TestMigrationApplyAndVerifyScriptsAreFailClosed(t *testing.T) {
	apply, err := BuildApplyScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"0012_device_trust_core_0121",
		"0013_hardware_bound_identities_0123",
		"database contains migrations unknown to this binary",
		"UPDATE schema_migrations SET checksum=",
		"pg_advisory_lock(718033100100)",
	} {
		if !strings.Contains(apply, required) {
			t.Fatalf("apply script missing %q", required)
		}
	}

	verify, err := BuildVerifyScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"unknown to this binary",
		"pending migration",
		"without sealed checksum",
		"checksum mismatch",
		"nl_expected_migrations",
	} {
		if !strings.Contains(verify, required) {
			t.Fatalf("verify script missing %q", required)
		}
	}
}
