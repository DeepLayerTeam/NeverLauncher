package dbmigrate

import (
	"os"
	"strings"
	"testing"
)

func catalogChecksums(t *testing.T) map[string]string {
	t.Helper()
	ms, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string, len(ms))
	for _, m := range ms {
		out[m.Version] = m.Checksum
	}
	return out
}

func TestEvaluateAppliedSealedCatalog(t *testing.T) {
	applied := catalogChecksums(t)
	st, err := EvaluateApplied(applied)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Compatible || len(st.Pending) != 0 || len(st.Unknown) != 0 || len(st.Unverified) != 0 || st.Applied != st.Total {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Current != "0011_auth_federation_release_0120" {
		t.Fatalf("unexpected current migration %q", st.Current)
	}
}

func TestEvaluateAppliedDetectsPendingUnknownUnverifiedAndDrift(t *testing.T) {
	base := catalogChecksums(t)

	pending := make(map[string]string, len(base))
	for k, v := range base {
		if k != "0011_auth_federation_release_0120" {
			pending[k] = v
		}
	}
	st, err := EvaluateApplied(pending)
	if err != nil || !st.Compatible || len(st.Pending) != 1 {
		t.Fatalf("pending should be compatible but incomplete: status=%+v err=%v", st, err)
	}

	unknown := catalogChecksums(t)
	unknown["9999_future"] = "deadbeef"
	st, err = EvaluateApplied(unknown)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "unknown to this binary") {
		t.Fatalf("future migration was not rejected: status=%+v err=%v", st, err)
	}

	unverified := catalogChecksums(t)
	unverified["0009_minecraft_auth_compat_2_0119"] = ""
	st, err = EvaluateApplied(unverified)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "without sealed checksum") {
		t.Fatalf("unsealed checksum was not rejected: status=%+v err=%v", st, err)
	}

	drift := catalogChecksums(t)
	drift["0008_session_management_2_0118"] = strings.Repeat("0", 64)
	st, err = EvaluateApplied(drift)
	if err == nil || st.Compatible || !strings.Contains(err.Error(), "checksum migration") {
		t.Fatalf("checksum drift was not rejected: status=%+v err=%v", st, err)
	}
}

func TestApplyUsesSessionAdvisoryLock(t *testing.T) {
	src, err := os.ReadFile("migrate.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, required := range []string{"pg_advisory_lock(718033100100)", "pg_advisory_unlock(718033100100)", "validateExistingBeforeApply"} {
		if !strings.Contains(text, required) {
			t.Fatalf("migration apply missing serialized gate %q", required)
		}
	}
}
