package gravitreports

import (
	"strings"
	"testing"
)

const s64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func baseline() Report {
	return Report{RunID: "migration0001", ProjectID: "project", SourceSHA256: s64, InventorySHA256: s64,
		Items:      []Item{{Kind: "asset", Source: "b.png", Status: "transferred", SHA256: s64}, {Kind: "asset", Source: "a.png", Status: "manual", SHA256: s64}},
		Identities: []Identity{{Provider: "fileauth", SourceID: "42", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", TargetUserID: "u1", Status: "imported"}},
		Evidence:   []Evidence{}, Decisions: []Decision{{Sequence: 2, Kind: "source_inspected", Revision: 2}, {Sequence: 1, Kind: "created", Revision: 1}}}
}
func TestDigestStableAndTamper(t *testing.T) {
	a := baseline()
	stages := []string{"compatibility", "inventory", "identity", "authentication", "security", "content", "modules", "rehearsal", "cutover", "rollback"}
	for _, s := range stages {
		a.Evidence = append(a.Evidence, Evidence{Stage: s, State: "verified", SHA256: s64})
	}
	one, e := Finalize(a)
	if e != nil {
		t.Fatal(e)
	}
	if one.Status != "review_required" || one.Counts["transferred"] != 1 {
		t.Fatalf("bad report %+v", one)
	}
	if e = Verify(one); e != nil {
		t.Fatal(e)
	}
	b := baseline()
	for i := len(stages) - 1; i >= 0; i-- {
		b.Evidence = append(b.Evidence, Evidence{Stage: stages[i], State: "verified", SHA256: s64})
	}
	two, e := Finalize(b)
	if e != nil || two.ReportSHA256 != one.ReportSHA256 {
		t.Fatal("nondeterministic sorted evidence", e)
	}
	one.Identities[0].TargetUserID = "tampered"
	if Verify(one) == nil {
		t.Fatal("tampering accepted")
	}
}
func TestMissingAndBlockedCannotPass(t *testing.T) {
	a := baseline()
	r, e := Finalize(a)
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != "blocked" || len(r.Blockers) != 10 {
		t.Fatal(r.Blockers)
	}
	a.Items = append(a.Items, Item{Kind: "module", Source: "unknown.jar", Status: "blocked", SHA256: s64})
	a.Identities = append(a.Identities, Identity{Provider: "sql", SourceID: "43", UUID: a.Identities[0].UUID, TargetUserID: "u2", Status: "matched"})
	r, e = Finalize(a)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(r.Blockers, "/"), "collision") {
		t.Fatal(r.Blockers)
	}
}
func TestDuplicateInvalidEvidence(t *testing.T) {
	a := baseline()
	a.Evidence = []Evidence{{Stage: "auth", State: "verified"}, {Stage: "auth", State: "verified"}}
	if _, e := Finalize(a); e == nil {
		t.Fatal("duplicate evidence accepted")
	}
	a = baseline()
	a.Items[0].SHA256 = "spoof"
	if _, e := Finalize(a); e == nil {
		t.Fatal("invalid hash accepted")
	}
}

func TestManualCutoverCannotBeReviewed0340(t *testing.T) {
	a := baseline()
	for _, stage := range []string{"compatibility", "inventory", "identity", "authentication", "security", "content", "modules", "rehearsal", "cutover", "rollback"} {
		state := "verified"
		if stage == "cutover" {
			state = "manual"
		}
		a.Evidence = append(a.Evidence, Evidence{Stage: stage, State: state})
	}
	r, e := Finalize(a)
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != "blocked" || !strings.Contains(strings.Join(r.Blockers, ";"), "cutover: required stage not verified") {
		t.Fatalf("unsafe RC review: %+v", r)
	}
	a.Evidence[len(a.Evidence)-2].State = "verified"
	a.Evidence = append(a.Evidence, Evidence{Stage: "cutover_scope:default/stable", State: "manual", Details: "staged"})
	r, e = Finalize(a)
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != "blocked" {
		t.Fatal("staged channel passed review")
	}
}
func TestUnknownEvidenceStateBlocks0340(t *testing.T) {
	a := baseline()
	a.Evidence = []Evidence{{Stage: "cutover", State: "fully_compatible"}}
	if _, e := Finalize(a); e == nil {
		t.Fatal("unknown status accepted")
	}
}
