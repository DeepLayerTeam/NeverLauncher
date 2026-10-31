package gravitrollback

import (
	gr "gitflic.ru/skif4er/launcher/services/api/internal/gravitrehearsal"
	"strings"
	"testing"
)

func fixture() (PlanInput, gr.Report) {
	h := strings.Repeat("a", 64)
	uuid := "12345678-1234-1234-1234-123456789abc"
	s := gr.Snapshot{WorldSHA256: h, Loader: "forge", OptionalPresetSHA256: h, Players: []gr.Player{{SourceID: "fileauth:1", UUID: uuid, InventorySHA256: h, PermissionsSHA256: h, Economy: "100", SkinSHA256: h}}}
	digest, _ := gr.SnapshotDigest(s)
	r := gr.Report{Format: gr.Format, RunID: "12345678-run", StageID: "1234567890123456", SourceInventorySHA256: h, SourceSnapshotSHA256: digest, TargetSnapshotSHA256: digest, Source: s, Target: s}
	for _, name := range gr.RequiredProbes {
		p := gr.Probe{Name: name, Passed: true, RunID: r.RunID, StageID: r.StageID, EvidenceSHA256: h}
		if name == "login" || name == "join" {
			p.UUID = uuid
		}
		r.Probes = append(r.Probes, p)
	}
	return PlanInput{ProfileID: "client", Channel: "stable", ExpectedRevision: 2, Current: s, EvidenceReference: "evidence/export-42", EvidenceSHA256: h}, r
}
func TestCompareRefusesPostSwitchWrites(t *testing.T) {
	p, r := fixture()
	ok, e := Compare(p, r, r.RunID)
	if e != nil || !ok.Ready || len(ok.Blockers) != 0 {
		t.Fatalf("clean: %+v %v", ok, e)
	}
	p.Current.Players = append([]gr.Player(nil), p.Current.Players...)
	p.Current.Players[0].Economy = "101"
	diff, e := Compare(p, r, r.RunID)
	if e != nil || diff.Ready || len(diff.Blockers) == 0 {
		t.Fatalf("changed economy accepted: %+v %v", diff, e)
	}
	p, r = fixture()
	p.Current.WorldSHA256 = strings.Repeat("b", 64)
	diff, e = Compare(p, r, r.RunID)
	if e != nil || diff.Ready {
		t.Fatalf("changed world accepted: %+v %v", diff, e)
	}
	p, r = fixture()
	p.Current.Players = append(p.Current.Players, p.Current.Players[0])
	if _, e = Compare(p, r, r.RunID); e == nil {
		t.Fatal("duplicate accepted")
	}
	p, r = fixture()
	p.EvidenceReference = "different/evidence"
	different, e := Compare(p, r, r.RunID)
	if e != nil || different.PlanSHA256 == ok.PlanSHA256 {
		t.Fatal("evidence must change plan hash")
	}
}
func TestCommitRequiresBothFences(t *testing.T) {
	c := CommitInput{ProfileID: "client", Channel: "stable", ExpectedRevision: 2, PlanSHA256: strings.Repeat("a", 64), CurrentEvidenceSHA256: strings.Repeat("a", 64)}
	if ValidateCommit(c) == nil {
		t.Fatal("unfenced commit accepted")
	}
	c.SourceWriterFenced = true
	c.NeverWriterFenced = true
	if e := ValidateCommit(c); e != nil {
		t.Fatal(e)
	}
}

func TestReconciledPostSwitchWrites03312(t *testing.T) {
	p, r := fixture()
	p.Current.Players = append([]gr.Player(nil), p.Current.Players...)
	p.Current.Players[0].Economy = "300"
	blocked, e := Compare(p, r, r.RunID)
	if e != nil || blocked.Ready {
		t.Fatalf("should require reconciliation: %+v %v", blocked, e)
	}
	source := p.Current
	source.Players = append([]gr.Player(nil), p.Current.Players...)
	p.ReconciledSource = &source
	p.ReconciliationEvidenceSHA256 = strings.Repeat("b", 64)
	result, e := Compare(p, r, r.RunID)
	if e != nil || !result.Ready || result.Mode != "reconciled" || result.ReconciledSourceSHA256 == "" {
		t.Fatalf("reconciled state rejected: %+v %v", result, e)
	}
	source.Players[0].InventorySHA256 = strings.Repeat("c", 64)
	result, e = Compare(p, r, r.RunID)
	if e != nil || result.Ready {
		t.Fatalf("differing source accepted: %+v %v", result, e)
	}
}
