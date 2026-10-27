package gravitrehearsal

import (
	"strings"
	"testing"
)

func TestEvaluate03310(t *testing.T) {
	h := strings.Repeat("a", 64)
	p := Player{SourceID: "42", UUID: "12345678-1234-1234-1234-123456789abc", InventorySHA256: h, PermissionsSHA256: h, Economy: "100.00", SkinSHA256: h, Admin: true}
	ss := Snapshot{WorldSHA256: h, Loader: "forge", OptionalPresetSHA256: h, Players: []Player{p}}
	s, _ := SnapshotDigest(ss)
	r := Report{Format: Format, RunID: "1234567890abcdef", StageID: "abcdef1234567890", SourceInventorySHA256: h, SourceSnapshotSHA256: s, TargetSnapshotSHA256: s, Source: ss, Target: ss}
	for _, name := range RequiredProbes {
		r.Probes = append(r.Probes, Probe{Name: name, Passed: true, RunID: r.RunID, StageID: r.StageID, UUID: p.UUID, EvidenceSHA256: h})
	}
	v, e := Evaluate(r)
	if e != nil || !v.Ready || len(v.Blockers) != 0 || v.CutoverAllowed {
		t.Fatalf("valid: %+v %v", v, e)
	}
	if e = CompareReady(v); e != nil {
		t.Fatal(e)
	}
	v.Probes[0].Passed = false
	failed, e := Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("failed test passed")
	}
	if e = CompareReady(v); e == nil {
		t.Fatal("forged readiness accepted")
	}
	v = r
	v.Target.Players = append([]Player(nil), v.Target.Players...)
	v.Target.Players[0].Economy = "0"
	d, _ := SnapshotDigest(v.Target)
	v.TargetSnapshotSHA256 = d
	failed, e = Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("economy regression passed")
	}
	v = r
	v.Probes = v.Probes[:len(v.Probes)-1]
	failed, e = Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("missing admin probe passed")
	}
	v = r
	v.Probes = append([]Probe(nil), v.Probes...)
	v.Probes[2].UUID = "not-existing"
	failed, e = Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("wrong join UUID passed")
	}
	v = r
	v.TargetSnapshotSHA256 = h
	if _, e = Evaluate(v); e == nil {
		t.Fatal("forged snapshot digest accepted")
	}
}
