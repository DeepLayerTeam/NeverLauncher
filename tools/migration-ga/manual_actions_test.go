package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManualWorklistDerivedFromReport0450(t *testing.T) {
	r := sampleReport(t, testHash)
	r.Items = []Item{{Kind: "module", Source: "old-module.jar", Status: "manual", Reason: "requires source port"}}
	r.Counts["manual"] = 1
	r.ReportSHA256 = ""
	raw, _ := json.Marshal(r)
	r.ReportSHA256 = hash(raw)
	p := Plan{RunID: r.RunID, ProjectID: r.ProjectID, TargetReleaseSHA256: testHash}
	work, err := renderManualWorklist(p, r)
	if err != nil {
		t.Fatal(err)
	}
	content := string(work)
	for _, need := range []string{"old-module.jar", "requires source port", r.ReportSHA256, "[ ]", "Ограничения отката"} {
		if !strings.Contains(content, need) {
			t.Fatalf("Отсутствует %s", need)
		}
	}
	p.ProjectID = "other"
	if _, err := renderManualWorklist(p, r); err == nil {
		t.Fatal("wrong project accepted")
	}
}
