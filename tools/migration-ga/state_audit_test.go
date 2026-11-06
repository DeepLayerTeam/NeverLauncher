package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStateAudit0450() StateAudit {
	return StateAudit{Format: stateAuditFormat, Matched: true, SourceWorldSHA256: testHash, TargetWorldSHA256: testHash, SourcePluginSHA256: testHash, TargetPluginSHA256: testHash, SourceUUIDs: []string{testUUID}, TargetUUIDs: []string{testUUID}, WorldFiles: 1, PluginFiles: 1, Excluded: []string{}}
}
func stateFixture0450(t *testing.T, root string) {
	t.Helper()
	for _, name := range []string{"world/region", "plugins/config"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("data-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "player-uuids.txt"), []byte(testUUID+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestAuditStateReadsRealFiles0450(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "source"), filepath.Join(root, "target")
	for _, p := range []string{source, target} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		stateFixture0450(t, p)
	}
	a, err := auditState(source, target)
	if err != nil || !a.Matched || a.WorldFiles != 1 || a.PluginFiles != 1 {
		t.Fatalf("Ожидалось совпадение реальных данных: %+v %v", a, err)
	}
	evidence := filepath.Join(root, "audit.json")
	if err := executeStateAudit(source, target, evidence); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var decoded StateAudit
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	probe := Probe{SourceUUIDs: decoded.SourceUUIDs, TargetUUIDs: decoded.TargetUUIDs, SourceWorldSHA256: decoded.SourceWorldSHA256, TargetWorldSHA256: decoded.TargetWorldSHA256, SourcePluginSHA256: decoded.SourcePluginSHA256, TargetPluginSHA256: decoded.TargetPluginSHA256}
	if err := validateStateAuditEvidence(b, probe); err != nil {
		t.Fatal(err)
	}
	probe.SourceWorldSHA256 = testHash
	if err := validateStateAuditEvidence(b, probe); err == nil {
		t.Fatal("unbound state hash accepted")
	}
	if err := os.WriteFile(filepath.Join(target, "world/region"), []byte("changed-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := auditState(source, target); err == nil {
		t.Fatal("changed player world accepted")
	}
	if err := os.WriteFile(filepath.Join(target, "world/region"), []byte("data-world/region"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "player-uuids.txt"), []byte(strings.Repeat("b", 8)+testUUID[8:]+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := auditState(source, target); err == nil {
		t.Fatal("different identity accepted")
	}
}
func TestAuditStateRejectsSymlinkAndEmpty0450(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "s"), filepath.Join(root, "t")
	for _, p := range []string{source, target} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		stateFixture0450(t, p)
	}
	if err := os.Remove(filepath.Join(target, "world/region")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(source, "world/region"), filepath.Join(target, "world/region")); err != nil {
		t.Fatal(err)
	}
	if _, err := auditState(source, target); err == nil {
		t.Fatal("symlink member accepted")
	}
	if _, err := auditState(source, source); err == nil {
		t.Fatal("same snapshot accepted")
	}
}

func TestSnapshotMustRemainUnchangedAfterAudit0450(t *testing.T) {
	root := t.TempDir()
	src, tgt := filepath.Join(root, "source"), filepath.Join(root, "target")
	for _, p := range []string{src, tgt} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		stateFixture0450(t, p)
	}
	actual, err := auditState(src, tgt)
	if err != nil {
		t.Fatal(err)
	}
	evidenceDir := filepath.Join(root, "evidence")
	if err := os.Mkdir(evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(actual)
	if err := os.WriteFile(filepath.Join(evidenceDir, "uuid-world-plugin-data.evidence"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	p := Plan{SnapshotSourceDir: src, SnapshotTargetDir: tgt}
	if err := ensureSnapshotStillMatches(p, evidenceDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tgt, "plugins/config"), []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSnapshotStillMatches(p, evidenceDir); err == nil {
		t.Fatal("late plugin data mutation accepted")
	}
}

func TestEmptyPluginTreesCanBeAudited0450(t *testing.T) {
	root := t.TempDir()
	src, tgt := filepath.Join(root, "s"), filepath.Join(root, "t")
	for _, p := range []string{src, tgt} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		stateFixture0450(t, p)
		if err := os.Remove(filepath.Join(p, "plugins/config")); err != nil {
			t.Fatal(err)
		}
	}
	a, err := auditState(src, tgt)
	if err != nil || !a.Matched || a.PluginFiles != 0 {
		t.Fatalf("Проект Vanilla без плагина был отклонён: %+v, %v", a, err)
	}
}
