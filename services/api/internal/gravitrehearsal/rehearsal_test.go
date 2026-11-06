package gravitrehearsal

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluate03310(t *testing.T) {
	h := strings.Repeat("a", 64)
	p := Player{SourceID: "42", UUID: "12345678-1234-1234-1234-123456789abc", InventorySHA256: h, PermissionsSHA256: h, Economy: "100.00", SkinSHA256: h, Admin: true}
	ss := Snapshot{WorldSHA256: h, Loader: "forge", OptionalPresetSHA256: h, Players: []Player{p}}
	s, _ := SnapshotDigest(ss)
	r := Report{Format: Format, RunID: "1234567890abcdef", StageID: "abcdef1234567890", SourceInventorySHA256: h, SourceSnapshotSHA256: s, TargetSnapshotSHA256: s, Source: ss, Target: ss}
	started := time.Now().UTC().Add(-10 * time.Second)
	r.LiveSession = &LiveSession{ClientSHA256: h, PlayerName: "Steve", PlayerUUID: p.UUID, BeforeSHA256: h, JoinedSHA256: h, StartedAt: started.Format(time.RFC3339Nano), JoinedAt: started.Add(3 * time.Second).Format(time.RFC3339Nano)}
	for _, name := range RequiredProbes {
		r.Probes = append(r.Probes, Probe{Name: name, Passed: true, RunID: r.RunID, StageID: r.StageID, UUID: p.UUID, EvidenceSHA256: h})
	}
	v, e := Evaluate(r)
	if e != nil || !v.Ready || len(v.Blockers) != 0 || v.CutoverAllowed {
		t.Fatalf("Корректность: %+v %v", v, e)
	}
	if e = CompareReady(v); e != nil {
		t.Fatal(e)
	}
	v.Probes[0].Passed = false
	failed, e := Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("Провален тест, который должен был завершиться отказом")
	}
	if e = CompareReady(v); e == nil {
		t.Fatal("Принята поддельная готовность")
	}
	v = r
	v.Target.Players = append([]Player(nil), v.Target.Players...)
	v.Target.Players[0].Economy = "0"
	d, _ := SnapshotDigest(v.Target)
	v.TargetSnapshotSHA256 = d
	failed, e = Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("Не обнаружена регрессия экономики")
	}
	v = r
	v.Probes = v.Probes[:len(v.Probes)-1]
	failed, e = Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("Пройдена проверка без административного запроса")
	}
	v = r
	v.Probes = append([]Probe(nil), v.Probes...)
	v.Probes[2].UUID = "not-existing"
	failed, e = Evaluate(v)
	if e != nil || failed.Ready {
		t.Fatal("Принят неверный UUID подключения")
	}
	v = r
	v.TargetSnapshotSHA256 = h
	if _, e = Evaluate(v); e == nil {
		t.Fatal("Принята поддельная контрольная сумма снимка")
	}
}

func TestEvaluateRequiresNativeLiveSession0447(t *testing.T) {
	h := strings.Repeat("a", 64)
	p := Player{SourceID: "fileauth:42", UUID: "12345678-1234-1234-1234-123456789abc", InventorySHA256: h, PermissionsSHA256: h, SkinSHA256: h, Economy: "1"}
	snap := Snapshot{WorldSHA256: h, Loader: "fabric", OptionalPresetSHA256: h, Players: []Player{p}}
	sum, _ := SnapshotDigest(snap)
	report := Report{Format: Format, RunID: "1234567890abcdef", StageID: "stage_1234567890abcdef", SourceInventorySHA256: h, SourceSnapshotSHA256: sum, TargetSnapshotSHA256: sum, Source: snap, Target: snap}
	for _, name := range RequiredProbes {
		report.Probes = append(report.Probes, Probe{Name: name, Passed: true, RunID: report.RunID, StageID: report.StageID, UUID: p.UUID, EvidenceSHA256: h})
	}
	older, e := Evaluate(report)
	if e != nil || older.Ready || len(older.Blockers) == 0 {
		t.Fatalf("Принят устаревший синтетический отчёт: %+v %v", older, e)
	}
	start := time.Now().UTC().Add(-10 * time.Second)
	report.LiveSession = &LiveSession{ClientSHA256: h, PlayerName: "Steve", PlayerUUID: p.UUID, BeforeSHA256: h, JoinedSHA256: h, StartedAt: start.Format(time.RFC3339Nano), JoinedAt: start.Add(3 * time.Second).Format(time.RFC3339Nano)}
	ready, e := Evaluate(report)
	if e != nil || !ready.Ready {
		t.Fatalf("Отчёт в корректном формате ошибочно отклонён: %+v %v", ready, e)
	}
	report.LiveSession.PlayerUUID = "76543210-1234-1234-1234-123456789abc"
	blocked, e := Evaluate(report)
	if e != nil || blocked.Ready {
		t.Fatalf("Принят неверный UUID реального сеанса: %+v %v", blocked, e)
	}
	report.LiveSession.PlayerUUID = p.UUID
	report.LiveSession.JoinedAt = report.LiveSession.StartedAt
	if _, e = Evaluate(report); e == nil {
		t.Fatal("Принята невозможная хронология реального сеанса")
	}
}
