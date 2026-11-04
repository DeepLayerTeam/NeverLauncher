package gravitplan

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
)

const testClient0442 = `{"title":"Demo","info":"Server","version":"1.20.4","mainClass":"net.minecraft.client.main.Main","recommendJavaVersion":17,"minJavaVersion":17,"maxJavaVersion":999,"classLoaderConfig":"SYSTEM_ARGS","classPath":["minecraft.jar"],"update":["minecraft.jar"],"updateVerify":["minecraft.jar"],"updateExclusions":["saves","screenshots","resourcepacks","options.txt"],"settings":{"ram":4096,"autoEnter":false,"fullScreen":false},"limited":false}`

func preview0442(t *testing.T) (Plan, inv.Inventory, gd.Report, gm.Report, gc.Plan, Destination) {
	t.Helper()
	files := map[string]string{"profiles/demo.json": testClient0442, "updates/demo/minecraft.jar": "test game file", "updates/demo/saves/world/level.dat": "player world", "assets/indexes/index.json": "{}", "profiles/another.json": testClient0442, "skins/user.png": "skin bytes", "keys/private.key": "SECRET_KEY_NOT_TO_TRANSFER", "sql-export/users.csv": "id,username,uuid\n7,Demo,11111111-2222-4333-8444-555555555555\n"}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, name := range []string{"profiles/demo.json", "profiles/another.json", "updates/demo/minecraft.jar", "updates/demo/saves/world/level.dat", "assets/indexes/index.json", "skins/user.png", "keys/private.key", "sql-export/users.csv"} {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(files[name])); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	raw := buf.Bytes()
	h := sha256.Sum256(raw)
	sum := hex.EncodeToString(h[:])
	vi, e := inv.Inspect(context.Background(), bytes.NewReader(raw), int64(len(raw)), sum)
	if e != nil {
		t.Fatal(e)
	}
	compat, e := gd.AssessReader(context.Background(), bytes.NewReader(raw), int64(len(raw)), sum, "")
	if e != nil {
		t.Fatal(e)
	}
	tmp, e := os.CreateTemp(t.TempDir(), "source-*.zip")
	if e != nil {
		t.Fatal(e)
	}
	defer tmp.Close()
	if _, e = tmp.Write(raw); e != nil {
		t.Fatal(e)
	}
	mods, e := gm.Analyze(context.Background(), tmp, int64(len(raw)), vi)
	if e != nil {
		t.Fatal(e)
	}
	cp, e := gc.Prepare(context.Background(), bytes.NewReader(raw), int64(len(raw)), vi, "profiles/demo.json", "project", "demo", "Demo", "vanilla")
	if e != nil {
		t.Fatal(e)
	}
	dest := Destination{ProfilePath: "profiles/demo.json", ProfileID: "demo", ProfileName: "Demo", Loader: "vanilla", Channel: "stable", Version: "migration-1"}
	plan, e := Build("run", "project", strings.Repeat("a", 64), dest, vi, compat, mods, cp, false, IdentityPreview{SourceAccounts: 1, State: "review_required"})
	if e != nil {
		t.Fatal(e)
	}
	return plan, vi, compat, mods, cp, dest
}
func TestPlanDeterminismAndNoSecret0442(t *testing.T) {
	p, vi, compat, mods, cp, d := preview0442(t)
	if e := Verify(p); e != nil {
		t.Fatal(e)
	}
	again, e := Build("run", "project", p.TargetSHA256, d, vi, compat, mods, cp, false, IdentityPreview{SourceAccounts: 1, State: "review_required"})
	if e != nil {
		t.Fatal(e)
	}
	if p.PlanSHA256 != again.PlanSHA256 {
		t.Fatalf("nondeterministic plan: %s != %s", p.PlanSHA256, again.PlanSHA256)
	}
	if p.TransferBytes == 0 || p.Counts["manual"] == 0 || p.Counts["excluded"] != 2 {
		t.Fatalf("missing real transfer/manual/key exclusion: %+v", p.Counts)
	}
	if p.Status == "blocked" && len(p.Blockers) == 0 {
		t.Fatal("blocked plan lacks reason")
	}
	for _, item := range p.Items {
		if item.Kind == "key" && (item.Status != "excluded" || item.Target != "") {
			t.Fatal("legacy key scheduled for transfer")
		}
	}
	// План не должен раскрывать содержимое файлов или старые секреты.
	if strings.Contains(strings.Join(p.Blockers, "|"), "SECRET_KEY_NOT_TO_TRANSFER") {
		t.Fatal("source contents leaked")
	}
	tampered := p
	tampered.TargetSHA256 = strings.Repeat("b", 64)
	if Verify(tampered) == nil {
		t.Fatal("tampered plan accepted")
	}
}
func TestPlanBlocksDestinationAndSourceChanges0442(t *testing.T) {
	p, vi, compat, mods, cp, d := preview0442(t)
	changed, e := Build("run", "project", p.TargetSHA256, d, vi, compat, mods, cp, true, IdentityPreview{SourceAccounts: 1, State: "review_required"})
	if e != nil || changed.Status != "blocked" || len(changed.Blockers) == 0 {
		t.Fatalf("destination collision not blocked: %+v, %v", changed, e)
	}
	vi.SourceSHA256 = strings.Repeat("f", 64)
	if _, e = Build("run", "project", p.TargetSHA256, d, vi, compat, mods, cp, false, IdentityPreview{SourceAccounts: 1, State: "review_required"}); e == nil {
		t.Fatal("mismatched source accepted")
	}
}

func TestMissingIdentityAndChangedDestination0442(t *testing.T) {
	p, vi, compat, mods, cp, d := preview0442(t)
	missing, e := Build("run", "project", p.TargetSHA256, d, vi, compat, mods, cp, false, IdentityPreview{State: "blocked", Reason: "missing source identity export"})
	if e != nil || missing.Status != "blocked" || len(missing.Blockers) == 0 {
		t.Fatalf("missing identities not blocked %+v %v", missing, e)
	}
	modified := d
	modified.Channel = "beta"
	other, e := Build("run", "project", p.TargetSHA256, modified, vi, compat, mods, cp, false, IdentityPreview{SourceAccounts: 1, State: "review_required"})
	if e != nil || other.PlanSHA256 == p.PlanSHA256 {
		t.Fatalf("changed destination accepted old digest: %v", e)
	}
}

// Файл, принадлежащий клиенту, в проверенном ZIP явно исключается из
// одобренного плана; он не должен случайно стать источником будущей
// автоматической копии.
func TestPlanExcludesPlayerFiles0443(t *testing.T) {
	p, _, _, _, content, _ := preview0442(t)
	if len(content.SkippedFiles) != 1 {
		t.Fatalf("missing source exclusion: %+v", content.SkippedFiles)
	}
	seen := false
	for _, item := range p.Items {
		if item.Source != "updates/demo/saves/world/level.dat" {
			continue
		}
		seen = true
		if item.Status != "excluded" || item.Target != "" || item.Reason == "" {
			t.Fatalf("unsafe operation on player-owned file: %+v", item)
		}
	}
	if !seen {
		t.Fatal("player file absent from operator plan")
	}
	if err := Verify(p); err != nil {
		t.Fatal(err)
	}
}
