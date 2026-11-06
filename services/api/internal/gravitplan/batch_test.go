package gravitplan

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	gc "gitflic.ru/skif4er/launcher/services/api/internal/gravitcontent"
	gd "gitflic.ru/skif4er/launcher/services/api/internal/gravitdetector"
	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	gm "gitflic.ru/skif4er/launcher/services/api/internal/gravitmodules"
)

func fixturesBatch0492(t *testing.T, sameDir bool) ([]byte, inv.Inventory, gd.Report, gm.Report) {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	profileA := strings.Replace(testClient0442, `"title":"Demo"`, `"title":"Demo","dir":"alpha"`, 1)
	profileB := strings.Replace(testClient0442, `"title":"Demo"`, `"title":"Beta","dir":"beta"`, 1)
	if sameDir {
		profileB = strings.Replace(profileB, `"dir":"beta"`, `"dir":"alpha"`, 1)
	}
	files := map[string]string{"profiles/alpha.json": profileA, "profiles/beta.json": profileB, "updates/alpha/minecraft.jar": "alpha", "updates/beta/minecraft.jar": "beta", "sql-export/users.csv": "id,username,uuid\n1,demo,11111111-2222-4333-8444-555555555555\n"}
	for _, k := range []string{"profiles/alpha.json", "profiles/beta.json", "updates/alpha/minecraft.jar", "updates/beta/minecraft.jar", "sql-export/users.csv"} {
		f, e := w.Create(k)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(files[k])); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	src := b.Bytes()
	sum := sha256.Sum256(src)
	h := hex.EncodeToString(sum[:])
	vi, e := inv.Inspect(context.Background(), bytes.NewReader(src), int64(len(src)), h)
	if e != nil {
		t.Fatal(e)
	}
	comp, e := gd.AssessReader(context.Background(), bytes.NewReader(src), int64(len(src)), h, "")
	if e != nil {
		t.Fatal(e)
	}
	tmp, e := os.CreateTemp(t.TempDir(), "gravit-*.zip")
	if e != nil {
		t.Fatal(e)
	}
	defer tmp.Close()
	if _, e = tmp.Write(src); e != nil {
		t.Fatal(e)
	}
	mods, e := gm.Analyze(context.Background(), tmp, int64(len(src)), vi)
	if e != nil {
		t.Fatal(e)
	}
	return src, vi, comp, mods
}
func destinationsBatch0492() []Destination {
	return []Destination{
		{ProfilePath: "profiles/alpha.json", ProfileID: "alpha", ProfileName: "Alpha", Loader: "vanilla", Channel: "stable", Version: "1.20.4"},
		{ProfilePath: "profiles/beta.json", ProfileID: "beta", ProfileName: "Beta", Loader: "vanilla", Channel: "stable", Version: "1.20.4"},
	}
}
func makeBatch0492(t *testing.T, src []byte, v inv.Inventory, c gd.Report, m gm.Report, d []Destination, existing map[string]bool) (Batch0492, error) {
	t.Helper()
	return BuildBatch0492(context.Background(), bytes.NewReader(src), int64(len(src)), "run", "project", strings.Repeat("a", 64), existing, v, c, m, IdentityPreview{State: "review_required", SourceAccounts: 1}, d)
}
func TestMultiProfilePreviewAndDeterminism0492(t *testing.T) {
	source, v, c, m := fixturesBatch0492(t, false)
	one, err := makeBatch0492(t, source, v, c, m, destinationsBatch0492(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if one.ProfileCount != 2 || one.Format != BatchFormat0492 || one.Profiles[0].FileCount == 0 || one.Profiles[1].FileCount == 0 || one.Profiles[0].SourceDirectory != "alpha" || one.Profiles[1].SourceDirectory != "beta" {
		t.Fatalf("not converted: %+v", one)
	}
	if err = VerifyBatch0492(one); err != nil {
		t.Fatal(err)
	}
	reversed := destinationsBatch0492()
	reversed[0], reversed[1] = reversed[1], reversed[0]
	two, err := makeBatch0492(t, source, v, c, m, reversed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if two.BatchSHA256 != one.BatchSHA256 {
		t.Fatal("Изменение порядка профилей привело к недетерминированному результату")
	}
	tampered := one
	tampered.TargetSHA256 = strings.Repeat("b", 64)
	if VerifyBatch0492(tampered) == nil {
		t.Fatal("Подменённый отчёт ошибочно принят")
	}
	encoded, err := json.Marshal(one)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("11111111-2222-4333-8444-555555555555")) {
		t.Fatal("Идентификационные данные попали в групповой отчёт")
	}
	// Формирование отчёта никогда не записывает новые целевые данные или выпуск.
	_ = gc.WorkspaceID("run", "profiles/alpha.json")
}
func TestMultiProfileFailClosed0492(t *testing.T) {
	src, v, c, m := fixturesBatch0492(t, false)
	missing := destinationsBatch0492()[:1]
	if _, e := makeBatch0492(t, src, v, c, m, missing, nil); e == nil {
		t.Fatal("Принят профиль без сопоставления")
	}
	duplicate := destinationsBatch0492()
	duplicate[1].ProfileID = "ALPHA"
	if _, e := makeBatch0492(t, src, v, c, m, duplicate, nil); e == nil {
		t.Fatal("Повторяющийся идентификатор цели ошибочно принят")
	}
	invalid := destinationsBatch0492()
	invalid[1].ProfilePath = "profiles/not-here.json"
	if _, e := makeBatch0492(t, src, v, c, m, invalid, nil); e == nil {
		t.Fatal("Неизвестный путь к источнику ошибочно принят")
	}
	collision, e := makeBatch0492(t, src, v, c, m, destinationsBatch0492(), map[string]bool{"beta": true})
	if e != nil || collision.Status != "blocked" || collision.Profiles[1].Status != "blocked" {
		t.Fatalf("Не обнаружен конфликт цели: %+v %v", collision, e)
	}
	v.SourceSHA256 = strings.Repeat("f", 64)
	if _, e = makeBatch0492(t, src, v, c, m, destinationsBatch0492(), nil); e == nil {
		t.Fatal("Принят вымышленный хеш SHA")
	}
}
func TestMultiProfileOverlappingClientDirectories0492(t *testing.T) {
	src, v, c, m := fixturesBatch0492(t, true)
	report, e := makeBatch0492(t, src, v, c, m, destinationsBatch0492(), nil)
	if e != nil {
		t.Fatal(e)
	}
	if report.Status != "blocked" || report.Profiles[0].Status != "blocked" || report.Profiles[1].Status != "blocked" {
		t.Fatalf("Не обнаружено пересечение владения источником: %+v", report)
	}
	if VerifyBatch0492(report) != nil {
		t.Fatal("Проверка контрольной суммы заблокированного, но корректного отчёта завершилась ошибкой")
	}
}
