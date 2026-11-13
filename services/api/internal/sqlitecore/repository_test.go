package sqlitecore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func openTest(t *testing.T) (*Repository, string) {
	t.Helper()
	dir := os.Getenv("LAUNCHER_SQLITE_TEST_ROOT")
	if dir == "" {
		dir = privateSQLiteTempDir(t)
	} else {
		dir = filepath.Join(dir, "sqlite-core-"+strings.ReplaceAll(t.Name(), "/", "-"))
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "core.db")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, e := Open(ctx, sqlitedurable.Options{Path: path})
	if e != nil && strings.Contains(e.Error(), "Неподдерживаемая файловая система SQLite") && os.Getenv("LAUNCHER_SQLITE_TEST_ROOT") == "" {
		t.Skipf("Требуется каталог на файловой системе ext4/xfs/btrfs: %v", e)
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r, path
}
func project(t *testing.T, r *Repository) {
	t.Helper()
	if _, e := r.SaveProject(context.Background(), model.Project{ID: "project", Name: "My project"}, "owner"); e != nil {
		t.Fatal(e)
	}
}
func profile(t *testing.T, r *Repository) model.Profile {
	t.Helper()
	p, e := r.SaveProfile(context.Background(), model.Profile{ID: "vanilla", ProjectID: "project", Name: "Vanilla", Loader: "vanilla"}, "owner")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func signManifest(t *testing.T, m model.Manifest, key ed25519.PrivateKey) model.Manifest {
	t.Helper()
	m.Signature = nil
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	m.Signature = &model.SignatureInfo{Algorithm: "Ed25519", PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Signature: hex.EncodeToString(ed25519.Sign(key, raw)), SignedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	return m
}
func TestCoreRestartHistoryAndAudit(t *testing.T) {
	r, path := openTest(t)
	ctx := context.Background()
	project(t, r)
	first := profile(t, r)
	first.Name = "Vanilla next"
	next, e := r.SaveProfile(ctx, first, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if next.Revision != 2 {
		t.Fatalf("ревизия=%d", next.Revision)
	}
	if _, e = r.SaveProfile(ctx, first, "owner"); !errors.Is(e, ErrConflict) {
		t.Fatalf("Принята устаревшая ревизия: %v", e)
	}
	history, e := r.ListProfileRevisions(ctx, "project", "vanilla")
	if e != nil || len(history) != 2 {
		t.Fatalf("история: %d %v", len(history), e)
	}
	if history[0].Spec.Name != "Vanilla" || history[1].Spec.Name != "Vanilla next" {
		t.Fatal("История неожиданно изменилась")
	}
	if _, e = r.SaveUser(ctx, model.User{ID: "owner", Email: "owner@example.test", RoleID: "owner", Status: "active", ProjectRoles: map[string]string{"project": "owner"}}, "bootstrap"); e != nil {
		t.Fatal(e)
	}
	if e = r.SetUserDisabled(ctx, "owner", true, "operator"); e == nil {
		t.Fatal("отключён последний владелец")
	}
	u, e := r.GetUser(ctx, "owner")
	if e != nil || u.Status != "active" {
		t.Fatalf("изменена учётная запись последнего владельца: %v %+v", e, u)
	}
	if _, e = r.SaveUser(ctx, model.User{ID: "user", Email: "mixed@example.test", RoleID: "viewer", ProjectRoles: map[string]string{"project": "viewer"}}, "owner"); e != nil {
		t.Fatal(e)
	}
	before, e := r.AuthEpoch(ctx, "user")
	if e != nil {
		t.Fatal(e)
	}
	u, e = r.GetUserByEmail(ctx, "MIXED@EXAMPLE.TEST")
	if e != nil {
		t.Fatal(e)
	}
	u.ProjectRoles["project"] = "release-manager"
	if _, e = r.SaveUser(ctx, u, "owner"); e != nil {
		t.Fatal(e)
	}
	after, e := r.AuthEpoch(ctx, "user")
	if e != nil || after != before+1 {
		t.Fatalf("эпоха авторизации %d -> %d: %v", before, after, e)
	}
	if e = r.RecordAudit(ctx, model.AuditEvent{ID: "known", Actor: "owner", Action: "security:test", Target: "user"}); e != nil {
		t.Fatal(e)
	}
	if e = r.RecordAudit(ctx, model.AuditEvent{ID: "known", Actor: "owner", Action: "security:test", Target: "user"}); !errors.Is(e, ErrConflict) {
		t.Fatalf("повторяющаяся запись аудита не отклонена: %v", e)
	}
	n, e := r.Count(ctx)
	if e != nil || n["audit_events"] < 4 {
		t.Fatalf("Данные аудита потеряны: %v %v", n, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenExisting(ctx, sqlitedurable.Options{Path: path})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	h, e := r.ListProfileRevisions(ctx, "project", "vanilla")
	if e != nil || len(h) != 2 {
		t.Fatalf("история не сохраняется надёжно: %v %d", e, len(h))
	}
	u, e = r.GetUser(ctx, "user")
	if e != nil || u.ProjectRoles["project"] != "release-manager" {
		t.Fatalf("роль не сохраняется надёжно: %v %+v", e, u)
	}
	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestConcurrentCASAndPublish(t *testing.T) {
	r, _ := openTest(t)
	ctx := context.Background()
	project(t, r)
	p := profile(t, r)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			x := p
			x.Name = "concurrent-" + string(rune('0'+i))
			_, e := r.SaveProfile(ctx, x, "owner")
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	success, conflicts := 0, 0
	for e := range errs {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("CAS: успешных=%d, конфликтов=%d", success, conflicts)
	}
	d, e := r.CreateDraft(ctx, "project", "vanilla", "stable", "1.0.0", "owner")
	if e != nil {
		t.Fatal(e)
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, attacker, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	manifest := d.Manifest
	manifest.Minecraft.Version = "1.21.1"
	manifest.Runtime.Java.MajorVersion = 21
	manifest.Runtime.Java.Distribution = "any"
	manifest.Runtime.Launch.MainClass = "net.minecraft.client.main.Main"
	manifest = signManifest(t, manifest, key)
	if _, e = r.UpdateDraftManifest(ctx, "project", d.ID, manifest, "owner"); e != nil {
		t.Fatal(e)
	}
	if _, e = r.PublishDraft(ctx, "project", d.ID, 0, []ed25519.PublicKey{attacker.Public().(ed25519.PublicKey)}, "owner"); e == nil {
		t.Fatal("опубликован подписанный, но недоверенный релиз")
	}
	pub, e := r.PublishDraft(ctx, "project", d.ID, 0, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if pub.Status != "published" {
		t.Fatal("публикация не была сохранена")
	}
	if _, e = r.PublishDraft(ctx, "project", d.ID, 0, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, "owner"); !errors.Is(e, ErrImmutable) {
		t.Fatalf("результат повторной публикации: %v", e)
	}
	if _, e = r.UpdateDraftManifest(ctx, "project", d.ID, manifest, "owner"); !errors.Is(e, ErrImmutable) {
		t.Fatalf("опубликованные данные можно изменять: %v", e)
	}
	published, e := r.Published(ctx, "project", "vanilla", "stable", []ed25519.PublicKey{key.Public().(ed25519.PublicKey)})
	if e != nil || published.ID != d.ID {
		t.Fatalf("головная ревизия: %v %+v", e, published)
	}
	head, e := r.GetChannelHead(ctx, "project", "vanilla", "stable")
	if e != nil || head.Revision != 1 {
		t.Fatalf("головная ревизия: %+v %v", head, e)
	}
}
func TestInvalidRoleRollsBackUserAndAudit(t *testing.T) {
	r, _ := openTest(t)
	ctx := context.Background()
	project(t, r)
	if _, e := r.SaveUser(ctx, model.User{ID: "owner", Email: "owner@example.test", RoleID: "owner"}, "bootstrap"); e != nil {
		t.Fatal(e)
	}
	before, e := r.Count(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = r.SaveUser(ctx, model.User{ID: "new", Email: "new@example.test", RoleID: "invalid"}, "owner")
	if e == nil {
		t.Fatal("принята недопустимая роль пользователя")
	}
	if _, e = r.GetUser(ctx, "new"); !errors.Is(e, ErrNotFound) {
		t.Fatalf("частичная запись пользователя зафиксирована: %v", e)
	}
	after, e := r.Count(ctx)
	if e != nil || after["audit_events"] != before["audit_events"] {
		t.Fatalf("неполный аудит: %v %v", after, e)
	}
}
