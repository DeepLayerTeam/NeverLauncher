package repository

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Добавленное поле модели домена нельзя молча отбрасывать при сохранении.
// Тест намеренно расположен в пакете репозитория.
func TestSQLiteHTTPStateCoverage0372(t *testing.T) {
	source := reflect.TypeOf(MemoryRepository{})
	persisted := reflect.TypeOf(sqliteHTTPState0372{})
	got := map[string]reflect.Type{}
	for i := 0; i < persisted.NumField(); i++ {
		f := persisted.Field(i)
		got[strings.ToLower(f.Name[:1])+f.Name[1:]] = f.Type
	}
	for i := 0; i < source.NumField(); i++ {
		f := source.Field(i)
		if f.Type == reflect.TypeOf(sync.Mutex{}) || f.Type == reflect.TypeOf(sync.RWMutex{}) || f.Type.Kind() == reflect.Func {
			continue
		}
		if v, ok := got[f.Name]; !ok || v != f.Type {
			t.Errorf("поле HTTP-состояния %s (%s) не сохраняется с соответствующим типом", f.Name, f.Type)
		}
	}
}

func TestSQLiteHTTPPersistenceAndCAS0372(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "http-repository.db")
	open := func() *SQLiteHTTPRepository0372 {
		r, err := OpenSQLiteHTTPRepository0372(ctx, path, "https://example")
		if err != nil {
			t.Fatalf("не удалось открыть реальный репозиторий SQLite WAL: %v", err)
		}
		return r
	}
	r := open()
	if len(r.ListProjects()) != 0 || len(r.ListUsers()) != 0 {
		t.Fatal("новая установка SQLite не должна наследовать проекты разработки и учётные данные администратора")
	}
	if err := r.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SaveUser(model.User{ID: "unapproved", Email: "viewer@example.test", RoleID: "viewer"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("первая учётная запись должна принадлежать активному владельцу: %v", err)
	}
	project, err := r.SaveProject(model.Project{ID: "real-project", Name: "Real project"})
	if err != nil || project.ID != "real-project" {
		t.Fatalf("сохранение проекта: %+v / %v", project, err)
	}
	p, err := r.SaveProfile(model.Profile{ProjectID: project.ID, ID: "client", Name: "Vanilla", Loader: "vanilla"})
	if err != nil || p.Revision != 1 {
		t.Fatalf("сохранение профиля: %+v / %v", p, err)
	}
	current := p
	current.Name = "Updated"
	updated, err := r.SaveProfile(current)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("ревизия CAS: %+v / %v", updated, err)
	}
	current.Name = "Stale edit"
	if _, err := r.SaveProfile(current); !errors.Is(err, ErrConflict) {
		t.Fatalf("ожидался конфликт устаревшей ревизии CAS, получено: %v", err)
	}
	if _, err := r.SaveUser(model.User{ID: "owner", Email: "owner@example.test", RoleID: "owner", Status: "active"}); err != nil {
		t.Fatalf("Владелец: %v", err)
	}
	if _, err := r.SetUserDisabled("owner", true); !errors.Is(err, ErrConflict) {
		t.Fatalf("последняя учётная запись владельца отключена: %v", err)
	}
	if _, err := OpenSQLiteHTTPRepository0372(ctx, path, ""); err == nil {
		t.Fatal("второй процесс записи захватил тот же файл SQLite")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = open()
	defer r.Close()
	if err := r.Health(ctx); err != nil {
		t.Fatalf("готовность после повторного открытия: %v", err)
	}
	if got, err := r.GetProject(project.ID); err != nil || got.Name != project.Name {
		t.Fatalf("проект потерян после перезапуска: %+v / %v", got, err)
	}
	profiles, err := r.ListProfiles(project.ID)
	if err != nil || len(profiles) != 1 || profiles[0].Revision != 2 || profiles[0].Name != "Updated" {
		t.Fatalf("ревизия профиля потеряна после перезапуска: %+v / %v", profiles, err)
	}
	history, err := r.ListProfileRevisions(project.ID, "client")
	if err != nil || len(history) != 2 {
		t.Fatalf("история потеряна после перезапуска: %+v / %v", history, err)
	}
	if _, err := r.GetUserByEmail("owner@example.test"); err != nil {
		t.Fatalf("владелец потерян после перезапуска: %v", err)
	}
	if len(r.ListUsers()) != 1 {
		t.Fatal("после повторного открытия обнаружен неожиданный пользователь разработки")
	}
}

func TestSQLiteHTTPConcurrentWritesAndSafeFailure0372(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "concurrency.db")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	const n = 18
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i))
			_, err := r.SaveProject(model.Project{ID: "p" + id, Name: "project " + id})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := len(r.ListProjects()); got != n {
		t.Fatalf("параллельные записи потеряны: получено %d, ожидалось %d", got, n)
	}
	// Отсутствующий релиз нельзя продвинуть в stable. Обхода Runtime-гейта нет.
	if _, err := r.PublishVersion("pa", "client", "stable", "1.0"); err == nil {
		t.Fatal("публикация стабильного выпуска неожиданно завершилась успешно")
	}
}

func TestSQLiteHTTPMutationsCannotReportSuccessWithoutCommit0372(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateSQLiteTempDir(t), "commit-failure.db")
	r, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	// Ошибка диска/подключения после изменения домена должна сообщаться
	// как долговременная запись либо обслуживаться из несинхронизированного кэша процесса.
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = r.SaveProject(model.Project{ID: "not-committed", Name: "Not committed"})
	if err == nil {
		t.Fatal("после неудачной фиксации SQLite COMMIT возвращён успешный результат")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("устаревший несинхронизированный кеш остался доступен для чтения")
			}
		}()
		_, _ = r.GetProject("not-committed")
	}()
	reloaded, err := OpenSQLiteHTTPRepository0372(ctx, path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if _, err = reloaded.GetProject("not-committed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("незафиксированный проект сохранился после перезапуска: %v", err)
	}
}

func TestSQLiteHTTPFilePermissions0372(t *testing.T) {
	path := filepath.Join(privateSQLiteTempDir(t), "mode.db")
	r, err := OpenSQLiteHTTPRepository0372(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("база данных доступна группе или другим пользователям: %s", info.Mode().Perm())
	}
}
