package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDetectsDirectSQLAndPostgresDialect0371(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "services/api/example")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	sample := `package example
import (
 "database/sql"
 _ "github.com/jackc/pgx/v5/stdlib"
)
func f(){
 var db *sql.DB
 db,_=sql.Open("pgx","postgres://local")
 _=db
 _="SELECT x::jsonb FROM t WHERE id=$1 FOR UPDATE"
}
`
	path := filepath.Join(dir, "pg.go")
	if err := os.WriteFile(path, []byte(sample), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := scanGo(root, "services/api/example/pg.go")
	if err != nil {
		t.Fatal(err)
	}
	categories := map[string]bool{}
	for _, item := range f.Findings {
		categories[item.Category] = true
		if item.Line < 1 || item.Evidence == "" {
			t.Fatalf("Некорректная позиция в исходнике: %+v", item)
		}
	}
	for _, kind := range []string{"postgres-driver-import", "database-sql-handle", "direct-sql-open", "postgresql-sql-dialect", "postgresql-config-or-literal"} {
		if !categories[kind] {
			t.Errorf("Отсутствует зависимость %s: %+v", kind, f.Findings)
		}
	}
}
func TestIgnoresGoCommentsAndNonPostgresSQL0371(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "services/api/example")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	code := `package example
// postgres:// здесь только в комментарии, а не в качестве промышленной зависимости.
func plain(){ _ = "SELECT id FROM projects WHERE id=?" }
`
	if err := os.WriteFile(filepath.Join(dir, "normal.go"), []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := scanGo(root, "services/api/example/normal.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Findings) != 0 {
		t.Fatalf("Неверно классифицирован комментарий или запрос без привязки к диалекту: %+v", f.Findings)
	}
}
func TestReportIsDeterministicAndMethodCoverageNotSemantic0371(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	a, err := collect(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := collect(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := serialize(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := serialize(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Инвентаризация не воспроизводится")
	}
	if len(a.MethodSurface.Interface) < 100 {
		t.Fatalf("Интерфейс HTTP Repository просканирован не полностью (%d)", len(a.MethodSurface.Interface))
	}
	if len(a.MethodSurface.Missing) == 0 {
		t.Fatal("Ошибочно подтверждено полное соответствие HTTP и SQLite")
	}
	if !strings.Contains(string(first), "sqliteSameNameOnlyNotParity") {
		t.Fatal("Совпадение имён методов не доказывает совместимость")
	}
}
