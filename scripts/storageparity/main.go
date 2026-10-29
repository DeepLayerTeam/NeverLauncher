// Command storageparity inventories the actual PostgreSQL coupling and SQLite
// method surface directly from source. The checked-in snapshot is a regression
// gate: any added/removed dependency must be reviewed, not silently overlooked.
// It deliberately does not claim semantic parity from matching method names.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Finding struct {
	Category string `json:"category"`
	Line     int    `json:"line"`
	Evidence string `json:"evidence"`
}
type File struct {
	Path     string    `json:"path"`
	Findings []Finding `json:"findings"`
}
type Surface struct {
	Interface  []string `json:"httpRepositoryMethods"`
	PostgreSQL []string `json:"postgresSQLRepositoryMethods"`
	SQLite     []string `json:"sqliteCoreMethods"`
	SameNames  []string `json:"sqliteSameNameOnlyNotParity"`
	Missing    []string `json:"httpRepositoryMethodsWithoutSQLiteCoreName"`
}
type Report struct {
	Schema        int     `json:"schema"`
	Scope         string  `json:"scope"`
	MethodSurface Surface `json:"methodSurface"`
	Dependencies  []File  `json:"dependencies"`
}

var (
	pgDialect = regexp.MustCompile(`(?i)(\$[1-9][0-9]*|::(?:jsonb?|uuid|text|timestamptz|interval)|\b(?:FOR\s+UPDATE|SKIP\s+LOCKED|BIGSERIAL|TIMESTAMPTZ|pg_advisory_[a-z_]+|jsonb_[a-z_]+|pg_catalog|CREATE\s+EXTENSION|ON\s+CONFLICT\s+ON\s+CONSTRAINT)\b)`)
	pgConfig  = regexp.MustCompile(`(?i)(NEVERLAUNCHER_(?:POSTGRES|PG_|DATABASE_DSN|REPOSITORY_DRIVER|SQL_DRIVER)|postgres(?:ql)?://|\b(?:postgres|postgresql|pgx|jsonb|bigserial|timestamptz)\b)`)
)

func uniqueSorted(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}
func readerMethods(expr *ast.InterfaceType) []string {
	found := map[string]bool{}
	for _, f := range expr.Methods.List {
		if _, ok := f.Type.(*ast.FuncType); ok {
			for _, n := range f.Names {
				found[n.Name] = true
			}
		}
	}
	return uniqueSorted(found)
}
func recvName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
func sourceMethods(path, typ, receiver string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.GenDecl:
			if typ == "" {
				continue
			}
			for _, s := range d.Specs {
				t, ok := s.(*ast.TypeSpec)
				if !ok || t.Name.Name != typ {
					continue
				}
				iface, ok := t.Type.(*ast.InterfaceType)
				if ok {
					return readerMethods(iface), nil
				}
			}
		case *ast.FuncDecl:
			if recvName(d) == receiver && d.Recv != nil {
				out[d.Name.Name] = true
			}
		}
	}
	if typ != "" {
		return nil, fmt.Errorf("%s: missing interface %s", path, typ)
	}
	return uniqueSorted(out), nil
}
func allMethods(dir, recv string) ([]string, error) {
	m := map[string]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		methods, err := sourceMethods(filepath.Join(dir, e.Name()), "", recv)
		if err != nil {
			return nil, err
		}
		for _, name := range methods {
			m[name] = true
		}
	}
	return uniqueSorted(m), nil
}
func methodSurface(root string) (Surface, error) {
	base := filepath.Join(root, "services/api/internal")
	iface, err := sourceMethods(filepath.Join(base, "repository/memory.go"), "Repository", "")
	if err != nil {
		return Surface{}, err
	}
	pg, err := allMethods(filepath.Join(base, "repository"), "SQLRepository")
	if err != nil {
		return Surface{}, err
	}
	sqlite, err := allMethods(filepath.Join(base, "sqlitecore"), "Repository")
	if err != nil {
		return Surface{}, err
	}
	sqliteSet := map[string]bool{}
	for _, m := range sqlite {
		sqliteSet[m] = true
	}
	overlapping := []string{}
	missing := []string{}
	for _, m := range iface {
		if sqliteSet[m] {
			overlapping = append(overlapping, m)
		} else {
			missing = append(missing, m)
		}
	}
	return Surface{Interface: iface, PostgreSQL: pg, SQLite: sqlite, SameNames: overlapping, Missing: missing}, nil
}
func readEvidence(b []byte, pos token.Position) string {
	lines := bytes.Split(b, []byte{'\n'})
	if pos.Line < 1 || pos.Line > len(lines) {
		return ""
	}
	s := strings.Join(strings.Fields(string(lines[pos.Line-1])), " ")
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}
func scanGo(root, rel string) (File, error) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, b, 0)
	if err != nil {
		return File{}, fmt.Errorf("parse %s: %w", rel, err)
	}
	findings := map[string]Finding{}
	add := func(kind string, pos token.Pos) {
		p := fset.Position(pos)
		k := fmt.Sprintf("%s:%d", kind, p.Line)
		findings[k] = Finding{Category: kind, Line: p.Line, Evidence: readEvidence(b, p)}
	}
	for _, i := range f.Imports {
		s, e := strconv.Unquote(i.Path.Value)
		if e == nil && (strings.Contains(s, "pgx") || strings.Contains(s, "pq") || strings.Contains(s, "postgres")) {
			add("postgres-driver-import", i.Pos())
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			switch v.Sel.Name {
			case "DatabaseDSN", "SQLDriver", "RepositoryDriver", "SQLiteCoordinatorPath":
				add("storage-configuration-read", v.Pos())
			}
		case *ast.CallExpr:
			if s, ok := v.Fun.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == "sql" && s.Sel.Name == "Open" {
					add("direct-sql-open", v.Pos())
				}
			}
			if id, ok := v.Fun.(*ast.Ident); ok {
				switch id.Name {
				case "NewPostgresRepository", "NewSQLRepository":
					add("postgres-repository-construction", v.Pos())
				}
			}
			if s, ok := v.Fun.(*ast.SelectorExpr); ok {
				switch s.Sel.Name {
				case "NewPostgresRepository", "NewSQLRepository":
					add("postgres-repository-construction", v.Pos())
				}
			}
		case *ast.StarExpr:
			if s, ok := v.X.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == "sql" && (s.Sel.Name == "DB" || s.Sel.Name == "Tx") {
					add("database-sql-handle", v.Pos())
				}
			}
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				break
			}
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				break
			}
			if pgDialect.MatchString(s) {
				add("postgresql-sql-dialect", v.Pos())
			}
			if pgConfig.MatchString(s) {
				add("postgresql-config-or-literal", v.Pos())
			}
		}
		return true
	})
	result := File{Path: rel}
	for _, v := range findings {
		result.Findings = append(result.Findings, v)
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Category < b.Category
	})
	return result, nil
}
func scanText(root, rel string) (File, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return File{}, err
	}
	var findings []Finding
	for i, line := range strings.Split(string(b), "\n") {
		var kinds []string
		if pgDialect.MatchString(line) {
			kinds = append(kinds, "postgresql-sql-dialect")
		}
		if pgConfig.MatchString(line) {
			kinds = append(kinds, "postgresql-config-or-literal")
		}
		if strings.HasSuffix(rel, ".sql") && len(strings.TrimSpace(line)) > 0 && i == 0 {
			// Only migration catalogues wired to the PostgreSQL migrate package
			// are positively classified. Other SQL files remain candidates.
			if strings.Contains(rel, "/dbmigrate/sql/") {
				kinds = append(kinds, "postgresql-migration-file")
			} else {
				kinds = append(kinds, "sql-file-engine-unclassified")
			}
		}
		for _, kind := range kinds {
			s := strings.Join(strings.Fields(line), " ")
			if len(s) > 180 {
				s = s[:180]
			}
			findings = append(findings, Finding{Category: kind, Line: i + 1, Evidence: s})
		}
	}
	return File{Path: rel, Findings: findings}, nil
}
func collect(root string) (Report, error) {
	surface, err := methodSurface(root)
	if err != nil {
		return Report{}, err
	}
	report := Report{Schema: 1, Scope: "source-wide Go AST + SQL/config/shell/Python/CI text; excludes vendored/generated binary dependencies", MethodSurface: surface, Dependencies: []File{}}
	ignoredDirs := map[string]bool{".git": true, "node_modules": true, "target": true, "dist": true, "build": true, "vendor": true, "__pycache__": true, ".venv": true}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		ext := filepath.Ext(rel)
		var item File
		switch {
		case ext == ".go":
			item, e = scanGo(root, rel)
		case ext == ".sql" || ext == ".sh" || ext == ".py" || ext == ".yml" || ext == ".yaml" || ext == ".toml" || ext == ".example" || ext == ".mod" || ext == ".env" || filepath.Base(rel) == "Dockerfile":
			item, e = scanText(root, rel)
		default:
			return nil
		}
		if e != nil {
			return e
		}
		if len(item.Findings) > 0 {
			report.Dependencies = append(report.Dependencies, item)
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	sort.Slice(report.Dependencies, func(i, j int) bool { return report.Dependencies[i].Path < report.Dependencies[j].Path })
	return report, nil
}
func serialize(r Report) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func main() {
	root := flag.String("root", ".", "repository root")
	output := flag.String("output", "docs/deployment/storage-dependencies-0371.json", "checked in inventory")
	check := flag.Bool("check", false, "verify inventory equals the current code; never rewrite on check")
	flag.Parse()
	abs, err := filepath.Abs(*root)
	if err != nil {
		fatal(err)
	}
	report, err := collect(abs)
	if err != nil {
		fatal(err)
	}
	b, err := serialize(report)
	if err != nil {
		fatal(err)
	}
	dest := filepath.Join(abs, *output)
	if *check {
		current, err := os.ReadFile(dest)
		if err != nil {
			fatal(err)
		}
		if !bytes.Equal(current, b) {
			fatal(errors.New("storage dependency inventory drift: re-run go run ./scripts/storageparity -root .; review updated dependency map and parity coverage before merging"))
		}
		fmt.Printf("storage inventory verified: %d PostgreSQL-related files; HTTP methods=%d; SQLite name-overlap=%d (NOT semantic parity)\n", len(report.Dependencies), len(report.MethodSurface.Interface), len(report.MethodSurface.SameNames))
		return
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(dest, b, 0644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s: %d files; HTTP methods=%d; SQLite name-overlap=%d (not parity)\n", dest, len(report.Dependencies), len(report.MethodSurface.Interface), len(report.MethodSurface.SameNames))
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "storageparity:", err); os.Exit(1) }
