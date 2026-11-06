package sqlitepg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

const MinimalBundleSchema0377 = "launcher_minimal_transfer_0377"
const minimalBundleFormat0377 = "launcher-minimal-offline-backup-v1"

type MinimalBundleFile0377 struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
type MinimalBundleManifest0377 struct {
	Format      string                  `json:"format"`
	CreatedAt   string                  `json:"createdAt"`
	SourceRoot  string                  `json:"sourceRoot"`
	Files       []MinimalBundleFile0377 `json:"files"`
	Directories []string                `json:"directories"`
}
type MinimalBundleReport0377 struct {
	Format                 string `json:"format"`
	ManifestSHA256         string `json:"manifestSha256"`
	Files                  int    `json:"files"`
	Bytes                  int64  `json:"bytes"`
	ReadyForBackendCutover bool   `json:"readyForBackendCutover"`
}

func minimalRef0377(table string) string {
	return quoted(MinimalBundleSchema0377) + "." + quoted(table)
}
func legalPath0377(p string) bool {
	if p == "" || p == "." || strings.ContainsAny(p, "\\\x00") || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, v := range strings.Split(p, "/") {
		if v == "" || v == "." || v == ".." {
			return false
		}
	}
	return true
}
func rejectSymlinkComponents0377(p string) error {
	abs, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	for current := abs; current != "/"; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("В пути обнаружен компонент-символьная ссылка: %s", current)
		}
	}
	return nil
}

func privateFile0377(p string, directory bool) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("Небезопасное значение: файл или каталог без ограниченного доступа %s", p)
	}
	if directory && !st.IsDir() {
		return fmt.Errorf("Указанный путь не является каталогом: %s", p)
	}
	if !directory && (!st.Mode().IsRegular() || st.Sys() == nil) {
		return fmt.Errorf("Указанный путь не является обычным файлом: %s", p)
	}
	return nil
}
func digestFile0377(p string) (int64, string, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}
func checkSQLite0377(ctx context.Context, p string) error {
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: p}).String()+"?mode=ro&immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("Проверка integrity_check SQLite: %s", result)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	failed := rows.Next()
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if failed {
		return errors.New("Ошибка: проверка внешних ключей SQLite")
	}
	return nil
}
func verifyMinimalBundle0377(ctx context.Context, bundle string) (MinimalBundleManifest0377, []byte, error) {
	var m MinimalBundleManifest0377
	if err := rejectSymlinkComponents0377(bundle); err != nil {
		return m, nil, err
	}
	if err := privateFile0377(bundle, true); err != nil {
		return m, nil, err
	}
	payload := filepath.Join(bundle, "payload")
	if err := privateFile0377(payload, true); err != nil {
		return m, nil, err
	}
	raw, err := os.ReadFile(filepath.Join(bundle, "manifest.json"))
	if err != nil {
		return m, nil, err
	}
	if len(raw) > 32*1024*1024 {
		return m, nil, errors.New("Превышен допустимый размер: минимальный манифест")
	}
	if err = privateFile0377(filepath.Join(bundle, "manifest.json"), false); err != nil {
		return m, nil, err
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		return m, nil, err
	}
	if m.Format != minimalBundleFormat0377 || len(m.SourceRoot) == 0 || !filepath.IsAbs(m.SourceRoot) || len(m.Directories) == 0 || m.Directories[0] != "." {
		return m, nil, errors.New("Неподдерживаемый формат минимальной автономной резервной копии")
	}
	dirs := map[string]bool{".": true}
	files := map[string]bool{}
	for i, d := range m.Directories {
		if i > 0 && (!legalPath0377(d) || d <= "." || d <= m.Directories[i-1]) {
			return m, nil, errors.New("Некорректное значение: или каталог с нарушенным порядком в минимальном комплекте")
		}
		if d != "." {
			if err = privateFile0377(filepath.Join(payload, filepath.FromSlash(d)), true); err != nil {
				return m, nil, err
			}
		}
		dirs[d] = true
	}
	foundHTTP, foundCoord, foundEnv := false, false, false
	for i, f := range m.Files {
		if !legalPath0377(f.Path) || (i > 0 && f.Path <= m.Files[i-1].Path) || (f.Kind != "sqlite" && f.Kind != "file") || f.Bytes < 0 || len(f.SHA256) != 64 || f.Mode > 0700 || f.Mode&0077 != 0 {
			return m, nil, errors.New("Небезопасное значение: или файл минимального комплекта с нарушенным порядком")
		}
		file := filepath.Join(payload, filepath.FromSlash(f.Path))
		if err = privateFile0377(file, false); err != nil {
			return m, nil, err
		}
		stat, err := os.Stat(file)
		if err != nil {
			return m, nil, err
		}
		if stat.Mode().Perm() != os.FileMode(f.Mode) {
			return m, nil, fmt.Errorf("Несовпадение: «mode»: %s", f.Path)
		}
		n, digest, e := digestFile0377(file)
		if e != nil {
			return m, nil, e
		}
		if n != f.Bytes || digest != f.SHA256 {
			return m, nil, fmt.Errorf("Несовпадение: контрольная сумма файла минимального комплекта: %s", f.Path)
		}
		if f.Kind == "sqlite" {
			if err = checkSQLite0377(ctx, file); err != nil {
				return m, nil, fmt.Errorf("%s: %w", f.Path, err)
			}
		}
		if f.Path == "db/http.sqlite" {
			foundHTTP = f.Kind == "sqlite"
		}
		if f.Path == "db/coordinator.sqlite" {
			foundCoord = f.Kind == "sqlite"
		}
		if f.Path == "config/backend.env" {
			foundEnv = true
		}
		files[f.Path] = true
	}
	if !foundHTTP || !foundCoord || !foundEnv {
		return m, nil, errors.New("Отсутствует: обязательные БД или конфигурация минимального комплекта")
	}
	actualDirs := []string{"."}
	actualFiles := []string{}
	err = filepath.WalkDir(payload, func(p string, d os.DirEntry, er error) error {
		if er != nil {
			return er
		}
		if p == payload {
			return nil
		}
		relative, e := filepath.Rel(payload, p)
		if e != nil {
			return e
		}
		relative = filepath.ToSlash(relative)
		if d.IsDir() {
			actualDirs = append(actualDirs, relative)
		} else {
			actualFiles = append(actualFiles, relative)
		}
		return nil
	})
	if err != nil {
		return m, nil, err
	}
	sort.Strings(actualDirs)
	sort.Strings(actualFiles)
	if len(actualDirs) != len(dirs) || len(actualFiles) != len(files) {
		return m, nil, errors.New("Отсутствует: или посторонние файлы в минимальной резервной копии")
	}
	for _, p := range actualDirs {
		if !dirs[p] {
			return m, nil, fmt.Errorf("Лишний каталог: %s", p)
		}
	}
	for _, p := range actualFiles {
		if !files[p] {
			return m, nil, fmt.Errorf("Лишний файл: %s", p)
		}
	}
	return m, raw, nil
}

// ImportMinimalBundle0377 сохраняет полный минимальный офлайн-снимок в
// PostgreSQL, включая обе БД SQLite, ключи, конфигурацию и файлы проекта.
// Она изменяет рабочую схему PostgreSQL Repository.
func ImportMinimalBundle0377(ctx context.Context, bundle, dsn string) (report MinimalBundleReport0377, err error) {
	if dsn == "" {
		return report, errors.New("Необходимо указать DSN PostgreSQL")
	}
	m, raw, err := verifyMinimalBundle0377(ctx, bundle)
	if err != nil {
		return report, err
	}
	h := sha256.Sum256(raw)
	report = MinimalBundleReport0377{Format: minimalBundleFormat0377, ManifestSHA256: hex.EncodeToString(h[:]), Files: len(m.Files), ReadyForBackendCutover: false}
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return report, fmt.Errorf("Ошибка подключения к PostgreSQL (%T; DSN скрыт)", err)
	}
	defer pg.Close(context.Background())
	tx, err := pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return report, err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(377, 1)`); err != nil {
		return report, err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, MinimalBundleSchema0377).Scan(&exists); err != nil {
		return report, err
	}
	if exists {
		return report, errors.New("Минимальный перенос PostgreSQL уже существует; перезапись запрещена")
	}
	if _, err = tx.Exec(ctx, "CREATE SCHEMA "+quoted(MinimalBundleSchema0377)); err != nil {
		return report, err
	}
	ddls := []string{
		`CREATE TABLE ` + minimalRef0377("receipt") + ` (id TEXT PRIMARY KEY, manifest JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`CREATE TABLE ` + minimalRef0377("files") + ` (path TEXT PRIMARY KEY, kind TEXT NOT NULL, mode INTEGER NOT NULL, bytes BIGINT NOT NULL, sha256 TEXT NOT NULL)`,
		`CREATE TABLE ` + minimalRef0377("chunks") + ` (path TEXT NOT NULL REFERENCES ` + minimalRef0377("files") + ` (path), ordinal BIGINT NOT NULL, sha256 TEXT NOT NULL, payload BYTEA NOT NULL, PRIMARY KEY(path,ordinal))`,
	}
	for _, ddl := range ddls {
		if _, err = tx.Exec(ctx, ddl); err != nil {
			return report, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+minimalRef0377("receipt")+` (id,manifest) VALUES($1,$2)`, report.ManifestSHA256, string(raw)); err != nil {
		return report, err
	}
	for _, f := range m.Files {
		if _, err = tx.Exec(ctx, `INSERT INTO `+minimalRef0377("files")+` (path,kind,mode,bytes,sha256) VALUES($1,$2,$3,$4,$5)`, f.Path, f.Kind, int32(f.Mode), f.Bytes, f.SHA256); err != nil {
			return report, err
		}
		source := filepath.Join(bundle, "payload", filepath.FromSlash(f.Path))
		input, e := os.Open(source)
		if e != nil {
			return report, e
		}
		digest := sha256.New()
		buffer := make([]byte, snapshotChunkSize)
		for ordinal := int64(0); ; ordinal++ {
			n, e := io.ReadFull(input, buffer)
			if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
				input.Close()
				return report, e
			}
			if n == 0 {
				break
			}
			part := append([]byte(nil), buffer[:n]...)
			_, _ = digest.Write(part)
			sum := sha256.Sum256(part)
			if _, err = tx.Exec(ctx, `INSERT INTO `+minimalRef0377("chunks")+` (path,ordinal,sha256,payload) VALUES($1,$2,$3,$4)`, f.Path, ordinal, hex.EncodeToString(sum[:]), part); err != nil {
				input.Close()
				return report, err
			}
			if e != nil {
				break
			}
		}
		err = errors.Join(err, input.Close())
		if err != nil {
			return report, err
		}
		if hex.EncodeToString(digest.Sum(nil)) != f.SHA256 {
			return report, fmt.Errorf("Файл изменился во время переноса в PostgreSQL: %s", f.Path)
		}
		report.Bytes += f.Bytes
	}
	// Таблицы переноса только для чтения предотвращают случайное изменение отзыва токенов,
	// состояния доверия или конфигурации проекта после фиксации снимка.
	if _, err = tx.Exec(ctx, `CREATE FUNCTION `+quoted(MinimalBundleSchema0377)+`.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Launcher minimal bundle is immutable'; END $$`); err != nil {
		return report, err
	}
	for _, name := range []string{"receipt", "files", "chunks"} {
		for _, kind := range []string{"BEFORE INSERT OR UPDATE OR DELETE", "BEFORE TRUNCATE"} {
			level := "FOR EACH ROW"
			if kind == "BEFORE TRUNCATE" {
				level = "FOR EACH STATEMENT"
			}
			_, err = tx.Exec(ctx, `CREATE TRIGGER `+quoted("nl_guard_"+strings.ReplaceAll(kind, " ", "_"))+` `+kind+` ON `+minimalRef0377(name)+` `+level+` EXECUTE FUNCTION `+quoted(MinimalBundleSchema0377)+`.reject_mutation()`)
			if err != nil {
				return report, err
			}
		}
	}
	// Повторно проверить точные байты источника непосредственно перед COMMIT; использовать
	// незамороженный активный каталог здесь. Источник должен быть офлайн-резервной копией.
	_, again, err := verifyMinimalBundle0377(ctx, bundle)
	if err != nil {
		return report, err
	}
	h = sha256.Sum256(again)
	if hex.EncodeToString(h[:]) != report.ManifestSHA256 {
		return report, errors.New("Манифест изменился во время импорта")
	}
	if err = tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("Результат сохранения PostgreSQL требует сверки: %w", err)
	}
	return report, nil
}

// ExportMinimalBundle0377 восстанавливает новый минимальный офлайн-пакет резервной копии.
// Передать это в minimal_backup.py verify/restore; не обслуживать импортированную схему PG
// как рабочий PostgreSQL Backend.
func ExportMinimalBundle0377(ctx context.Context, dsn, target string) (report MinimalBundleReport0377, err error) {
	if dsn == "" || target == "" {
		return report, errors.New("Требуется: строка подключения PostgreSQL и целевая база")
	}
	dest, e := filepath.Abs(target)
	if e != nil {
		return report, e
	}
	if _, e = os.Lstat(dest); e == nil {
		return report, errors.New("Уже существует: цель")
	} else if !os.IsNotExist(e) {
		return report, e
	}
	parent := filepath.Dir(dest)
	if err = rejectSymlinkComponents0377(parent); err != nil {
		return report, err
	}
	if err = privateFile0377(parent, true); err != nil {
		return report, err
	}
	pg, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return report, fmt.Errorf("Ошибка подключения к PostgreSQL (%T; DSN скрыт)", e)
	}
	defer pg.Close(context.Background())
	tx, e := pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return report, e
	}
	defer tx.Rollback(context.Background())
	var receipt string
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT id,manifest FROM `+minimalRef0377("receipt")).Scan(&receipt, &raw); err != nil {
		return report, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != receipt {
		return report, errors.New("Несовпадение: целостность минимального манифеста")
	}
	var m MinimalBundleManifest0377
	if err = json.Unmarshal(raw, &m); err != nil {
		return report, err
	}
	if m.Format != minimalBundleFormat0377 {
		return report, errors.New("Не поддерживается: «формат резервной копии»")
	}
	report = MinimalBundleReport0377{Format: m.Format, ManifestSHA256: receipt, Files: len(m.Files)}
	stage, e := os.MkdirTemp(parent, ".launcher-minimal-pg-*")
	if e != nil {
		return report, e
	}
	defer os.RemoveAll(stage)
	if e = os.Chmod(stage, 0700); e != nil {
		return report, e
	}
	payload := filepath.Join(stage, "payload")
	if err = os.Mkdir(payload, 0700); err != nil {
		return report, err
	}
	for _, dir := range m.Directories {
		if dir != "." {
			if !legalPath0377(dir) {
				return report, errors.New("Недопустимый каталог резервной копии")
			}
			if err = os.Mkdir(filepath.Join(payload, filepath.FromSlash(dir)), 0700); err != nil {
				return report, err
			}
		}
	}
	for _, f := range m.Files {
		if !legalPath0377(f.Path) {
			return report, errors.New("Недопустимый путь в импортированном манифесте")
		}
		var saved MinimalBundleFile0377
		var mode int32
		if err = tx.QueryRow(ctx, `SELECT path,kind,mode,bytes,sha256 FROM `+minimalRef0377("files")+` WHERE path=$1`, f.Path).Scan(&saved.Path, &saved.Kind, &mode, &saved.Bytes, &saved.SHA256); err != nil {
			return report, err
		}
		if mode < 0 {
			return report, fmt.Errorf("Некорректное значение: «stored file mode»: %s", f.Path)
		}
		saved.Mode = uint32(mode)
		if saved != f {
			return report, fmt.Errorf("Метаданные файла PostgreSQL не совпадают с манифестом: %s", f.Path)
		}
		targetFile := filepath.Join(payload, filepath.FromSlash(f.Path))
		out, e := os.OpenFile(targetFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return report, e
		}
		rows, e := tx.Query(ctx, `SELECT ordinal,sha256,payload FROM `+minimalRef0377("chunks")+` WHERE path=$1 ORDER BY ordinal`, f.Path)
		if e != nil {
			out.Close()
			return report, e
		}
		count, n := int64(0), int64(0)
		h := sha256.New()
		for rows.Next() {
			var ordinal int64
			var digest string
			var chunk []byte
			if err = rows.Scan(&ordinal, &digest, &chunk); err != nil {
				break
			}
			ch := sha256.Sum256(chunk)
			if ordinal != count || len(chunk) == 0 || len(chunk) > snapshotChunkSize || hex.EncodeToString(ch[:]) != digest {
				err = errors.New("Отсутствует или повреждён фрагмент пакета PostgreSQL")
				break
			}
			var written int
			written, err = out.Write(chunk)
			if err != nil {
				break
			}
			if written != len(chunk) {
				err = io.ErrShortWrite
				break
			}
			_, _ = h.Write(chunk)
			n += int64(written)
			count++
			if n > f.Bytes {
				err = errors.New("Размер пакета превышает заявленный")
				break
			}
		}
		err = errors.Join(err, rows.Err())
		rows.Close()
		if err == nil && (n != f.Bytes || hex.EncodeToString(h.Sum(nil)) != f.SHA256) {
			err = errors.New("Несовпадение: «хеш или размер файла комплекта PostgreSQL»")
		}
		if err == nil {
			err = out.Sync()
		}
		err = errors.Join(err, out.Close())
		if err != nil {
			return report, fmt.Errorf("%s: %w", f.Path, err)
		}
		if err = os.Chmod(targetFile, os.FileMode(f.Mode)); err != nil {
			return report, err
		}
		report.Bytes += n
	}
	if err = os.WriteFile(filepath.Join(stage, "manifest.json"), raw, 0600); err != nil {
		return report, err
	}
	if _, _, err = verifyMinimalBundle0377(ctx, stage); err != nil {
		return report, err
	}
	// Назначения нет: атомарная публикация каталога без замены существующего в Linux.
	if err = publishNewDirectory0377(stage, dest); err != nil {
		return report, err
	}
	if err = tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("Передача опубликована, но подтверждение записи PostgreSQL не определено; проверьте целевое хранилище: %w", err)
	}
	return report, nil
}
