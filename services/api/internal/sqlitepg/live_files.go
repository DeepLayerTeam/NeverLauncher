package sqlitepg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"github.com/jackc/pgx/v5"
)

// FileCopyReport0474 записывается только после повторного чтения каждого файла и
// криптографической проверки из целевого Backend.
type FileCopyReport0474 struct {
	SourceSHA256   string `json:"sourceSha256"`
	Driver         string `json:"driver"`
	Checked        int64  `json:"checked"`
	Copied         int64  `json:"copied"`
	AlreadyPresent int64  `json:"alreadyPresent"`
	Verified       bool   `json:"verified"`
	CatalogSHA256  string `json:"catalogSha256"`
}

type fileObject0474 struct {
	project, version, path, hash string
	size                         int64
}

// Каноническая сериализация каталога обязана включать значения, а не только
// счётчик строк. Иначе неэкспортируемые поля fileObject сериализуются как {}.
func (f fileObject0474) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Project string `json:"project"`
		Version string `json:"version"`
		Path    string `json:"path"`
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
	}{f.project, f.version, f.path, f.size, f.hash})
}

func filePath0474(p, v, rel string) (string, error) {
	for _, s := range []string{p, v} {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\\x00") || strings.Contains(s, "..") {
			return "", errors.New("Небезопасное значение: «project/version segment»")
		}
	}
	if rel == "" || strings.HasPrefix(rel, "/") || strings.ContainsAny(rel, "\\\x00") || strings.Contains(rel, "//") {
		return "", errors.New("Небезопасное значение: путь к файлу")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "." || part == ".." || part == "" {
			return "", errors.New("path traversal")
		}
	}
	return filepath.Join(p, v, filepath.FromSlash(rel)), nil
}
func noSymlinks0474(root, rel string) error {
	abs, e := filepath.Abs(root)
	if e != nil {
		return e
	}
	st, e := os.Lstat(abs)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("Небезопасное значение: «storage root»")
	}
	cur := abs
	for _, s := range strings.Split(filepath.ToSlash(rel), "/") {
		cur = filepath.Join(cur, s)
		st, e = os.Lstat(cur)
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in storage: %s", rel)
		}
	}
	return nil
}
func fileDigest0474(ctx context.Context, reader io.Reader) (string, int64, error) {
	h := sha256.New()
	const maxFile = int64(1) << 40
	n, e := io.Copy(h, &io.LimitedReader{R: &contextReader0474{ctx, reader}, N: maxFile + 1})
	if e != nil {
		return "", 0, e
	}
	if n > maxFile {
		return "", n, errors.New("Размер файла превышает ограничение миграции 1 ТиБ")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type contextReader0474 struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader0474) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func verifyObject0474(ctx context.Context, store storage.Storage, obj fileObject0474) (bool, error) {
	r, size, e := store.Open(obj.project, obj.version, obj.path)
	if errors.Is(e, fs.ErrNotExist) || errors.Is(e, storage.ErrObjectNotFound) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer r.Close()
	if size != obj.size {
		return true, fmt.Errorf("object %s size differs: %d != %d", obj.path, size, obj.size)
	}
	h, n, e := fileDigest0474(ctx, r)
	if e != nil {
		return true, e
	}
	if n != obj.size || h != obj.hash {
		return true, fmt.Errorf("Несоответствие: объект %s SHA-256", obj.path)
	}
	return true, nil
}

// Перед открытием локального назначения отклонять символьные ссылки, даже когда объект
// уже существует с совпадающими байтами. Совпадающая ссылка за пределами корня хранилища
// не является допустимым доказательством владения целевым объектом.
func safeExistingLocal0474(local *storage.LocalStorage, obj fileObject0474) error {
	rel, e := filePath0474(obj.project, obj.version, obj.path)
	if e != nil {
		return e
	}
	root, e := filepath.Abs(local.RootPath())
	if e != nil {
		return e
	}
	cur := root
	candidates := append([]string{cur}, strings.Split(filepath.ToSlash(rel), "/")...)
	for i, part := range candidates {
		if i > 0 {
			cur = filepath.Join(cur, part)
		}
		st, er := os.Lstat(cur)
		if errors.Is(er, os.ErrNotExist) {
			return nil
		}
		if er != nil {
			return er
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in storage destination: %s", obj.path)
		}
		if i < len(candidates)-1 && !st.IsDir() {
			return fmt.Errorf("non-directory storage path %s", obj.path)
		}
	}
	return nil
}
func safeLocalObject0474(local *storage.LocalStorage, obj fileObject0474) error {
	rel, e := filePath0474(obj.project, obj.version, obj.path)
	if e != nil {
		return e
	}
	return noSymlinks0474(local.RootPath(), rel)
}

// atomicLocalSave0474 публикует проверенный файл без O_TRUNC и перехода по
// символьным ссылкам. Жёсткая ссылка из fsync-синхронизированного закрытого временного файла гарантирует, что
// конкурирующие писатели не перезапишут существующий объект.
func atomicLocalSave0474(ctx context.Context, dest *storage.LocalStorage, obj fileObject0474, source io.Reader) error {
	rel, e := filePath0474(obj.project, obj.version, obj.path)
	if e != nil {
		return e
	}
	root, e := filepath.Abs(dest.RootPath())
	if e != nil {
		return e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(root)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("Небезопасное значение: «destination storage root»")
	}
	parent := filepath.Dir(filepath.Join(root, rel))
	// Создавать каталоги по одному, отклоняя переход по символьным ссылкам.
	cur := root
	for _, part := range strings.Split(filepath.ToSlash(filepath.Dir(rel)), "/") {
		if part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		if e = os.Mkdir(cur, 0700); e != nil && !errors.Is(e, fs.ErrExist) {
			return e
		}
		st, e = os.Lstat(cur)
		if e != nil {
			return e
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("Небезопасное значение: «destination directory»")
		}
	}
	tmp, e := os.CreateTemp(parent, ".sqlite-import-*")
	if e != nil {
		return e
	}
	tempName := tmp.Name()
	defer os.Remove(tempName)
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(tmp, h), &io.LimitedReader{R: &contextReader0474{ctx, source}, N: obj.size + 1})
	if e == nil && (n != obj.size || hex.EncodeToString(h.Sum(nil)) != obj.hash) {
		e = errors.New("Хеш исходного файла изменился во время копирования")
	}
	if e == nil {
		e = tmp.Sync()
	}
	e = errors.Join(e, tmp.Close())
	if e != nil {
		return e
	}
	target := filepath.Join(root, rel)
	if e = os.Link(tempName, target); e != nil {
		return fmt.Errorf("«destination object»: запрещено «already exist:» %w", e)
	}
	dir, e := os.Open(parent)
	if e != nil {
		return e
	}
	e = errors.Join(dir.Sync(), dir.Close())
	return e
}

// CopyFileObjects0474 — явно офлайновое идемпотентное копирование для перенесённого
// SQLRepository. Источник и назначение должны быть изолированы от пишущих служб.
// Существующие совпадающие объекты принимаются; несовпадающие НИКОГДА не
// перезаписываются. Работает с LocalStorage и S3Storage и проверяет повторное чтение.
func CopyFileObjects0474(ctx context.Context, pgDSN string, src, dst storage.Storage) (report FileCopyReport0474, err error) {
	if src == nil || dst == nil || pgDSN == "" {
		return report, errors.New("Требуется: «database and both storage drivers»")
	}
	if l, ok := src.(*storage.LocalStorage); ok {
		if d, ok := dst.(*storage.LocalStorage); ok {
			a, _ := filepath.Abs(l.RootPath())
			b, _ := filepath.Abs(d.RootPath())
			if a == b {
				return report, errors.New("Корневые каталоги исходного и целевого хранилищ должны различаться")
			}
		}
	}
	report.Driver = dst.Driver()
	pg, e := pgx.Connect(ctx, pgDSN)
	if e != nil {
		return report, fmt.Errorf("PostgreSQL connection: %w", e)
	}
	defer pg.Close(context.Background())
	// Предварительная проверка только на чтение; частичная миграция не может сделать квитанцию достоверной.
	var sourceSHA string
	e = pg.QueryRow(ctx, `SELECT source_sha256 FROM sqlite_live_receipts_0473 ORDER BY created_at DESC LIMIT 1`).Scan(&sourceSHA)
	if e != nil {
		return report, fmt.Errorf("Требуется: «verified live import»: %w", e)
	}
	report.SourceSHA256 = sourceSHA
	rows, e := pg.Query(ctx, `SELECT project_id,version_id,path,size,sha256 FROM files ORDER BY project_id,version_id,path`)
	if e != nil {
		return report, e
	}
	objects := make([]fileObject0474, 0)
	for rows.Next() {
		var o fileObject0474
		if e = rows.Scan(&o.project, &o.version, &o.path, &o.size, &o.hash); e != nil {
			break
		}
		objects = append(objects, o)
	}
	e = errors.Join(e, rows.Err())
	rows.Close()
	if e != nil {
		return report, e
	}
	catalog, e := json.Marshal(objects)
	if e != nil {
		return report, e
	}
	catalogSHA := sha256.Sum256(catalog)
	report.CatalogSHA256 = hex.EncodeToString(catalogSHA[:])
	for _, o := range objects {
		if e = ctx.Err(); e != nil {
			return report, e
		}
		if o.size < 0 {
			return report, errors.New("Некорректное значение: «negative object size»")
		}
		if _, e = filePath0474(o.project, o.version, o.path); e != nil {
			return report, e
		}
		if len(o.hash) != 64 {
			return report, errors.New("Некорректное значение: «SHA-256 in files table»")
		}
		if _, e = hex.DecodeString(o.hash); e != nil {
			return report, e
		}
		if l, ok := src.(*storage.LocalStorage); ok {
			if e = safeLocalObject0474(l, o); e != nil {
				return report, e
			}
		}
		if l, ok := dst.(*storage.LocalStorage); ok {
			if e = safeExistingLocal0474(l, o); e != nil {
				return report, e
			}
		}
		exists, e := verifyObject0474(ctx, dst, o)
		if e != nil {
			return report, e
		}
		if exists {
			report.AlreadyPresent++
		} else {
			r, size, er := src.Open(o.project, o.version, o.path)
			if er != nil {
				return report, er
			}
			if size != o.size {
				r.Close()
				return report, fmt.Errorf("Несовпадение: «source object %s size»", o.path)
			}
			if local, ok := dst.(*storage.LocalStorage); ok {
				er = atomicLocalSave0474(ctx, local, o, r)
			} else {
				// Объекты S3 записываются только в замороженное назначение, затем
				// читаются обратно; неудачная удалённая запись никогда не выдаёт квитанцию.
				_, n, writeErr := dst.Save(o.project, o.version, o.path, &contextReader0474{ctx, r})
				er = writeErr
				if er == nil && n != o.size {
					er = errors.New("remote write truncated")
				}
			}
			er = errors.Join(er, r.Close())
			if er != nil {
				return report, er
			}
			report.Copied++
		}
		verified, er := verifyObject0474(ctx, dst, o)
		if er != nil || !verified {
			return report, fmt.Errorf("destination readback %s: %w", o.path, er)
		}
		report.Checked++
	}
	// Защита от конкуренции: изменяющийся файловый каталог нельзя сертифицировать.
	var liveCount int64
	if e = pg.QueryRow(ctx, `SELECT count(*) FROM files`).Scan(&liveCount); e != nil {
		return report, e
	}
	if liveCount != report.Checked {
		return report, errors.New("files catalog changed during copy")
	}
	// Проверить, что при том же количестве строк метаданные каталога не изменились.
	againRows, e := pg.Query(ctx, `SELECT project_id,version_id,path,size,sha256 FROM files ORDER BY project_id,version_id,path`)
	if e != nil {
		return report, e
	}
	again := make([]fileObject0474, 0, len(objects))
	for againRows.Next() {
		var obj fileObject0474
		if e = againRows.Scan(&obj.project, &obj.version, &obj.path, &obj.size, &obj.hash); e != nil {
			break
		}
		again = append(again, obj)
	}
	e = errors.Join(e, againRows.Err())
	againRows.Close()
	if e != nil {
		return report, e
	}
	currentJSON, e := json.Marshal(again)
	if e != nil {
		return report, e
	}
	if sha256.Sum256(currentJSON) != catalogSHA {
		return report, errors.New("files catalog content changed during copy")
	}
	report.Verified = true
	_, e = pg.Exec(ctx, `CREATE TABLE IF NOT EXISTS sqlite_file_receipts_0474(
       source_sha256 TEXT PRIMARY KEY,driver TEXT NOT NULL,objects BIGINT NOT NULL,
       catalog_sha256 TEXT NOT NULL DEFAULT '',
       verified_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
	if e != nil {
		report.Verified = false
		return report, e
	}
	// В старых квитанциях 0.47.4 отсутствует дайджест каталога. Их нужно повторно проверить
	// этой процедурой, а не молча принять как совпадающий каталог.
	_, e = pg.Exec(ctx, `ALTER TABLE sqlite_file_receipts_0474 ADD COLUMN IF NOT EXISTS catalog_sha256 TEXT NOT NULL DEFAULT ''`)
	if e != nil {
		report.Verified = false
		return report, e
	}
	_, e = pg.Exec(ctx, `INSERT INTO sqlite_file_receipts_0474(source_sha256,driver,objects,catalog_sha256)
      VALUES($1,$2,$3,$4) ON CONFLICT(source_sha256) DO UPDATE SET driver=excluded.driver,objects=excluded.objects,catalog_sha256=excluded.catalog_sha256,verified_at=now()`, sourceSHA, report.Driver, report.Checked, report.CatalogSHA256)
	if e != nil {
		report.Verified = false
		return report, e
	}
	return report, nil
}
