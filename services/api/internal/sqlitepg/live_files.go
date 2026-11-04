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

// FileCopyReport0474 is written only after each file has been read back and
// cryptographically verified from the destination backend.
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

// Canonical catalog serialization must include values, not merely a row
// count. The unexported fileObject fields would otherwise marshal as {}.
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
			return "", errors.New("unsafe project/version segment")
		}
	}
	if rel == "" || strings.HasPrefix(rel, "/") || strings.ContainsAny(rel, "\\\x00") || strings.Contains(rel, "//") {
		return "", errors.New("unsafe file path")
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
		return errors.New("unsafe storage root")
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
		return "", n, errors.New("file exceeds 1 TiB migration limit")
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
		return true, fmt.Errorf("object %s SHA-256 mismatch", obj.path)
	}
	return true, nil
}

// Before opening a local destination, reject symlinks even if the object
// currently exists with matching bytes. A matching link outside the storage
// root is not an acceptable proof of ownership of the destination object.
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

// atomicLocalSave0474 publishes a verified file without O_TRUNC or following
// symlinks. A hardlink from an fsynced private temporary file guarantees that
// concurrent writers cannot overwrite an existing object.
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
		return errors.New("unsafe destination storage root")
	}
	parent := filepath.Dir(filepath.Join(root, rel))
	// Create directories one at a time, refusing symlink traversal.
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
			return errors.New("unsafe destination directory")
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
		e = errors.New("source file digest mismatch while copying")
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
		return fmt.Errorf("destination object must not already exist: %w", e)
	}
	dir, e := os.Open(parent)
	if e != nil {
		return e
	}
	e = errors.Join(dir.Sync(), dir.Close())
	return e
}

// CopyFileObjects0474 is an explicitly offline, idempotent copy for a migrated
// SQLRepository. Source and destination must be isolated from service writers.
// Existing matching objects are accepted; mismatching objects are NEVER
// overwritten. It works with LocalStorage and S3Storage and verifies readback.
func CopyFileObjects0474(ctx context.Context, pgDSN string, src, dst storage.Storage) (report FileCopyReport0474, err error) {
	if src == nil || dst == nil || pgDSN == "" {
		return report, errors.New("database and both storage drivers required")
	}
	if l, ok := src.(*storage.LocalStorage); ok {
		if d, ok := dst.(*storage.LocalStorage); ok {
			a, _ := filepath.Abs(l.RootPath())
			b, _ := filepath.Abs(d.RootPath())
			if a == b {
				return report, errors.New("source and destination storage roots must differ")
			}
		}
	}
	report.Driver = dst.Driver()
	pg, e := pgx.Connect(ctx, pgDSN)
	if e != nil {
		return report, fmt.Errorf("PostgreSQL connection: %w", e)
	}
	defer pg.Close(context.Background())
	// Read-only preflight; no partial migration can make the receipt claim true.
	var sourceSHA string
	e = pg.QueryRow(ctx, `SELECT source_sha256 FROM sqlite_live_receipts_0473 ORDER BY created_at DESC LIMIT 1`).Scan(&sourceSHA)
	if e != nil {
		return report, fmt.Errorf("verified live import required: %w", e)
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
			return report, errors.New("invalid negative object size")
		}
		if _, e = filePath0474(o.project, o.version, o.path); e != nil {
			return report, e
		}
		if len(o.hash) != 64 {
			return report, errors.New("invalid SHA-256 in files table")
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
				return report, fmt.Errorf("source object %s size mismatch", o.path)
			}
			if local, ok := dst.(*storage.LocalStorage); ok {
				er = atomicLocalSave0474(ctx, local, o, r)
			} else {
				// S3 objects are written only on a frozen destination, then
				// read back; a failed remote write never yields a receipt.
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
	// Concurrency protection: a changing file catalog cannot be certified.
	var liveCount int64
	if e = pg.QueryRow(ctx, `SELECT count(*) FROM files`).Scan(&liveCount); e != nil {
		return report, e
	}
	if liveCount != report.Checked {
		return report, errors.New("files catalog changed during copy")
	}
	// Verify that no catalog metadata changed with the same row count.
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
	// Old 0.47.4 receipts lack the catalog digest. They must be reverified
	// by this routine rather than silently accepted as a matching catalog.
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
