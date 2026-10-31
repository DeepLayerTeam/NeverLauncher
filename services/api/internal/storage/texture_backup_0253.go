package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// TextureBackupObject0253 binds a verified database row to its immutable bytes.
type TextureBackupObject0253 struct {
	Digest    string `json:"digest"`
	ByteSize  int64  `json:"byteSize"`
	Driver    string `json:"driver"`
	ObjectKey string `json:"objectKey"`
}
type textureBackupManifest0253 struct {
	Format    int                       `json:"format"`
	CreatedAt time.Time                 `json:"createdAt"`
	Objects   []TextureBackupObject0253 `json:"objects"`
}

func validateBackupObject0253(store Storage, b TextureBackupObject0253) error {
	rel, err := texturePath0252(b.Digest)
	if err != nil {
		return err
	}
	want, err := objectKey(textureProject0252, textureVersion0252, rel)
	if err != nil {
		return err
	}
	if b.Driver != store.Driver() || b.ObjectKey != want || b.ByteSize < 1 || b.ByteSize > 4<<20 {
		return errors.New("invalid texture backup metadata")
	}
	return nil
}

func backupBytes0253(store Storage, obj TextureBackupObject0253) ([]byte, error) {
	if err := validateBackupObject0253(store, obj); err != nil {
		return nil, err
	}
	body, sz, err := OpenTexture0252(store, obj.Digest)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if sz >= 0 && sz != obj.ByteSize {
		return nil, errors.New("texture backup size mismatch")
	}
	payload, err := io.ReadAll(io.LimitReader(body, 4<<20+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	if int64(len(payload)) != obj.ByteSize || hex.EncodeToString(sum[:]) != obj.Digest {
		return nil, errors.New("texture backup checksum mismatch")
	}
	return payload, nil
}

// BackupTextures0253 writes a complete fsynced snapshot in a temporary
// directory and only publishes it after verifying all remote/local objects.
// The destination must not already exist; backup data are owner-only (0600).
func BackupTextures0253(ctx context.Context, store Storage, objects []TextureBackupObject0253, destination string) error {
	if destination == "" {
		return errors.New("backup path required")
	}
	dest, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dest); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(dest), ".launcher-texture-backup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0700); err != nil {
		return err
	}
	blobs := filepath.Join(stage, "blobs")
	if err := os.Mkdir(blobs, 0700); err != nil {
		return err
	}
	visited := make(map[string]bool, len(objects))
	for _, obj := range objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visited[obj.Digest] {
			return errors.New("duplicate texture backup digest")
		}
		visited[obj.Digest] = true
		payload, err := backupBytes0253(store, obj)
		if err != nil {
			return fmt.Errorf("backup %s: %w", obj.Digest, err)
		}
		f, err := os.OpenFile(filepath.Join(blobs, obj.Digest+".png"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(payload)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	man := textureBackupManifest0253{Format: 1, CreatedAt: time.Now().UTC(), Objects: objects}
	file, err := os.OpenFile(filepath.Join(stage, "manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	err = enc.Encode(man)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := syncDirectory0253(blobs); err != nil {
		return err
	}
	if err := syncDirectory0253(stage); err != nil {
		return err
	}
	if _, err := os.Lstat(dest); err == nil {
		return errors.New("backup destination occupied")
	}
	if err := os.Rename(stage, dest); err != nil {
		return err
	}
	return syncDirectory0253(filepath.Dir(dest))
}

func syncDirectory0253(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// RestoreTextures0253 requires the current database inventory to authorize
// each restored digest; metadata is not imported or overwritten from a backup.
// The caller must restore the matching PostgreSQL snapshot separately.
func RestoreTextures0253(ctx context.Context, store Storage, snapshot string, inventory []TextureBackupObject0253) (int, error) {
	// Never read an untrusted manifest without a bound: ReadFile allocates the
	// entire input before the legacy size check. Reject symlinks and non-files.
	manifestPath := filepath.Join(snapshot, "manifest.json")
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return 0, errors.New("unsafe or oversized backup manifest")
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return 0, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 16<<20+1))
	closeErr := f.Close()
	if readErr != nil {
		return 0, readErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if len(data) > 16<<20 {
		return 0, errors.New("backup manifest too large")
	}
	var man textureBackupManifest0253
	if err := json.Unmarshal(data, &man); err != nil {
		return 0, err
	}
	if man.Format != 1 {
		return 0, errors.New("unsupported texture backup format")
	}
	// This command restores a *complete*, pinned database inventory, not a
	// best-effort subset that could silently leave live profiles with missing
	// textures. Incremental/partial recovery needs a separate explicit mode.
	allowed := make(map[string]TextureBackupObject0253, len(inventory))
	for _, b := range inventory {
		if err := validateBackupObject0253(store, b); err != nil {
			return 0, err
		}
		if _, duplicate := allowed[b.Digest]; duplicate {
			return 0, errors.New("duplicate database inventory digest")
		}
		allowed[b.Digest] = b
	}
	if len(man.Objects) != len(allowed) {
		return 0, fmt.Errorf("incomplete texture snapshot: backup has %d objects, database has %d", len(man.Objects), len(allowed))
	}
	visited := make(map[string]bool, len(man.Objects))
	for _, obj := range man.Objects {
		if err := validateBackupObject0253(store, obj); err != nil {
			return 0, err
		}
		if visited[obj.Digest] {
			return 0, errors.New("duplicate backup object")
		}
		visited[obj.Digest] = true
		if expected, ok := allowed[obj.Digest]; !ok || expected != obj {
			return 0, fmt.Errorf("backup object %s not authorized by current database", obj.Digest)
		}
	}
	// Preflight ALL objects before writing any, avoiding partial writes on corrupt backup.
	for _, obj := range man.Objects {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := checkRestoreFile0253(snapshot, obj); err != nil {
			return 0, err
		}
	}
	restored := 0
	for _, obj := range man.Objects {
		if err := ctx.Err(); err != nil {
			return restored, err
		}
		payload, err := os.ReadFile(filepath.Join(snapshot, "blobs", obj.Digest+".png"))
		if err != nil {
			return restored, err
		}
		key, n, err := RestoreTextureObject0253(ctx, store, obj.Digest, payload)
		if err != nil {
			return restored, err
		}
		if key != obj.ObjectKey || n != obj.ByteSize {
			return restored, errors.New("restored object metadata differs")
		}
		// Do not trust the return value of a storage write alone. Read back
		// through the configured local/S3 path and check the full content.
		if verification := VerifyTexture02511(ctx, store, obj); verification.Result != "ok" {
			return restored, fmt.Errorf("restored texture %s failed readback: %s (%s)", obj.Digest, verification.Result, verification.Detail)
		}
		restored++
	}
	return restored, nil
}
func checkRestoreFile0253(snapshot string, obj TextureBackupObject0253) error {
	path := filepath.Join(snapshot, "blobs", obj.Digest+".png")
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != obj.ByteSize {
		return errors.New("backup object not regular or size mismatch")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, 4<<20+1))
	if err != nil {
		return err
	}
	if n != obj.ByteSize || hex.EncodeToString(hash.Sum(nil)) != obj.Digest {
		return errors.New("backup file checksum mismatch")
	}
	return nil
}
