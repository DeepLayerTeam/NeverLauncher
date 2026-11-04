package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// RestoreTextureObject0253 is deliberately *not* called by HTTP uploads. It
// repairs a corrupt existing object only during an operator-validated restore.
// Recovery checks every byte and uses atomic local rename or S3 If-Match CAS.
func RestoreTextureObject0253(ctx context.Context, store Storage, digest string, png []byte) (string, int64, error) {
	rel, err := texturePath0252(digest)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.Sum256(png)
	if hex.EncodeToString(hash[:]) != digest || len(png) < 1 || len(png) > 4<<20 {
		return "", 0, errors.New("restore data failed SHA-256 verification")
	}
	if _, ok := store.(*S3Storage); ok {
		return restoreS3Texture0253(ctx, store.(*S3Storage), digest, rel, png)
	}
	local, ok := store.(*LocalStorage)
	if !ok {
		return "", 0, errors.New("unsupported repair storage")
	}
	filePath, key, err := local.objectPath(textureProject0252, textureVersion0252, rel)
	if err != nil {
		return "", 0, err
	}
	info, err := os.Lstat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return PutTextureImmutable0253(ctx, store, digest, png)
	}
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, errors.New("unsafe existing texture object")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return "", 0, err
	}
	existing, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
	closeErr := f.Close()
	if err != nil {
		return "", 0, err
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	if bytes.Equal(existing, png) {
		return key, int64(len(png)), nil
	}
	// Prepare the verified replacement fully before publishing it. Rename is a
	// single atomic transition for concurrent readers: a process crash cannot
	// strand the digest without a readable object between two renames.
	tmp, err := os.CreateTemp(filepath.Dir(filePath), ".texture-repair-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(png); err != nil {
		tmp.Close()
		return "", 0, err
	}
	if err = tmp.Chmod(0644); err != nil {
		tmp.Close()
		return "", 0, err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return "", 0, err
	}
	if err = tmp.Close(); err != nil {
		return "", 0, err
	}
	if err = os.Rename(tmp.Name(), filePath); err != nil {
		return "", 0, err
	}
	if err = syncDirectory0253(filepath.Dir(filePath)); err != nil {
		return "", 0, err
	}
	return key, int64(len(png)), nil
}

func restoreS3Texture0253(ctx context.Context, s3 *S3Storage, digest, rel string, png []byte) (string, int64, error) {
	key, err := objectKey(textureProject0252, textureVersion0252, rel)
	if err != nil {
		return "", 0, err
	}
	readCtx, readCancel := context.WithTimeout(ctx, 45*time.Second)
	defer readCancel()
	get, err := s3.newSignedRequest(readCtx, http.MethodGet, key, nil, 0)
	if err != nil {
		return "", 0, err
	}
	res, err := s3.client.Do(get)
	if err != nil {
		return "", 0, err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return PutTextureImmutable0253(ctx, s3, digest, png)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return "", 0, fmt.Errorf("S3 recovery read HTTP %d", res.StatusCode)
	}
	etag := res.Header.Get("ETag")
	existing, readErr := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
	closeErr := res.Body.Close()
	if readErr != nil {
		return "", 0, readErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	if bytes.Equal(existing, png) {
		return key, int64(len(png)), nil
	}
	if etag == "" || len(etag) > 256 {
		return "", 0, errors.New("corrupt S3 object has no usable ETag for conditional recovery")
	}
	hdr := http.Header{}
	hdr.Set("If-Match", etag)
	hdr.Set("Content-Type", "image/png")
	hdr.Set("Cache-Control", "public, max-age=31536000, immutable")
	putCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := s3.newSignedRequestWithHeaders0253(putCtx, http.MethodPut, key, bytes.NewReader(png), int64(len(png)), digest, hdr)
	if err != nil {
		return "", 0, err
	}
	update, err := s3.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer update.Body.Close()
	if update.StatusCode < 200 || update.StatusCode >= 300 {
		return "", 0, fmt.Errorf("S3 conditional recovery HTTP %d", update.StatusCode)
	}
	// Verify the full replacement through the object endpoint, not only PUT 200.
	blob, sz, err := OpenTexture0252(s3, digest)
	if err != nil {
		return "", 0, err
	}
	defer blob.Close()
	recovered, err := io.ReadAll(io.LimitReader(blob, 4<<20+1))
	if err != nil {
		return "", 0, err
	}
	if (sz >= 0 && sz != int64(len(png))) || !bytes.Equal(recovered, png) {
		return "", 0, errors.New("S3 recovered object failed readback verification")
	}
	return key, int64(len(png)), nil
}
