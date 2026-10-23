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
	"strings"
	"time"
)

// PutTextureImmutable0253 ensures that an existing digest-keyed blob is NEVER
// overwritten on S3. A conflict is accepted only after verifying the remote
// bytes, including their digest. The local implementation uses atomic hardlink.
func PutTextureImmutable0253(ctx context.Context, store Storage, digest string, png []byte) (string, int64, error) {
	rel, err := texturePath0252(digest)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(png)
	if hex.EncodeToString(sum[:]) != digest {
		return "", 0, errors.New("texture SHA-256 mismatch")
	}
	if len(png) == 0 || len(png) > 4<<20 {
		return "", 0, errors.New("invalid texture payload size")
	}
	if s3, ok := store.(*S3Storage); ok {
		key, err := objectKey(textureProject0252, textureVersion0252, rel)
		if err != nil {
			return "", 0, err
		}
		hdr := http.Header{}
		hdr.Set("If-None-Match", "*")
		hdr.Set("Content-Type", "image/png")
		hdr.Set("Cache-Control", "public, max-age=31536000, immutable")
		putCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		req, err := s3.newSignedRequestWithHeaders0253(putCtx, http.MethodPut, key, bytes.NewReader(png), int64(len(png)), digest, hdr)
		if err != nil {
			return "", 0, err
		}
		resp, err := s3.client.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("S3 texture write: %w", err)
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return key, int64(len(png)), nil
		case resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusConflict:
			// Conflicting, immutable object may be corrupt: verify before deduplicating.
			body, size, err := OpenTexture0252(s3, digest)
			if err != nil {
				return "", 0, fmt.Errorf("S3 texture collision read: %w", err)
			}
			defer body.Close()
			found, err := io.ReadAll(io.LimitReader(body, 4<<20+1))
			if err != nil || size > 4<<20 || !bytes.Equal(found, png) {
				return "", 0, errors.New("S3 digest collision or corrupted immutable object")
			}
			return key, int64(len(png)), nil
		default:
			errorBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return "", 0, fmt.Errorf("S3 texture write HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errorBody)))
		}
	}
	return SaveTexture0252(store, digest, png)
}

// DeleteTexture0253 is idempotent. It accepts only SHA-256 texture object keys.
// Calling it requires a database GC lease; user-controlled requests cannot call it.
func DeleteTexture0253(ctx context.Context, store Storage, digest string) error {
	rel, err := texturePath0252(digest)
	if err != nil {
		return err
	}
	if local, ok := store.(*LocalStorage); ok {
		filePath, _, err := local.objectPath(textureProject0252, textureVersion0252, rel)
		if err != nil {
			return err
		}
		// A symlink, unexpected file type or tampered file must not be followed/deleted.
		info, err := os.Lstat(filePath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("texture object is not a regular file")
		}
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		sum := sha256.New()
		n, readErr := io.Copy(sum, io.LimitReader(f, 4<<20+1))
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n > 4<<20 || hex.EncodeToString(sum.Sum(nil)) != digest {
			return errors.New("texture file corrupted, refusing GC")
		}
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if dir, err := os.Open(filepath.Dir(filePath)); err == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
		return nil
	}
	s3, ok := store.(*S3Storage)
	if !ok {
		return errors.New("texture GC requires local or S3 storage")
	}
	key, err := objectKey(textureProject0252, textureVersion0252, rel)
	if err != nil {
		return err
	}
	deleteCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := s3.newSignedRequest(deleteCtx, http.MethodDelete, key, nil, 0)
	if err != nil {
		return err
	}
	resp, err := s3.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("S3 texture delete HTTP %d", resp.StatusCode)
}
