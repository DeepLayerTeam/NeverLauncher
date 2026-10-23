package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TextureVerification02511 is an operator-visible integrity check of a
// database-registered immutable object. It does not trust object ETags as hashes.
type TextureVerification02511 struct {
	Digest string `json:"digest"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

func VerifyTexture02511(ctx context.Context, store Storage, obj TextureBackupObject0253) TextureVerification02511 {
	result := TextureVerification02511{Digest: obj.Digest, Result: "corrupt"}
	if err := ctx.Err(); err != nil {
		result.Result = "cancelled"
		result.Detail = err.Error()
		return result
	}
	if err := validateBackupObject0253(store, obj); err != nil {
		result.Detail = err.Error()
		return result
	}
	f, size, err := OpenTexture0252(store, obj.Digest)
	if err != nil {
		result.Result = "unavailable"
		result.Detail = err.Error()
		return result
	}
	defer f.Close()
	if size >= 0 && size != obj.ByteSize {
		result.Detail = "object length differs from database"
		return result
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&contextTextureReader02511{ctx: ctx, reader: f}, 4<<20+1))
	if err != nil {
		result.Result = "unavailable"
		result.Detail = err.Error()
		return result
	}
	if n != obj.ByteSize || hex.EncodeToString(h.Sum(nil)) != obj.Digest {
		result.Detail = "SHA-256 or byte length differs from database"
		return result
	}
	result.Result = "ok"
	return result
}

type contextTextureReader02511 struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextTextureReader02511) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

// DeleteTextureSafely02511 verifies S3 bytes *and* deletes conditionally using
// the exact ETag observed on read. This prevents an outdated GC worker from
// deleting a replacement object after the checksum validation.
func DeleteTextureSafely02511(ctx context.Context, store Storage, digest string) error {
	if _, err := texturePath0252(digest); err != nil {
		return err
	}
	s3, ok := store.(*S3Storage)
	if !ok {
		return DeleteTexture0253(ctx, store, digest)
	}
	rel, _ := texturePath0252(digest)
	key, err := objectKey(textureProject0252, textureVersion0252, rel)
	if err != nil {
		return err
	}
	readCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := s3.newSignedRequest(readCtx, http.MethodGet, key, nil, 0)
	if err != nil {
		return err
	}
	resp, err := s3.client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 GC read: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("S3 GC read HTTP %d", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if len(etag) < 3 || len(etag) > 256 || !strings.HasPrefix(etag, "\"") || !strings.HasSuffix(etag, "\"") {
		resp.Body.Close()
		return errors.New("S3 GC requires a strong object ETag")
	}
	dataHash := sha256.New()
	n, readErr := io.Copy(dataHash, io.LimitReader(resp.Body, 4<<20+1))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n < 1 || n > 4<<20 || hex.EncodeToString(dataHash.Sum(nil)) != digest {
		return errors.New("S3 texture corruption: GC stopped; restore from backup before deletion")
	}
	headers := http.Header{}
	headers.Set("If-Match", etag)
	deleteCtx, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	del, err := s3.newSignedRequestWithHeaders0253(deleteCtx, http.MethodDelete, key, nil, 0, sha256Hex(nil), headers)
	if err != nil {
		return err
	}
	response, err := s3.client.Do(del)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	case http.StatusPreconditionFailed, http.StatusConflict:
		return errors.New("S3 GC conditional delete failed: object changed")
	default:
		return fmt.Errorf("S3 GC delete HTTP %d", response.StatusCode)
	}
}
