package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const textureProject0252 = "texture-blobs"
const textureVersion0252 = "sha256"

func texturePath0252(digest string) (string, error) {
	if len(digest) != 64 {
		return "", errors.New("invalid texture digest")
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errors.New("invalid texture digest")
		}
	}
	return digest[:2] + "/" + digest + ".png", nil
}

// SaveTexture0252 writes already-normalized bytes by content hash. Local writes
// are fsynced and linked atomically, preventing simultaneous uploads of the
// same object from exposing a partially-written PNG.
func SaveTexture0252(store Storage, digest string, png []byte) (string, int64, error) {
	path, err := texturePath0252(digest)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(png)
	if hex.EncodeToString(sum[:]) != digest {
		return "", 0, errors.New("texture checksum mismatch")
	}
	if local, ok := store.(*LocalStorage); ok {
		return local.saveTextureAtomic0252(path, png)
	}
	key, n, err := store.Save(textureProject0252, textureVersion0252, path, bytes.NewReader(png))
	if err != nil {
		return "", 0, err
	}
	if n != int64(len(png)) {
		return "", 0, fmt.Errorf("texture storage short write")
	}
	return key, n, nil
}

func (s *LocalStorage) saveTextureAtomic0252(path string, png []byte) (string, int64, error) {
	dest, key, err := s.objectPath(textureProject0252, textureVersion0252, path)
	if err != nil {
		return "", 0, err
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".png-upload-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(png); err != nil {
		return "", 0, err
	}
	if err = tmp.Chmod(0o644); err != nil {
		return "", 0, err
	}
	if err = tmp.Sync(); err != nil {
		return "", 0, err
	}
	if err = tmp.Close(); err != nil {
		return "", 0, err
	}
	if err = os.Link(tmp.Name(), dest); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", 0, err
		}
		// Validate existing immutable object instead of trusting its filename.
		existing, readErr := os.ReadFile(dest)
		if readErr != nil {
			return "", 0, readErr
		}
		existingSum := sha256.Sum256(existing)
		expected := sha256.Sum256(png)
		if existingSum != expected {
			return "", 0, errors.New("texture digest object mismatch")
		}
	}
	if dir, err := os.Open(filepath.Dir(dest)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return key, int64(len(png)), nil
}

func OpenTexture0252(store Storage, digest string) (io.ReadCloser, int64, error) {
	path, err := texturePath0252(digest)
	if err != nil {
		return nil, 0, err
	}
	return store.Open(textureProject0252, textureVersion0252, path)
}
