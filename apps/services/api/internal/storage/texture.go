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
		return "", errors.New("Некорректный дайджест текстуры")
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errors.New("Некорректный дайджест текстуры")
		}
	}
	return digest[:2] + "/" + digest + ".png", nil
}

// SaveTexture0252 пишет уже нормализованные байты по хешу содержимого. Локальные записи
// синхронизируются fsync и связываются атомарно, не давая параллельным загрузкам
// одного объекта раскрыть частично записанный PNG.
func SaveTexture0252(store Storage, digest string, png []byte) (string, int64, error) {
	path, err := texturePath0252(digest)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(png)
	if hex.EncodeToString(sum[:]) != digest {
		return "", 0, errors.New("Контрольная сумма текстуры не совпадает")
	}
	if local, ok := store.(*LocalStorage); ok {
		return local.saveTextureAtomic0252(path, png)
	}
	key, n, err := store.Save(textureProject0252, textureVersion0252, path, bytes.NewReader(png))
	if err != nil {
		return "", 0, err
	}
	if n != int64(len(png)) {
		return "", 0, fmt.Errorf("Не удалось полностью записать данные в хранилище текстур")
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
		// Проверять существующий неизменяемый объект, а не доверять его имени файла.
		existing, readErr := os.ReadFile(dest)
		if readErr != nil {
			return "", 0, readErr
		}
		existingSum := sha256.Sum256(existing)
		expected := sha256.Sum256(png)
		if existingSum != expected {
			return "", 0, errors.New("Несоответствие: дайджест текстуры объект")
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
