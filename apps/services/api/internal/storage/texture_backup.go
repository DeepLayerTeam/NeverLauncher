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

// TextureBackupObject0253 связывает проверенную запись БД с её неизменяемыми байтами.
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
		return errors.New("Некорректное значение: резервная копия текстур метаданные")
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
		return nil, errors.New("Размер резервной копии текстур не совпадает с ожидаемым")
	}
	payload, err := io.ReadAll(io.LimitReader(body, 4<<20+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	if int64(len(payload)) != obj.ByteSize || hex.EncodeToString(sum[:]) != obj.Digest {
		return nil, errors.New("Несовпадение контрольной суммы резервной копии текстур")
	}
	return payload, nil
}

// BackupTextures0253 записывает полный fsync-синхронизированный снимок во временный
// каталог и публикует его только после проверки всех удалённых/локальных объектов.
// Назначение не должно существовать; данные копии доступны только владельцу (0600).
func BackupTextures0253(ctx context.Context, store Storage, objects []TextureBackupObject0253, destination string) error {
	if destination == "" {
		return errors.New("Необходимо указать путь к резервной копии")
	}
	dest, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dest); err == nil {
		return errors.New("Целевой каталог резервной копии уже существует")
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
			return errors.New("Повторяющийся дайджест резервной копии текстур")
		}
		visited[obj.Digest] = true
		payload, err := backupBytes0253(store, obj)
		if err != nil {
			return fmt.Errorf("Ошибка резервного копирования %s: %w", obj.Digest, err)
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
		return errors.New("Место назначения резервной копии занято")
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

// RestoreTextures0253 требует актуального списка объектов БД для разрешения
// каждого восстановленного дайджеста; метаданные не импортируются и не перезаписываются из копии.
// Соответствующий снимок PostgreSQL вызывающий должен восстановить отдельно.
func RestoreTextures0253(ctx context.Context, store Storage, snapshot string, inventory []TextureBackupObject0253) (int, error) {
	// Читать недоверенный манифест без ограничения опасно: ReadFile выделяет память под
	// весь ввод до прежней проверки размера. Отклонять символьные ссылки и не-файлы.
	manifestPath := filepath.Join(snapshot, "manifest.json")
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return 0, errors.New("Небезопасное значение: «or oversized backup manifest»")
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
		return 0, errors.New("Манифест резервной копии превышает допустимый размер")
	}
	var man textureBackupManifest0253
	if err := json.Unmarshal(data, &man); err != nil {
		return 0, err
	}
	if man.Format != 1 {
		return 0, errors.New("Формат резервной копии текстур не поддерживается")
	}
	// Эта команда восстанавливает *полный* закреплённый набор объектов БД, а не
	// частичный набор best-effort, который может незаметно оставить рабочие профили без
	// текстур. Инкрементальное/частичное восстановление требует отдельного явного режима.
	allowed := make(map[string]TextureBackupObject0253, len(inventory))
	for _, b := range inventory {
		if err := validateBackupObject0253(store, b); err != nil {
			return 0, err
		}
		if _, duplicate := allowed[b.Digest]; duplicate {
			return 0, errors.New("Повторяющийся дайджест реестра базы данных")
		}
		allowed[b.Digest] = b
	}
	if len(man.Objects) != len(allowed) {
		return 0, fmt.Errorf("Неполный снимок текстур: в резервной копии %d объектов, в базе данных %d", len(man.Objects), len(allowed))
	}
	visited := make(map[string]bool, len(man.Objects))
	for _, obj := range man.Objects {
		if err := validateBackupObject0253(store, obj); err != nil {
			return 0, err
		}
		if visited[obj.Digest] {
			return 0, errors.New("Повторяющийся объект резервной копии")
		}
		visited[obj.Digest] = true
		if expected, ok := allowed[obj.Digest]; !ok || expected != obj {
			return 0, fmt.Errorf("Объект резервной копии %s не разрешён текущей базой данных", obj.Digest)
		}
	}
	// Предварительно проверять ВСЕ объекты до записи, избегая частичной записи при повреждённой копии.
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
			return restored, errors.New("Метаданные восстановленного объекта не совпадают")
		}
		// Не доверять только результату операции записи хранилища. Повторно прочитать
		// через настроенный локальный/S3 путь и проверить всё содержимое.
		if verification := VerifyTexture02511(ctx, store, obj); verification.Result != "ok" {
			return restored, fmt.Errorf("Не удалось проверить чтением восстановленную текстуру %s: %s (%s)", obj.Digest, verification.Result, verification.Detail)
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
		return errors.New("Несовпадение: «backup object not regular or size»")
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
		return errors.New("Несовпадение контрольной суммы файла резервной копии")
	}
	return nil
}
