package extensionlifecycle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionpackage"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// checkRollbackPayload0305 гарантирует, что локальная резервная копия Java по-прежнему
// точно соответствует исходному неизменяемому артефакту Registry с проверенной подписью.
// Одним байтам копии не доверяют.
func (m *Manager) checkRollbackPayload0305(ctx context.Context, scope Scope, id, version, identity, staged string, manifest model.ExtensionManifest) error {
	// Каждая подписанная цель (Java, Go, UI, CLI, Desktop) должна восстанавливать
	// точно исходные байты пакета, а не просто корректный манифест/версию. Старые
	// локальные резервные копии без подписанной идентичности обрабатываются
	// вызывающей стороной.
	if identity == "" {
		return nil
	}
	original, err := m.Repo.GetExtensionRegistryVersion(ctx, id, version)
	if err != nil {
		return fmt.Errorf("Подписанная публикация для отката Java недоступна: %w", err)
	}
	if original.Artifact.PackageIdentity != identity {
		return errors.New("Несовпадение идентификатора подписанного выпуска для отката Java")
	}
	prepared, err := m.prepareArtifact0204(ctx, original)
	if err != nil {
		return fmt.Errorf("Ошибка проверки артефакта для подписанного отката Java: %w", err)
	}
	defer os.Remove(prepared.Path)
	pristine, err := makeStage0204(m.Root, scope, id)
	if err != nil {
		return err
	}
	defer os.RemoveAll(pristine)
	if _, err := extensionpackage.ExtractPayloadFile(prepared.Path, pristine, identity); err != nil {
		return err
	}
	actual, err := digestPayload0305(staged)
	if err != nil {
		return err
	}
	expected, err := digestPayload0305(pristine)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("Локальная резервная копия Java отличается от проверенного подписанного выпуска")
	}
	return nil
}

func digestPayload0305(root string) ([32]byte, error) {
	h := sha256.New()
	count := 0
	var total int64
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filename == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Резервная копия содержит символическую ссылку")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("Резервная копия содержит специальный файл")
		}
		count++
		total += info.Size()
		if count > 8192 || total > 512<<20 {
			return errors.New("Размер резервной копии превышает лимит сравнения")
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(h, filepath.ToSlash(rel)+"\x00"); err != nil {
			return err
		}
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(h, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if _, err := io.WriteString(h, "\x00"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}
	if count == 0 {
		return [32]byte{}, errors.New("Содержимое резервной копии пусто")
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
