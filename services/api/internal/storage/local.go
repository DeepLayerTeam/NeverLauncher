package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LocalStorage хранит файлы клиентских сборок на локальной файловой системе.
type LocalStorage struct {
	root string
}

// NewLocalStorage создаёт локальное хранилище файлов.
func NewLocalStorage(root string) *LocalStorage {
	if root == "" {
		root = "./data/storage"
	}
	return &LocalStorage{root: filepath.Clean(root)}
}

func (s *LocalStorage) Driver() string { return "local" }

// RootPath возвращает canonical local-storage root для maintenance restore.
func (s *LocalStorage) RootPath() string { return s.root }

func (s *LocalStorage) Save(projectID, versionID, relativePath string, reader io.Reader) (string, int64, error) {
	path, key, err := s.objectPath(projectID, versionID, relativePath)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, fmt.Errorf("не удалось создать каталог хранилища: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", 0, fmt.Errorf("не удалось открыть файл для записи: %w", err)
	}
	defer file.Close()

	size, err := io.Copy(file, reader)
	if err != nil {
		return "", size, fmt.Errorf("не удалось сохранить файл: %w", err)
	}
	return key, size, nil
}

func (s *LocalStorage) Open(projectID, versionID, relativePath string) (io.ReadCloser, int64, error) {
	path, _, err := s.objectPath(projectID, versionID, relativePath)
	if err != nil {
		return nil, 0, err
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, fs.ErrNotExist
		}
		return nil, 0, fmt.Errorf("не удалось открыть файл: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, fmt.Errorf("не удалось прочитать параметры файла: %w", err)
	}
	return file, info.Size(), nil
}

func (s *LocalStorage) Health(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := os.MkdirAll(s.root, 0o755); err != nil {
		return fmt.Errorf("локальное хранилище недоступно: %w", err)
	}
	probe, err := os.CreateTemp(s.root, ".neverlauncher-health-*")
	if err != nil {
		return fmt.Errorf("не удалось создать проверочный файл хранилища: %w", err)
	}
	name := probe.Name()
	if _, err := probe.WriteString("ok"); err != nil {
		probe.Close()
		_ = os.Remove(name)
		return fmt.Errorf("не удалось записать проверочный файл хранилища: %w", err)
	}
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("не удалось закрыть проверочный файл хранилища: %w", err)
	}
	return os.Remove(name)
}

func (s *LocalStorage) objectPath(projectID, versionID, relativePath string) (string, string, error) {
	projectID, err := safeSegment(projectID, "projectId")
	if err != nil {
		return "", "", err
	}
	versionID, err = safeSegment(versionID, "version")
	if err != nil {
		return "", "", err
	}
	relativePath, err = safeRelativePath(relativePath)
	if err != nil {
		return "", "", err
	}
	key := filepath.ToSlash(filepath.Join(projectID, versionID, relativePath))
	fullPath := filepath.Join(s.root, filepath.FromSlash(key))
	rootAbs, err := filepath.Abs(s.root)
	if err != nil {
		return "", "", err
	}
	fullAbs, err := filepath.Abs(fullPath)
	if err != nil {
		return "", "", err
	}
	if fullAbs != rootAbs && !strings.HasPrefix(fullAbs, rootAbs+string(os.PathSeparator)) {
		return "", "", errors.New("путь выходит за пределы хранилища")
	}
	return fullAbs, key, nil
}

func safeSegment(value, name string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s обязателен", name)
	}
	if strings.Contains(value, "/") || strings.Contains(value, "\\") || value == "." || value == ".." || strings.Contains(value, "..") {
		return "", fmt.Errorf("%s содержит недопустимые символы", name)
	}
	return value, nil
}

func safeRelativePath(value string) (string, error) {
	value = strings.TrimSpace(filepath.ToSlash(value))
	if value == "" || value == "." {
		return "", errors.New("path обязателен")
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return "", errors.New("path должен быть относительным POSIX-путём")
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, "/../") {
		return "", errors.New("path выходит за пределы хранилища")
	}
	return clean, nil
}
