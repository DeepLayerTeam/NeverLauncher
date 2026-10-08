package storage

import (
	"context"
	"io"
)

// Storage описывает backend-хранилище файлов клиентских сборок.
type Storage interface {
	// Driver возвращает имя активного драйвера хранилища.
	Driver() string
	// Save сохраняет файл сборки и возвращает внутренний ключ объекта и размер.
	Save(projectID, versionID, relativePath string, reader io.Reader) (string, int64, error)
	// Open открывает файл сборки для выдачи через Backend API.
	Open(projectID, versionID, relativePath string) (io.ReadCloser, int64, error)
	// Health проверяет доступность backend-хранилища.
	Health(ctx context.Context) error
}
