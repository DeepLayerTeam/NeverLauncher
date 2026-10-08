package storage

import (
	"context"
	"io"
)

// Хранилище описывает backend-хранилище файлов клиентских сборок.
type Storage interface {
	// Драйвер возвращает имя активного драйвера хранилища.
	Driver() string
	// Сохранение сохраняет файл сборки и возвращает внутренний ключ объекта и размер.
	Save(projectID, versionID, relativePath string, reader io.Reader) (string, int64, error)
	// Открытый открывает файл сборки для выдачи через Серверная часть API.
	Open(projectID, versionID, relativePath string) (io.ReadCloser, int64, error)
	// Работоспособность проверяет доступность backend-хранилища.
	Health(ctx context.Context) error
}
