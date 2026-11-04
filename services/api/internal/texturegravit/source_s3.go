package texturegravit

import (
	"context"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"io"
)

// S3Source читает объекты по доверенному ключу хранилища с настройками оператора.
// учётных данных источника. Публичный HTTP URL не загружается.
type S3Source struct{ Store *storage.S3Storage }

func (s S3Source) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ValidateObjectKey(key); err != nil {
		return nil, err
	}
	return s.Store.OpenGravitSourceObject02510(ctx, key)
}
