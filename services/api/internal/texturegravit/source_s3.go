package texturegravit

import (
	"context"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
	"io"
)

// S3Source reads objects by trusted storage key using the operator-configured
// source credentials. No public HTTP URL is fetched.
type S3Source struct{ Store *storage.S3Storage }

func (s S3Source) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ValidateObjectKey(key); err != nil {
		return nil, err
	}
	return s.Store.OpenGravitSourceObject02510(ctx, key)
}
