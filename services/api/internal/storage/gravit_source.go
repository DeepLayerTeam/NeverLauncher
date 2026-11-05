package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenGravitSourceObject02510 читает сырой ключ из явно настроенного
// доверенного исходного bucket S3 с обычной реализацией SigV4. Недоверенные
// URL Gravit file_url ДОЛЖНЫ передаваться сюда или загружаться напрямую.
func (s *S3Storage) OpenGravitSourceObject02510(ctx context.Context, key string) (io.ReadCloser, error) {
	if key == "" || len(key) > 512 || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.ContainsAny(key, "\x00\r\n") {
		return nil, errors.New("Некорректное значение: ключ объекта S3")
	}
	for _, piece := range strings.Split(key, "/") {
		if piece == "" || piece == "." || piece == ".." {
			return nil, errors.New("Небезопасный объект: ключ объекта S3")
		}
	}
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	req, err := s.newSignedRequest(requestCtx, http.MethodGet, key, nil, 0)
	if err != nil {
		cancel()
		return nil, err
	}
	// Не перенаправлять подписанный запрос на хост, указанный в HTTP-ответе S3.
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		cancel()
		return nil, fmt.Errorf("Ошибка получения исходного объекта S3: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > 4<<20 {
		res.Body.Close()
		cancel()
		return nil, errors.New("Исходный объект S3 превышает 4 МиБ")
	}
	return &cancelReadCloser{ReadCloser: res.Body, cancel: cancel}, nil
}
