package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// S3Config описывает параметры S3-совместимого хранилища.
type S3Config struct {
	Endpoint  string
	PublicURL string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	PathStyle bool
}

// S3Storage реализует минимальный S3-compatible storage через AWS Signature Version 4.
type S3Storage struct {
	cfg    S3Config
	client *http.Client
}

// NewS3Storage создаёт S3-совместимое хранилище.
func NewS3Storage(cfg S3Config) (*S3Storage, error) {
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	cfg.PublicURL = strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/")
	cfg.Bucket = strings.TrimSpace(cfg.Bucket)
	if cfg.Region == "" {
		cfg.Region = "ru-central1"
	}
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("для S3-хранилища обязательны endpoint, bucket, access key и secret key")
	}
	return &S3Storage{cfg: cfg, client: &http.Client{}}, nil
}

func (s *S3Storage) Driver() string { return "s3" }

func (s *S3Storage) Save(projectID, versionID, relativePath string, reader io.Reader) (string, int64, error) {
	key, err := objectKey(projectID, versionID, relativePath)
	if err != nil {
		return "", 0, err
	}

	// SigV4 requires the payload digest before headers are signed. Spool the
	// incoming stream to disk while hashing it, rather than buffering the whole
	// object in memory. The temporary file is then streamed directly to S3.
	tmp, err := os.CreateTemp("", "neverlauncher-s3-upload-*")
	if err != nil {
		return "", 0, fmt.Errorf("не удалось создать временный файл S3 upload: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, hasher), reader)
	if err != nil {
		return "", 0, fmt.Errorf("не удалось потоково подготовить файл для S3: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, fmt.Errorf("не удалось синхронизировать временный S3 upload: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return "", 0, fmt.Errorf("не удалось перемотать временный S3 upload: %w", err)
	}
	payloadHash := hex.EncodeToString(hasher.Sum(nil))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	req, err := s.newSignedRequestWithHash(ctx, http.MethodPut, key, tmp, size, payloadHash)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("не удалось отправить файл в S3: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", 0, fmt.Errorf("S3 вернул статус %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return key, size, nil
}

func (s *S3Storage) Open(projectID, versionID, relativePath string) (io.ReadCloser, int64, error) {
	key, err := objectKey(projectID, versionID, relativePath)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	req, err := s.newSignedRequest(ctx, http.MethodGet, key, nil, 0)
	if err != nil {
		cancel()
		return nil, 0, err
	}
	res, err := s.client.Do(req)
	if err != nil {
		cancel()
		return nil, 0, fmt.Errorf("не удалось получить файл из S3: %w", err)
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		cancel()
		return nil, 0, errors.New("файл не найден")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		cancel()
		return nil, 0, fmt.Errorf("S3 вернул статус %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return &cancelReadCloser{ReadCloser: res.Body, cancel: cancel}, res.ContentLength, nil
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func (s *S3Storage) Health(ctx context.Context) error {
	req, err := s.newSignedRequest(ctx, http.MethodHead, "", nil, 0)
	if err != nil {
		return err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("S3-хранилище недоступно: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 400 {
		return nil
	}
	return fmt.Errorf("S3 health check вернул статус %d", res.StatusCode)
}

func (s *S3Storage) newSignedRequest(ctx context.Context, method, key string, body io.Reader, size int64) (*http.Request, error) {
	if body != nil {
		return nil, errors.New("S3 request with body requires an explicit streaming payload hash")
	}
	return s.newSignedRequestWithHash(ctx, method, key, nil, size, sha256Hex(nil))
}

func (s *S3Storage) newSignedRequestWithHash(ctx context.Context, method, key string, body io.Reader, size int64, payloadHash string) (*http.Request, error) {
	objectURL, err := s.objectURL(key)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(payloadHash) == "" {
		return nil, errors.New("S3 payload hash обязателен")
	}
	req, err := http.NewRequestWithContext(ctx, method, objectURL.String(), body)
	if err != nil {
		return nil, err
	}
	if size > 0 {
		req.ContentLength = size
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalRequest, signedHeaders := canonicalRequest(req, payloadHash)
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, s.cfg.Region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(signingKey(s.cfg.SecretKey, dateStamp, s.cfg.Region), []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", s.cfg.AccessKey, scope, signedHeaders, signature))
	return req, nil
}

func (s *S3Storage) objectURL(key string) (*url.URL, error) {
	base, err := url.Parse(s.cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("некорректный S3 endpoint: %w", err)
	}
	if s.cfg.PathStyle {
		base.Path = joinURLPath(base.Path, s.cfg.Bucket, key)
		return base, nil
	}
	base.Host = s.cfg.Bucket + "." + base.Host
	base.Path = joinURLPath(base.Path, key)
	return base, nil
}

func objectKey(projectID, versionID, relativePath string) (string, error) {
	projectID, err := safeSegment(projectID, "projectId")
	if err != nil {
		return "", err
	}
	versionID, err = safeSegment(versionID, "version")
	if err != nil {
		return "", err
	}
	relativePath, err = safeRelativePath(relativePath)
	if err != nil {
		return "", err
	}
	return path.Join(projectID, versionID, relativePath), nil
}

func joinURLPath(parts ...string) string {
	items := make([]string, 0, len(parts))
	for _, item := range parts {
		item = strings.Trim(item, "/")
		if item != "" {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return "/"
	}
	return "/" + strings.Join(items, "/")
}

func canonicalRequest(req *http.Request, payloadHash string) (string, string) {
	headers := map[string]string{}
	for key, values := range req.Header {
		lower := strings.ToLower(key)
		headers[lower] = strings.Join(values, ",")
	}
	headers["host"] = req.URL.Host
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonicalHeaders strings.Builder
	for _, key := range keys {
		canonicalHeaders.WriteString(key)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(headers[key]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(keys, ";")
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	return strings.Join([]string{req.Method, uri, req.URL.RawQuery, canonicalHeaders.String(), signedHeaders, payloadHash}, "\n"), signedHeaders
}

func signingKey(secret, dateStamp, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
