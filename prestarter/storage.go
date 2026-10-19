package prestarter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type storage struct {
	root       string
	offlineDir string
	offline    bool
	http       *http.Client
}

func newStorage(root, offlineDir string, offline bool) (*storage, error) {
	if offlineDir != "" {
		var err error
		offlineDir, err = safeExistingDir(offlineDir)
		if err != nil {
			return nil, err
		}
	}
	dialer := &net.Dialer{Timeout: 12 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext, TLSHandshakeTimeout: 12 * time.Second, ResponseHeaderTimeout: 25 * time.Second, MaxIdleConns: 10, MaxIdleConnsPerHost: 3}
	client := &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || r.URL.Scheme != "https" {
			return errors.New("unsafe HTTPS redirect")
		}
		return nil
	}}
	return &storage{root: root, offlineDir: offlineDir, offline: offline, http: client}, nil
}
func safeExistingDir(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("offline directory must be absolute")
	}
	cleaned := filepath.Clean(path)
	resolved, e := filepath.EvalSymlinks(cleaned)
	if e != nil {
		return "", e
	}
	if resolved != cleaned {
		return "", errors.New("offline directory is a symlink/junction")
	}
	meta, e := os.Stat(cleaned)
	if e != nil || !meta.IsDir() {
		return "", errors.New("offline directory missing")
	}
	return cleaned, nil
}
func hashFile(path string, expected Artifact) bool {
	meta, e := os.Lstat(path)
	if e != nil || !meta.Mode().IsRegular() || meta.Size() != expected.Size {
		return false
	}
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	hash := sha256.New()
	size, e := io.Copy(hash, io.LimitReader(f, expected.Size+1))
	return e == nil && size == expected.Size && hex.EncodeToString(hash.Sum(nil)) == expected.SHA256
}
func durableCopy(source, destination string, expected Artifact, executable bool) error {
	if !hashFile(source, expected) {
		return errors.New("source SHA-256 mismatch")
	}
	parent := filepath.Dir(destination)
	if e := safeMkdir(parent); e != nil {
		return e
	}
	src, e := os.Open(source)
	if e != nil {
		return e
	}
	defer src.Close()
	dst, e := os.CreateTemp(parent, ".prestaging-*")
	if e != nil {
		return e
	}
	tmp := dst.Name()
	defer os.Remove(tmp)
	if _, e = io.CopyBuffer(dst, io.LimitReader(src, expected.Size+1), make([]byte, 65536)); e != nil {
		dst.Close()
		return e
	}
	mode := os.FileMode(0600)
	if executable {
		mode = 0700
	}
	if e = dst.Chmod(mode); e != nil {
		dst.Close()
		return e
	}
	if e = dst.Sync(); e != nil {
		dst.Close()
		return e
	}
	if e = dst.Close(); e != nil {
		return e
	}
	if !hashFile(tmp, expected) {
		return errors.New("changed source SHA-256 mismatch")
	}
	if e = atomicReplace(tmp, destination); e != nil {
		return e
	}
	return syncDir(parent)
}
func safeMkdir(dir string) error {
	// Reject links for EVERY component below the already verified installation root.
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	current := dir
	for {
		m, e := os.Lstat(current)
		if e != nil {
			return e
		}
		if m.Mode()&os.ModeSymlink != 0 || !m.IsDir() {
			return fmt.Errorf("non-directory or symlink path: %s", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}
func (s *storage) objectPath(art Artifact) string {
	return filepath.Join(s.root, "cache", "sha256", art.SHA256[:2], art.SHA256)
}
func (s *storage) artifact(ctx context.Context, art Artifact, offlineName string) (string, error) {
	cache := s.objectPath(art)
	if hashFile(cache, art) {
		return cache, nil
	}
	if e := safeMkdir(filepath.Dir(cache)); e != nil {
		return "", e
	}
	if e := os.Remove(cache); e != nil && !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	if s.offlineDir != "" {
		for _, rel := range []string{filepath.Join("objects", art.SHA256), offlineName} {
			if rel == "" {
				continue
			}
			candidate := filepath.Join(s.offlineDir, rel)
			if hashFile(candidate, art) {
				if e := durableCopy(candidate, cache, art, false); e != nil {
					return "", e
				}
				return cache, nil
			}
		}
	}
	if s.offline {
		return "", fmt.Errorf("offline cache missing SHA-256 %s", art.SHA256)
	}
	// Partial files are deterministically keyed by digest, not URLs. Their
	// accompanying validator is required before an HTTP Range is attempted.
	part := cache + ".part"
	meta := cache + ".etag"
	var failure error
	for attempt := 0; attempt < 5; attempt++ {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		failure = s.fetch(ctx, art, part, meta)
		if failure == nil {
			if !hashFile(part, art) {
				failure = errors.New("component SHA-256 mismatch")
				os.Remove(part)
				os.Remove(meta)
			} else {
				if e := os.Rename(part, cache); e != nil {
					return "", e
				}
				os.Remove(meta)
				if e := syncDir(filepath.Dir(cache)); e != nil {
					return "", e
				}
				return cache, nil
			}
		}
		if attempt < 4 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
	}
	return "", fmt.Errorf("download %s: %w", art.SHA256, failure)
}
func (s *storage) fetch(parent context.Context, art Artifact, part, metaPath string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	var start int64
	var validator string
	if st, e := os.Lstat(part); e == nil && st.Mode().IsRegular() && st.Size() > 0 && st.Size() < art.Size {
		if etag, e := os.ReadFile(metaPath); e == nil && strongETag(string(etag)) {
			start = st.Size()
			validator = string(etag)
		}
	}
	if start == 0 {
		os.Remove(part)
		os.Remove(metaPath)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, art.URL, nil)
	if e != nil {
		return e
	}
	req.Header.Set("Accept-Encoding", "identity")
	if start > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
		req.Header.Set("If-Range", validator)
	}
	res, e := s.http.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
		return errors.New("unsafe Content-Encoding")
	}
	if start > 0 {
		if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			os.Remove(part)
			os.Remove(metaPath)
			return errors.New("range rejected; discarded partial")
		}
		low, high, total, ok := parseContentRange(res.Header.Get("Content-Range"))
		if res.StatusCode != http.StatusPartialContent || !ok || low != start || total != art.Size || high < low || high >= art.Size || res.ContentLength >= 0 && res.ContentLength != high-low+1 || res.Header.Get("ETag") != validator {
			os.Remove(part)
			os.Remove(metaPath)
			return errors.New("invalid 206 range or validator; discarded partial")
		}
	} else {
		if res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusRequestTimeout || res.StatusCode >= 500 {
			return fmt.Errorf("retryable HTTP %d", res.StatusCode)
		}
		if res.StatusCode != http.StatusOK || res.Header.Get("Content-Range") != "" {
			return fmt.Errorf("expected HTTP 200, got %d", res.StatusCode)
		}
		if res.ContentLength >= 0 && res.ContentLength != art.Size {
			return errors.New("signed content length mismatch")
		}
	}
	etag := res.Header.Get("ETag")
	if start == 0 && strongETag(etag) {
		if e := atomicSmallWrite(metaPath, []byte(etag)); e != nil {
			return e
		}
	}
	flags := os.O_CREATE | os.O_WRONLY
	if start > 0 {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	output, e := os.OpenFile(part, flags, 0600)
	if e != nil {
		return e
	}
	// max size is enforced during streaming, including chunked responses.
	written, e := io.CopyBuffer(output, io.LimitReader(res.Body, art.Size-start+1), make([]byte, 65536))
	if syncErr := output.Sync(); e == nil {
		e = syncErr
	}
	if closeErr := output.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if written+start > art.Size {
		os.Remove(part)
		os.Remove(metaPath)
		return errors.New("body longer than signed size")
	}
	if written+start < art.Size {
		return errors.New("body ended before signed size")
	}
	return nil
}
func parseContentRange(value string) (int64, int64, int64, bool) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, false
	}
	a, b, ok := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !ok {
		return 0, 0, 0, false
	}
	low, high, ok := strings.Cut(a, "-")
	if !ok {
		return 0, 0, 0, false
	}
	x, e1 := strconv.ParseInt(low, 10, 64)
	y, e2 := strconv.ParseInt(high, 10, 64)
	z, e3 := strconv.ParseInt(b, 10, 64)
	return x, y, z, e1 == nil && e2 == nil && e3 == nil && x >= 0 && y >= x && z > y
}
func strongETag(s string) bool {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for _, r := range s[1 : len(s)-1] {
		if r < '!' || r == '"' || r == 127 {
			return false
		}
	}
	return true
}
func atomicSmallWrite(path string, data []byte) error {
	if e := safeMkdir(filepath.Dir(path)); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".atomic-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	// Windows cannot replace an open path with rename. The caller serializes
	// metadata updates under the installation process lock.
	if e = atomicReplace(tmp, path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }
