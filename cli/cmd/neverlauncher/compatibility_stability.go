package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	compatibilityHTTPAttempts = 4
	compatibilityLockWait     = 2 * time.Minute
	compatibilityLockStale    = 2 * time.Hour
	maxCompatibilityArtifact  = int64(2 << 30)
)

type compatibilityMaterializationLock struct {
	path string
}

func (l *compatibilityMaterializationLock) Close() {
	if l != nil && l.path != "" {
		_ = os.Remove(l.path)
	}
}

func acquireCompatibilityMaterializationLock(clientDir string) (*compatibilityMaterializationLock, error) {
	if strings.TrimSpace(clientDir) == "" {
		return nil, errors.New("clientDir пуст")
	}
	root, err := filepath.Abs(clientDir)
	if err != nil {
		return nil, fmt.Errorf("clientDir abs: %w", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("clientDir create: %w", err)
	}
	if info, err := os.Lstat(root); err != nil {
		return nil, fmt.Errorf("clientDir stat: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("clientDir должен быть реальным каталогом, а не symlink")
	}
	stateDir, err := secureClientDestination(root, ".neverlauncher")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("materialization state dir: %w", err)
	}
	lockPath := filepath.Join(stateDir, "materialize.lock")
	deadline := time.Now().Add(compatibilityLockWait)
	for {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(file, "pid=%d\nversion=%s\nstarted=%s\n", os.Getpid(), version, time.Now().UTC().Format(time.RFC3339Nano))
			if syncErr := file.Sync(); syncErr != nil {
				_ = file.Close()
				_ = os.Remove(lockPath)
				return nil, fmt.Errorf("materialization lock fsync: %w", syncErr)
			}
			if closeErr := file.Close(); closeErr != nil {
				_ = os.Remove(lockPath)
				return nil, fmt.Errorf("materialization lock close: %w", closeErr)
			}
			return &compatibilityMaterializationLock{path: lockPath}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("materialization lock: %w", err)
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > compatibilityLockStale {
			stale := lockPath + ".stale-" + strconv.FormatInt(time.Now().UnixNano(), 10)
			if renameErr := os.Rename(lockPath, stale); renameErr == nil {
				_ = os.Remove(stale)
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("clientDir %s занят другим materializer-процессом", root)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func secureClientDestination(root, relative string) (string, error) {
	if err := validateVanillaRelativePath(filepath.ToSlash(relative)); err != nil {
		return "", err
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil {
		return "", fmt.Errorf("client root stat: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", errors.New("client root должен быть реальным каталогом")
	}
	current := absoluteRoot
	parts := strings.Split(filepath.ToSlash(relative), "/")
	for i, part := range parts {
		current = filepath.Join(current, filepath.FromSlash(part))
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				// Missing suffix is safe: it will be created below the already-checked prefix.
				break
			}
			return "", fmt.Errorf("client path stat %s: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("client path содержит symlink: %s", filepath.Join(parts[:i+1]...))
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", fmt.Errorf("client path parent не является каталогом: %s", current)
		}
	}
	destination := filepath.Join(absoluteRoot, filepath.FromSlash(relative))
	rel, err := filepath.Rel(absoluteRoot, destination)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("client path вышел за root: %s", relative)
	}
	return destination, nil
}

func validateAssetLogicalPath(name string) error {
	normalized := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if normalized == "" || strings.HasPrefix(normalized, "/") || strings.ContainsRune(normalized, '\x00') {
		return fmt.Errorf("небезопасный asset logical path: %q", name)
	}
	for _, component := range strings.Split(normalized, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("небезопасный asset logical path: %q", name)
		}
	}
	return nil
}

func compatibilityGET(ctx context.Context, client *http.Client, rawURL, userAgent string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < compatibilityHTTPAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err == nil && !retryableCompatibilityStatus(resp.StatusCode) {
			return resp, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			delay := compatibilityRetryDelay(resp, attempt)
			_ = resp.Body.Close()
			if attempt+1 == compatibilityHTTPAttempts {
				break
			}
			if err := sleepContext(ctx, delay); err != nil {
				return nil, err
			}
			continue
		}
		lastErr = err
		if attempt+1 == compatibilityHTTPAttempts {
			break
		}
		if err := sleepContext(ctx, compatibilityRetryDelay(nil, attempt)); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("upstream GET failed after %d attempts: %w", compatibilityHTTPAttempts, lastErr)
}

func retryableCompatibilityStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func compatibilityRetryDelay(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if value := strings.TrimSpace(resp.Header.Get("Retry-After")); value != "" {
			if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
				delay := time.Duration(seconds) * time.Second
				if delay > 10*time.Second {
					return 10 * time.Second
				}
				return delay
			}
		}
	}
	delay := 250 * time.Millisecond * time.Duration(1<<attempt)
	if delay > 4*time.Second {
		delay = 4 * time.Second
	}
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func replaceFileAtomicPortable(tmp, dst string) error {
	if err := os.Rename(tmp, dst); err == nil {
		return nil
	}
	if _, err := os.Lstat(dst); err != nil {
		return fmt.Errorf("atomic rename %s: %w", dst, err)
	}
	backup := dst + ".nlreplace-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := os.Rename(dst, backup); err != nil {
		return fmt.Errorf("atomic replace backup %s: %w", dst, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Rename(backup, dst)
		return fmt.Errorf("atomic replace %s: %w", dst, err)
	}
	_ = os.RemoveAll(backup)
	return nil
}
