package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const loaderPayloadCacheSchema = "1.0"

type loaderPayloadCacheRecord struct {
	SchemaVersion    string `json:"schemaVersion"`
	Loader           string `json:"loader"`
	MinecraftVersion string `json:"minecraftVersion"`
	SourceURL        string `json:"sourceUrl"`
	PayloadSHA256    string `json:"payloadSha256"`
	Size             int64  `json:"size"`
	CachedAt         string `json:"cachedAt"`
}

func loaderPayloadCachePaths(root, sha string) (recordRel, payloadRel, recordPath, payloadPath string, err error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !compatibilitySHA256RE.MatchString(sha) {
		return "", "", "", "", errors.New("загрузчик полезная нагрузка кэш требует валидный SHA-256")
	}
	baseRel := filepath.ToSlash(filepath.Join(".neverlauncher", "loader-cache", "sha256", sha[:2], sha))
	recordRel = baseRel + ".json"
	payloadRel = baseRel + ".payload"
	recordPath, err = secureClientDestination(root, recordRel)
	if err != nil {
		return "", "", "", "", err
	}
	payloadPath, err = secureClientDestination(root, payloadRel)
	if err != nil {
		return "", "", "", "", err
	}
	return recordRel, payloadRel, recordPath, payloadPath, nil
}

func storeLoaderPayloadCacheBytes(root, loader, minecraft, source string, data []byte) (string, error) {
	sha := sha256HexBytes(data)
	_, _, recordPath, payloadPath, err := loaderPayloadCachePaths(root, sha)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o700); err != nil {
		return "", err
	}
	if err := writeAtomicBytes(payloadPath, data, 0o600); err != nil {
		return "", err
	}
	if err := writeLoaderPayloadCacheRecord(recordPath, loader, minecraft, source, sha, int64(len(data))); err != nil {
		return "", err
	}
	return sha, nil
}

func storeLoaderPayloadCacheFile(root, loader, minecraft, source, filePath, expectedSHA256 string) (string, error) {
	_, sha, size, err := hashFileSHA1SHA256(filePath)
	if err != nil {
		return "", err
	}
	sha = strings.ToLower(sha)
	if expectedSHA256 != "" && !strings.EqualFold(sha, strings.TrimSpace(expectedSHA256)) {
		return "", fmt.Errorf("загрузчик полезная нагрузка кэш исходник SHA-256 несоответствие: ожидаемый %s получил %s", expectedSHA256, sha)
	}
	_, _, recordPath, payloadPath, err := loaderPayloadCachePaths(root, sha)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o700); err != nil {
		return "", err
	}
	if ok, _, gotSize := existingFileMatchesSHA256(payloadPath, sha); !ok || gotSize != size {
		if err := copyFileAtomic(filePath, payloadPath); err != nil {
			return "", err
		}
	}
	if err := writeLoaderPayloadCacheRecord(recordPath, loader, minecraft, source, sha, size); err != nil {
		return "", err
	}
	return sha, nil
}

func writeLoaderPayloadCacheRecord(recordPath, loader, minecraft, source, sha string, size int64) error {
	if size <= 0 || size > maxCompatibilityArtifact {
		return fmt.Errorf("загрузчик полезная нагрузка кэш размер %d вне допустимого диапазона", size)
	}
	record := loaderPayloadCacheRecord{
		SchemaVersion:    loaderPayloadCacheSchema,
		Loader:           strings.ToLower(strings.TrimSpace(loader)),
		MinecraftVersion: strings.TrimSpace(minecraft),
		SourceURL:        strings.TrimSpace(source),
		PayloadSHA256:    strings.ToLower(strings.TrimSpace(sha)),
		Size:             size,
		CachedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicBytes(recordPath, append(raw, '\n'), 0o600)
}

func loadLoaderPayloadCacheBytes(root, loader, minecraft, source, expectedSHA256 string, max int64) ([]byte, error) {
	_, _, _, payloadPath, size, err := verifyLoaderPayloadCache(root, loader, minecraft, source, expectedSHA256, max)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, errors.New("загрузчик полезная нагрузка кэш размер изменён после проверка")
	}
	return data, nil
}

func restoreLoaderPayloadCacheFile(root, loader, minecraft, source, expectedSHA256, destination string, max int64) (int64, error) {
	_, _, _, payloadPath, size, err := verifyLoaderPayloadCache(root, loader, minecraft, source, expectedSHA256, max)
	if err != nil {
		return 0, err
	}
	if err := copyFileAtomic(payloadPath, destination); err != nil {
		return 0, err
	}
	ok, _, gotSize := existingFileMatchesSHA256(destination, expectedSHA256)
	if !ok || gotSize != size {
		_ = os.Remove(destination)
		return 0, errors.New("восстановление загрузчик полезная нагрузка ошибка SHA-256 проверка")
	}
	return size, nil
}

func verifyLoaderPayloadCache(root, loader, minecraft, source, expectedSHA256 string, max int64) (recordRel, payloadRel, recordPath, payloadPath string, size int64, err error) {
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	recordRel, payloadRel, recordPath, payloadPath, err = loaderPayloadCachePaths(root, expectedSHA256)
	if err != nil {
		return
	}
	if max <= 0 || max > maxCompatibilityArtifact {
		max = maxCompatibilityArtifact
	}
	raw, readErr := os.ReadFile(recordPath)
	if readErr != nil {
		err = readErr
		return
	}
	var record loaderPayloadCacheRecord
	if jsonErr := json.Unmarshal(raw, &record); jsonErr != nil {
		_, _ = quarantineCompatibilityArtifact(root, recordRel, "loader payload cache record JSON is corrupt")
		err = fmt.Errorf("загрузчик полезная нагрузка кэш запись JSON: %w", jsonErr)
		return
	}
	if record.SchemaVersion != loaderPayloadCacheSchema || record.Loader != strings.ToLower(strings.TrimSpace(loader)) || record.MinecraftVersion != strings.TrimSpace(minecraft) || record.SourceURL != strings.TrimSpace(source) || !strings.EqualFold(record.PayloadSHA256, expectedSHA256) || record.Size <= 0 || record.Size > max {
		_, _ = quarantineCompatibilityArtifact(root, recordRel, "loader payload cache identity/integrity metadata mismatch")
		err = errors.New("загрузчик полезная нагрузка кэш идентичность несоответствие")
		return
	}
	info, statErr := os.Lstat(payloadPath)
	if statErr != nil {
		err = statErr
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != record.Size {
		_, _ = quarantineCompatibilityArtifact(root, payloadRel, "loader payload cache file type/size mismatch")
		err = errors.New("загрузчик полезная нагрузка кэш полезная нагрузка метаданные несоответствие")
		return
	}
	ok, _, gotSize := existingFileMatchesSHA256(payloadPath, expectedSHA256)
	if !ok || gotSize != record.Size {
		_, _ = quarantineCompatibilityArtifact(root, payloadRel, "loader payload cache SHA-256 mismatch")
		err = errors.New("загрузчик полезная нагрузка кэш SHA-256 несоответствие")
		return
	}
	// Touch проверен полезная нагрузка так future GC реализация может использовать доступ время через mtime.
	_ = os.Chtimes(payloadPath, time.Now(), time.Now())
	size = record.Size
	return
}

func existingFileMatchesSHA256(path, expected string) (bool, string, int64) {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if !compatibilitySHA256RE.MatchString(expected) {
		return false, "", 0
	}
	file, err := os.Open(path)
	if err != nil {
		return false, "", 0
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false, "", 0
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, "", 0
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	return strings.EqualFold(actual, expected), actual, info.Size()
}

func fetchLoaderProfileWithCache(ctx context.Context, client *http.Client, root, loader, minecraft, source string, pinned *loaderResolutionLock, cacheOnly bool, max int64) ([]byte, bool, bool, error) {
	if pinned != nil {
		if pinned.PayloadURL != source {
			return nil, false, false, fmt.Errorf("загрузчик разрешение блокировка полезная нагрузка URL несоответствие: закреплённый %s получил %s", pinned.PayloadURL, source)
		}
		if data, err := loadLoaderPayloadCacheBytes(root, loader, minecraft, source, pinned.PayloadSHA256, max); err == nil {
			return data, true, cacheOnly, nil
		} else if cacheOnly {
			return nil, false, false, fmt.Errorf("загрузчик только кэш восстановление ошибка: %w", err)
		}
	}
	if cacheOnly {
		return nil, false, false, errors.New("загрузчик только кэш режим требует существующий неизменяемый разрешение блокировка")
	}
	data, err := fetchJSONBytes(ctx, client, source, max)
	if err != nil {
		if pinned != nil {
			if cached, cacheErr := loadLoaderPayloadCacheBytes(root, loader, minecraft, source, pinned.PayloadSHA256, max); cacheErr == nil {
				return cached, true, true, nil
			}
		}
		return nil, false, false, err
	}
	if pinned != nil {
		if err := assertPinnedPayload(pinned, source, data); err != nil {
			return nil, false, false, err
		}
	}
	if _, err := storeLoaderPayloadCacheBytes(root, loader, minecraft, source, data); err != nil {
		return nil, false, false, fmt.Errorf("загрузчик полезная нагрузка кэш фиксация: %w", err)
	}
	return data, false, false, nil
}

func restorePinnedInstallerFromCache(root, loader, minecraft, source, expectedSHA256, destination string) (vanillaDownloadedFile, error) {
	size, err := restoreLoaderPayloadCacheFile(root, loader, minecraft, source, expectedSHA256, destination, maxCompatibilityArtifact)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	sha1sum, sha256sum, actualSize, err := hashFileSHA1SHA256(destination)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	if actualSize != size || !strings.EqualFold(sha256sum, expectedSHA256) {
		return vanillaDownloadedFile{}, errors.New("восстановление установщик кэш проверка несоответствие")
	}
	rel, err := filepath.Rel(root, destination)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	return vanillaDownloadedFile{Path: filepath.ToSlash(rel), Kind: loader + "-installer", Size: actualSize, SHA1: sha1sum, SHA256: sha256sum, Cached: true}, nil
}

func downloadPinnedSHA256Artifact(ctx context.Context, client *http.Client, root, relative, source, expectedSHA256, kind string, max int64) (vanillaDownloadedFile, error) {
	if err := validateRemoteURL(source); err != nil {
		return vanillaDownloadedFile{}, err
	}
	if !compatibilitySHA256RE.MatchString(strings.ToLower(strings.TrimSpace(expectedSHA256))) {
		return vanillaDownloadedFile{}, errors.New("закреплённый артефакт требует SHA-256")
	}
	if max <= 0 || max > maxCompatibilityArtifact {
		max = maxCompatibilityArtifact
	}
	destination, err := secureClientDestination(root, relative)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return vanillaDownloadedFile{}, err
	}
	response, err := compatibilityGET(ctx, client, source, "NeverLauncher/"+version+" LoaderHardening")
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return vanillaDownloadedFile{}, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	tmp := destination + ".nlhardening-" + fmt.Sprint(time.Now().UnixNano())
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	h256 := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, h256), io.LimitReader(response.Body, max+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("закреплённый артефакт запись ошибка: %v %v %v", copyErr, syncErr, closeErr)
	}
	if written <= 0 || written > max {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("закреплённый артефакт размер %d вне разрешён диапазон", written)
	}
	actualSHA256 := hex.EncodeToString(h256.Sum(nil))
	if !strings.EqualFold(actualSHA256, expectedSHA256) {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, fmt.Errorf("закреплённый артефакт SHA-256 несоответствие: ожидаемый %s получил %s", expectedSHA256, actualSHA256)
	}
	if err := replaceFileAtomicPortable(tmp, destination); err != nil {
		_ = os.Remove(tmp)
		return vanillaDownloadedFile{}, err
	}
	sha1sum, sha256sum, size, err := hashFileSHA1SHA256(destination)
	if err != nil {
		return vanillaDownloadedFile{}, err
	}
	return vanillaDownloadedFile{Path: filepath.ToSlash(relative), Kind: kind, Size: size, SHA1: sha1sum, SHA256: sha256sum}, nil
}
