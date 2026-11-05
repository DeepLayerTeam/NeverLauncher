package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type exportedSourceFile0333 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type sourceManifest0333 struct {
	Format         string                   `json:"format"`
	SourceSHA256   string                   `json:"sourceSha256"`
	ManifestSHA256 string                   `json:"manifestSha256"`
	Files          []exportedSourceFile0333 `json:"files"`
}

func verifyGravitExport0333(name, manifestHash string) error {
	f, e := os.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	z, e := zip.NewReader(f, st.Size())
	if e != nil {
		return e
	}
	if len(z.File) == 0 || len(z.File) > 30001 {
		return errors.New("Некорректное значение: «export entry count»")
	}
	seen := make(map[string]bool, len(z.File))
	var manifest sourceManifest0333
	hasManifest := false
	for _, entry := range z.File {
		if entry.Name != ".migration/inventory.json" {
			continue
		}
		if entry.UncompressedSize64 > 16<<20 {
			return errors.New("Превышен допустимый размер: «export manifest»")
		}
		r, e := entry.Open()
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(r, 16<<20+1))
		r.Close()
		if e != nil {
			return e
		}
		if len(b) > 16<<20 {
			return errors.New("Размер экспортного манифеста превышает допустимый предел")
		}
		if e = json.Unmarshal(b, &manifest); e != nil {
			return e
		}
		digest := sha256.Sum256([]byte(strings.TrimSuffix(string(b), "\n")))
		if hex.EncodeToString(digest[:]) != manifestHash || manifest.ManifestSHA256 != "" {
			return errors.New("Несоответствие: экспорт дайджест манифеста")
		}
		hasManifest = true
		break
	}
	if !hasManifest || manifest.Format != "launcher.gravit-source-inventory.v1" {
		return errors.New("Экспортный манифест отсутствует или некорректен")
	}
	// Передавайте каждый экспортируемый файл потоком и проверяйте контрольную сумму, размер, CRC и присутствие в наборе.
	expected := make(map[string]exportedSourceFile0333, len(manifest.Files))
	for _, v := range manifest.Files {
		if _, ok := expected[v.Path]; ok {
			return errors.New("Обнаружен дубликат: «path in export manifest»")
		}
		expected[v.Path] = v
	}
	for _, entry := range z.File {
		if seen[entry.Name] {
			return errors.New("Обнаружен дубликат: «export member»")
		}
		seen[entry.Name] = true
		if entry.Name == ".migration/inventory.json" {
			continue
		}
		meta, ok := expected[entry.Name]
		if !ok {
			return fmt.Errorf("Неожиданное значение: файл экспорта %q", entry.Name)
		}
		r, e := entry.Open()
		if e != nil {
			return e
		}
		h := sha256.New()
		n, e := io.Copy(h, r)
		closeErr := r.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if n != meta.Size || hex.EncodeToString(h.Sum(nil)) != meta.SHA256 {
			return fmt.Errorf("Обнаружено изменение: файл экспорта: %q", entry.Name)
		}
	}
	if len(seen) != len(expected)+1 {
		return errors.New("При экспорте не найдены исходные файлы")
	}
	return nil
}
func postGravitInventory0333(endpoint, token, sourcePath, out string, export bool) error {
	if sourcePath == "" {
		return errors.New("inventory/export: требуется «--source /path/to/gravit.zip»")
	}
	if export && out == "" {
		return errors.New("export: требуется «--output /path/to/private-export.zip»")
	}
	st, e := os.Stat(sourcePath)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return errors.New("Исходный ZIP должен быть обычным файлом размером от 1 до 512 МиБ")
	}
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("Для экспорта источника необходим HTTPS, кроме явно указанного IP-адреса локального интерфейса")
		}
	}
	source, e := os.Open(sourcePath)
	if e != nil {
		return e
	}
	defer source.Close()
	req, e := http.NewRequest("POST", endpoint, source)
	if e != nil {
		return e
	}
	req.ContentLength = st.Size()
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Accept", "application/zip, application/json")
	client := &http.Client{Timeout: 30 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		return fmt.Errorf("Инвентаризация или экспорт источника: HTTP %d: %s", response.StatusCode, string(b))
	}
	if !export {
		b, e := io.ReadAll(io.LimitReader(response.Body, 32<<20))
		if e != nil {
			return e
		}
		var doc any
		if e = json.Unmarshal(b, &doc); e != nil {
			return e
		}
		if strings.HasSuffix(u.Path, "/identities") {
			return writePrivateIdentityReport0334(out, doc)
		}
		return writeOrPrintJSON(out, doc)
	}
	if response.Header.Get("Content-Type") != "application/zip" {
		return errors.New("Конечная точка экспорта вернула неожиданный тип содержимого")
	}
	expected := response.Header.Get("X-Migration-Manifest-SHA256")
	if len(expected) != 64 {
		return errors.New("Отсутствует: контрольная сумма манифеста")
	}
	dir := filepath.Dir(out)
	tmp, e := os.CreateTemp(dir, ".gravit-export-*.tmp")
	if e != nil {
		return e
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	_ = tmp.Chmod(0600)
	if _, e = io.Copy(tmp, response.Body); e != nil {
		return e
	}
	if e = tmp.Sync(); e != nil {
		return e
	}
	if e = verifyGravitExport0333(tmp.Name(), expected); e != nil {
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	// Создание ссылки атомарно в пределах файловой системы и завершается ошибкой при существующей цели. Не
	// затирайте предыдущие снимки восстановления и не переходите по символьным ссылкам назначения.
	if e = os.Link(tmp.Name(), out); e != nil {
		return fmt.Errorf("«cannot safely publish export to %q (destination»: запрещено «exist):» %w", out, e)
	}
	fmt.Printf("Exported verified Gravit source: %s (manifest SHA-256 %s)\n", out, expected)
	return nil
}
