package main

// Механизм импорта модпаков: проверяет недоверенные манифесты ZIP, находит точные идентичности
// файлов, скачивает и хеширует файлы в закрытом промежуточном кэше, запускает существующий Client
// Factory и атомарно фиксирует полностью проверенный клиент.
import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const modpackEvidencePath0275 = ".launcher/modpack-import.json"
const modpackMaxBytes0275 int64 = 2 << 30
const modpackMaxFile0275 int64 = 512 << 20

type modpackFile0275 struct {
	Path        string   `json:"path"`
	Source      string   `json:"source"`
	SHA1        string   `json:"sha1,omitempty"`
	SHA512      string   `json:"sha512,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	Size        int64    `json:"size"`
	Acquisition string   `json:"acquisition,omitempty"`
	URLs        []string `json:"-"`
	ManualName  string   `json:"-"`
	Required    bool     `json:"-"`
	ProjectID   int64    `json:"-"`
	FileID      int64    `json:"-"`
}
type modpackSpec0275 struct {
	Format        string               `json:"format"`
	Name          string               `json:"name"`
	Version       string               `json:"version"`
	Minecraft     string               `json:"minecraft"`
	Loader        string               `json:"loader"`
	LoaderVersion string               `json:"loaderVersion,omitempty"`
	PackSHA256    string               `json:"packSha256"`
	Files         []modpackFile0275    `json:"files"`
	Overrides     map[string]*zip.File `json:"-"`
	Skipped       []string             `json:"skipped,omitempty"`
}
type modpackMissing0275 struct {
	Code           string `json:"code,omitempty"`
	ExpectedSHA1   string `json:"expectedSha1,omitempty"`
	ExpectedSHA512 string `json:"expectedSha512,omitempty"`
	ExpectedSHA256 string `json:"expectedSha256,omitempty"`
	ExpectedSize   int64  `json:"expectedSize,omitempty"`
	CanManual      bool   `json:"canManual,omitempty"`
	Path           string `json:"path"`
	Source         string `json:"source"`
	Reason         string `json:"reason"`
	ManualAction   string `json:"manualAction"`
}
type modpackReport0275 struct {
	SchemaVersion string               `json:"schemaVersion"`
	Format        string               `json:"format"`
	Name          string               `json:"name"`
	Minecraft     string               `json:"minecraft"`
	Loader        string               `json:"loader"`
	LoaderVersion string               `json:"loaderVersion,omitempty"`
	PackSHA256    string               `json:"packSha256"`
	Status        string               `json:"status"`
	Skipped       []string             `json:"skipped,omitempty"`
	Missing       []modpackMissing0275 `json:"missing,omitempty"`
	Imported      []modpackFile0275    `json:"imported,omitempty"`
	Pending       []string             `json:"pending,omitempty"`
	FileCount     int                  `json:"fileCount"`
	OverrideCount int                  `json:"overrideCount"`
	PlanSHA256    string               `json:"planSha256,omitempty"`
	Distribution  string               `json:"distribution,omitempty"`
}

type modrinthIndex0275 struct {
	FormatVersion int               `json:"formatVersion"`
	Game          string            `json:"game"`
	VersionID     string            `json:"versionId"`
	Name          string            `json:"name"`
	Dependencies  map[string]string `json:"dependencies"`
	Files         []struct {
		Path      string            `json:"path"`
		Hashes    map[string]string `json:"hashes"`
		Downloads []string          `json:"downloads"`
		FileSize  int64             `json:"fileSize"`
		Env       map[string]string `json:"env"`
	} `json:"files"`
}
type curseIndex0275 struct {
	ManifestType    string `json:"manifestType"`
	ManifestVersion int    `json:"manifestVersion"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Overrides       string `json:"overrides"`
	Minecraft       struct {
		Version    string `json:"version"`
		ModLoaders []struct {
			ID      string `json:"id"`
			Primary bool   `json:"primary"`
		} `json:"modLoaders"`
	} `json:"minecraft"`
	Files []struct {
		ProjectID int64 `json:"projectID"`
		FileID    int64 `json:"fileID"`
		Required  bool  `json:"required"`
	} `json:"files"`
}

func packPath0275(v string) error {
	if len(v) > 1024 || v == "" || strings.Contains(v, "\\") || strings.Contains(v, ":") || strings.HasPrefix(v, "/") || strings.ContainsAny(v, "\x00\r\n") {
		return fmt.Errorf("Небезопасный путь модпака %q", v)
	}
	for _, seg := range strings.Split(v, "/") {
		if len(seg) > 240 || seg == "" || seg == "." || seg == ".." || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return fmt.Errorf("Небезопасный сегмент пути модпака в %q", v)
		}
	}
	for _, seg := range strings.Split(v, "/") {
		base := strings.ToUpper(strings.SplitN(seg, ".", 2)[0])
		if base == "CON" || base == "NUL" || base == "AUX" || base == "PRN" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return fmt.Errorf("Зарезервированный в Windows путь модпака %q", v)
		}
	}
	return validateVanillaRelativePath(v)
}
func packOutputPath0275(v string) error {
	if err := packPath0275(v); err != nil {
		return err
	}
	lower := strings.ToLower(v)
	for _, prefix := range []string{".launcher/", "versions/", "assets/", "libraries/", "natives/", "runtime/"} {
		if lower == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("Модпак не может перезаписать управляемый путь %s", v)
		}
	}
	return nil
}
func readPackJSON0275(z *zip.File, v any) error {
	if z == nil || z.UncompressedSize64 > 4<<20 || !z.Mode().IsRegular() {
		return errors.New("Недопустимый или слишком большой манифест модпака")
	}
	r, err := z.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, 4<<20+1))
	if err != nil {
		return err
	}
	if len(b) > 4<<20 {
		return errors.New("manifest exceeds 4 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err = dec.Decode(v); err != nil {
		return err
	}
	if err = dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("Лишние данные JSON после манифеста")
	}
	return nil
}
func modrinthDownloadURL0275(raw string) error {
	if err := validateRemoteURL(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "cdn.modrinth.com", "github.com", "raw.githubusercontent.com", "gitlab.com", "localhost", "127.0.0.1", "::1":
		return nil
	}
	return fmt.Errorf("Недоверенное имя хоста загрузки Modrinth: %s", host)
}
func loaderFromModrinth0275(deps map[string]string) (string, string, string, error) {
	mc := strings.TrimSpace(deps["minecraft"])
	if mc == "" || isMutableMinecraft0271(mc) {
		return "", "", "", errors.New("modpack must pin minecraft version")
	}
	var loader, version string
	for _, p := range []struct{ key, loader string }{{"fabric-loader", "fabric"}, {"quilt-loader", "quilt"}, {"forge", "forge"}, {"neoforge", "neoforge"}} {
		if value := strings.TrimSpace(deps[p.key]); value != "" {
			if loader != "" {
				return "", "", "", errors.New("multiple modloaders in Modrinth pack")
			}
			loader, version = p.loader, value
		}
	}
	for key := range deps {
		if key != "minecraft" && key != "fabric-loader" && key != "quilt-loader" && key != "forge" && key != "neoforge" {
			return "", "", "", fmt.Errorf("unsupported required Modrinth dependency %q", key)
		}
	}
	if loader == "" {
		loader = "vanilla"
	}
	if version != "" && isMutableLoaderSelector(version) {
		return "", "", "", errors.New("loader version cannot be mutable")
	}
	return mc, loader, version, nil
}
func loaderFromCurse0275(m curseIndex0275) (string, string, string, error) {
	mc := strings.TrimSpace(m.Minecraft.Version)
	if mc == "" || isMutableMinecraft0271(mc) {
		return "", "", "", errors.New("CurseForge manifest must pin Minecraft")
	}
	if len(m.Minecraft.ModLoaders) == 0 {
		return mc, "vanilla", "", nil
	}
	if len(m.Minecraft.ModLoaders) > 1 {
		primary := 0
		for _, l := range m.Minecraft.ModLoaders {
			if l.Primary {
				primary++
			}
		}
		if primary != 1 {
			return "", "", "", errors.New("ambiguous primary CurseForge loader")
		}
	}
	var id string
	for _, l := range m.Minecraft.ModLoaders {
		if l.Primary || len(m.Minecraft.ModLoaders) == 1 {
			id = l.ID
			break
		}
	}
	for _, name := range []string{"neoforge", "fabric", "quilt", "forge"} {
		if strings.HasPrefix(strings.ToLower(id), name+"-") {
			v := id[len(name)+1:]
			if v == "" || isMutableLoaderSelector(v) {
				return "", "", "", errors.New("Некорректное значение: CurseForge версия загрузчика")
			}
			return mc, name, v, nil
		}
	}
	return "", "", "", fmt.Errorf("Не поддерживается: CurseForge загрузчик %q", id)
}
func parseModpack0275(archive string, includeOptional bool) (modpackSpec0275, *zip.ReadCloser, error) {
	var spec modpackSpec0275
	st, err := os.Lstat(archive)
	if err != nil {
		return spec, nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > modpackMaxBytes0275 {
		return spec, nil, errors.New("Модпак должен быть обычным ZIP-файлом размером не более 2 ГиБ")
	}
	packHash, _, err := hashFile(archive)
	if err != nil {
		return spec, nil, err
	}
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return spec, nil, err
	}
	fail := func(err error) (modpackSpec0275, *zip.ReadCloser, error) { zr.Close(); return spec, nil, err }
	files := map[string]*zip.File{}
	folded := map[string]bool{}
	var total uint64
	if len(zr.File) > 10000 {
		return fail(errors.New("Модпак содержит слишком много элементов ZIP"))
	}
	for _, f := range zr.File {
		p := f.Name
		if f.FileInfo().IsDir() {
			p = strings.TrimSuffix(p, "/")
		}
		if err := packPath0275(p); err != nil {
			return fail(err)
		}
		if folded[strings.ToLower(p)] {
			return fail(fmt.Errorf("Повторяющийся путь архива или конфликт регистра %q", p))
		}
		folded[strings.ToLower(p)] = true
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.Mode().IsRegular() || f.UncompressedSize64 > uint64(modpackMaxFile0275) {
			return fail(fmt.Errorf("unsafe/oversized ZIP entry %q", p))
		}
		total += f.UncompressedSize64
		if total > uint64(modpackMaxBytes0275) {
			return fail(errors.New("Размер распакованного модпака превышает допустимый предел"))
		}
		files[p] = f
	}
	spec.PackSHA256 = packHash
	spec.Overrides = map[string]*zip.File{}
	_, mr := files["modrinth.index.json"]
	_, cf := files["manifest.json"]
	if mr == cf {
		return fail(errors.New("Архив должен содержать ровно один манифест Modrinth или CurseForge"))
	}
	var layers []string
	if mr {
		spec.Format = "modrinth"
		var index modrinthIndex0275
		if err := readPackJSON0275(files["modrinth.index.json"], &index); err != nil {
			return fail(err)
		}
		if index.FormatVersion != 1 || index.Game != "minecraft" || index.VersionID == "" || index.Name == "" {
			return fail(errors.New("Недопустимый индекс Modrinth"))
		}
		spec.Name = index.Name
		spec.Version = index.VersionID
		spec.Minecraft, spec.Loader, spec.LoaderVersion, err = loaderFromModrinth0275(index.Dependencies)
		if err != nil {
			return fail(err)
		}
		if len(index.Files) > 4000 {
			return fail(errors.New("Слишком много файлов Modrinth"))
		}
		for _, f := range index.Files {
			if err := packOutputPath0275(f.Path); err != nil {
				return fail(err)
			}
			client := f.Env["client"]
			server := f.Env["server"]
			for _, side := range []string{client, server} {
				if side != "" && side != "required" && side != "optional" && side != "unsupported" {
					return fail(fmt.Errorf("Неизвестное окружение Modrinth %q", side))
				}
			}
			if client == "unsupported" || client == "optional" && !includeOptional {
				spec.Skipped = append(spec.Skipped, f.Path)
				continue
			}
			if f.FileSize < 0 || f.FileSize > modpackMaxFile0275 {
				return fail(fmt.Errorf("Недопустимый размер файла %s", f.Path))
			}
			if len(f.Downloads) > 8 {
				return fail(fmt.Errorf("Для %s отсутствуют загрузки или их слишком много", f.Path))
			}
			if len(f.Hashes["sha1"]) != 40 || len(f.Hashes["sha512"]) != 128 {
				return fail(fmt.Errorf("Для Modrinth необходимы SHA1 и SHA512 для %s", f.Path))
			}
			if _, e := hex.DecodeString(f.Hashes["sha1"]); e != nil {
				return fail(e)
			}
			if _, e := hex.DecodeString(f.Hashes["sha512"]); e != nil {
				return fail(e)
			}
			for _, u := range f.Downloads {
				if err := modrinthDownloadURL0275(u); err != nil {
					return fail(fmt.Errorf("%s: %w", f.Path, err))
				}
			}
			spec.Files = append(spec.Files, modpackFile0275{Path: f.Path, Source: "modrinth:" + f.Path, SHA1: strings.ToLower(f.Hashes["sha1"]), SHA512: strings.ToLower(f.Hashes["sha512"]), Size: f.FileSize, URLs: f.Downloads, ManualName: path.Base(f.Path), Required: true})
		}
		layers = []string{"overrides/", "client-overrides/"}
	} else {
		spec.Format = "curseforge"
		var index curseIndex0275
		if err := readPackJSON0275(files["manifest.json"], &index); err != nil {
			return fail(err)
		}
		if index.ManifestType != "minecraftModpack" || index.ManifestVersion != 1 || index.Name == "" {
			return fail(errors.New("Неподдерживаемый манифест CurseForge"))
		}
		spec.Name = index.Name
		spec.Version = index.Version
		spec.Minecraft, spec.Loader, spec.LoaderVersion, err = loaderFromCurse0275(index)
		if err != nil {
			return fail(err)
		}
		if len(index.Files) > 4000 {
			return fail(errors.New("Слишком много файлов CurseForge"))
		}
		for _, f := range index.Files {
			if f.ProjectID <= 0 || f.FileID <= 0 {
				return fail(errors.New("Недопустимый идентификатор проекта или файла CurseForge"))
			}
			if !f.Required && !includeOptional {
				spec.Skipped = append(spec.Skipped, fmt.Sprintf("curseforge:%d/%d", f.ProjectID, f.FileID))
				continue
			}
			spec.Files = append(spec.Files, modpackFile0275{Source: fmt.Sprintf("curseforge:%d/%d", f.ProjectID, f.FileID), ProjectID: f.ProjectID, FileID: f.FileID, Required: true})
		}
		dir := index.Overrides
		if dir == "" {
			dir = "overrides"
		}
		if err := packPath0275(dir); err != nil {
			return fail(err)
		}
		if strings.Contains(dir, "/") {
			return fail(errors.New("Каталог переопределений CurseForge должен быть одним каталогом"))
		}
		layers = []string{dir + "/"}
	}
	// Переопределения Modrinth client-overrides намеренно имеют приоритет над общими overrides.
	for _, prefix := range layers {
		for _, name := range sortedZipNames0275(files) {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			rel := strings.TrimPrefix(name, prefix)
			if err := packOutputPath0275(rel); err != nil {
				return fail(err)
			}
			spec.Overrides[rel] = files[name]
		}
	}
	overrideCase := map[string]string{}
	for p := range spec.Overrides {
		key := strings.ToLower(p)
		if old, exists := overrideCase[key]; exists && old != p {
			return fail(fmt.Errorf("Конфликт регистра путей переопределений: %s и %s", old, p))
		}
		overrideCase[key] = p
	}
	paths := map[string]bool{}
	for _, f := range spec.Files {
		key := strings.ToLower(f.Path)
		if key != "" {
			if paths[key] {
				return fail(fmt.Errorf("Повторяющийся файл модпака %s", f.Path))
			}
			paths[key] = true
		}
	}
	for p := range spec.Overrides {
		if paths[strings.ToLower(p)] {
			return fail(fmt.Errorf("Загрузка конфликтует с переопределением %s", p))
		}
	}
	sort.Slice(spec.Files, func(i, j int) bool { return spec.Files[i].Source < spec.Files[j].Source })
	sort.Strings(spec.Skipped)
	return spec, zr, nil
}
func sortedZipNames0275(m map[string]*zip.File) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Загружайте в изолированный обычный файл и проверяйте все контрольные суммы источника,
// прежде чем предоставлять байты исполнителю Client Factory.
func fetchModpackArtifact0275(ctx context.Context, client *http.Client, dir string, f modpackFile0275, manual string) (string, string, int64, error) {
	paths := append([]string{}, f.URLs...)
	if manual != "" && f.ManualName != "" {
		// Сначала точный путь (несколько модов могут иметь одинаковое имя файла), затем прежний запасной
		// вариант плоского каталога --manual-dir. Компоненты символьных ссылок запрещены.
		candidates := []string{f.Path}
		if f.ManualName != f.Path {
			candidates = append(candidates, f.ManualName)
		}
		for i := len(candidates) - 1; i >= 0; i-- {
			rel := candidates[i]
			if packOutputPath0275(rel) != nil {
				continue
			}
			candidate, e := secureManualSource0276(manual, rel)
			if e == nil {
				paths = append([]string{"file:" + candidate}, paths...)
			}
		}
	}
	if len(paths) == 0 {
		return "", "", 0, errors.New("Нет разрешённого URL загрузки: требуется вручную проверенный артефакт")
	}
	var last error
	for _, raw := range paths {
		tmp, err := os.CreateTemp(dir, ".modpack-file-")
		if err != nil {
			return "", "", 0, err
		}
		name := tmp.Name()
		var reader io.ReadCloser
		if strings.HasPrefix(raw, "file:") {
			reader, err = os.Open(strings.TrimPrefix(raw, "file:"))
		} else {
			if err = validateRemoteURL(raw); err == nil {
				req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
				if e != nil {
					err = e
				} else {
					resp, e := client.Do(req)
					if e != nil {
						err = e
					} else if resp.StatusCode != http.StatusOK {
						resp.Body.Close()
						err = fmt.Errorf("HTTP %d", resp.StatusCode)
					} else if resp.ContentLength > modpackMaxFile0275 {
						resp.Body.Close()
						err = errors.New("Загрузка превышает ограничение размера")
					} else {
						reader = resp.Body
					}
				}
			}
		}
		if err == nil {
			h1, h256, h512 := sha1.New(), sha256.New(), sha512.New()
			n, e := io.Copy(io.MultiWriter(tmp, h1, h256, h512), io.LimitReader(reader, modpackMaxFile0275+1))
			closeErr := reader.Close()
			if e != nil {
				err = e
			} else if closeErr != nil {
				err = closeErr
			} else if n > modpackMaxFile0275 {
				err = errors.New("Загрузка превышает ограничение размера")
			} else if n != f.Size {
				err = errors.New("Несовпадение размера файла")
			} else if f.SHA1 != "" && !strings.EqualFold(f.SHA1, hex.EncodeToString(h1.Sum(nil))) {
				err = errors.New("Несоответствие: SHA-1")
			} else if f.SHA512 != "" && !strings.EqualFold(f.SHA512, hex.EncodeToString(h512.Sum(nil))) {
				err = errors.New("Несоответствие: SHA-512")
			} else if f.SHA256 != "" && !strings.EqualFold(f.SHA256, hex.EncodeToString(h256.Sum(nil))) {
				err = errors.New("SHA-256 mismatch")
			}
			if err == nil {
				err = tmp.Sync()
				if err == nil {
					err = tmp.Close()
					if err == nil {
						return name, hex.EncodeToString(h256.Sum(nil)), n, nil
					}
				}
			}
		}
		_ = tmp.Close()
		_ = os.Remove(name)
		last = err
	}
	return "", "", 0, fmt.Errorf("all permitted sources failed: %w", last)
}
func curseFileMetadata0275(ctx context.Context, client *http.Client, api, key string, f *modpackFile0275) error {
	endpoint := strings.TrimRight(api, "/") + "/v1/mods/" + strconv.FormatInt(f.ProjectID, 10) + "/files/" + strconv.FormatInt(f.FileID, 10)
	if err := validateRemoteURL(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("CurseForge API HTTP %d", resp.StatusCode)
	}
	var data struct {
		Data struct {
			ID          int64   `json:"id"`
			ModID       int64   `json:"modId"`
			FileName    string  `json:"fileName"`
			FileLength  int64   `json:"fileLength"`
			DownloadURL *string `json:"downloadUrl"`
			Hashes      []struct {
				Value string `json:"value"`
				Algo  int    `json:"algo"`
			} `json:"hashes"`
		} `json:"data"`
	}
	if resp.ContentLength > 4<<20 {
		return errors.New("Метаданные CurseForge слишком большие")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil {
		return err
	}
	if len(b) > 4<<20 {
		return errors.New("Метаданные CurseForge слишком большие")
	}
	if err = json.Unmarshal(b, &data); err != nil {
		return err
	}
	d := data.Data
	if d.ID != f.FileID || d.ModID != f.ProjectID {
		return errors.New("Несовпадение идентификатора файла CurseForge")
	}
	if d.FileLength < 0 || d.FileLength > modpackMaxFile0275 {
		return errors.New("Недопустимый размер файла CurseForge")
	}
	if d.FileName == "" || path.Base(d.FileName) != d.FileName || packPath0275(d.FileName) != nil || !strings.HasSuffix(strings.ToLower(d.FileName), ".jar") {
		return errors.New("Небезопасное имя файла CurseForge или файл не является JAR")
	}
	f.Path = "mods/" + d.FileName
	f.ManualName = d.FileName
	f.Size = d.FileLength
	for _, h := range d.Hashes {
		if h.Algo == 1 && len(h.Value) == 40 {
			if _, e := hex.DecodeString(h.Value); e == nil {
				f.SHA1 = strings.ToLower(h.Value)
			}
		}
	}
	if f.SHA1 == "" {
		return errors.New("Для этого файла CurseForge отсутствует доверенный SHA-1")
	}
	if d.DownloadURL != nil && *d.DownloadURL != "" {
		if err := validateRemoteURL(*d.DownloadURL); err != nil {
			return err
		}
		f.URLs = []string{*d.DownloadURL}
	} else {
		// API файлов CurseForge может не выдавать downloadUrl; документированный endpoint
		// download-url всё же может предоставить разрешённый официальный URL.
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/download-url", nil)
		if e != nil {
			return e
		}
		request.Header.Set("x-api-key", key)
		response, e := client.Do(request)
		if e == nil {
			defer response.Body.Close()
			if response.StatusCode == http.StatusOK {
				var result struct {
					Data string `json:"data"`
				}
				if response.ContentLength <= 1<<20 {
					raw, e := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
					if e == nil && len(raw) <= 1<<20 && json.Unmarshal(raw, &result) == nil && result.Data != "" && validateRemoteURL(result.Data) == nil {
						f.URLs = []string{result.Data}
					}
				}
			}
		}
	}
	return nil
}
func readZipOverride0275(z *zip.File, dir string) (string, string, int64, error) {
	dest, err := os.CreateTemp(dir, ".pack-override-")
	if err != nil {
		return "", "", 0, err
	}
	name := dest.Name()
	defer dest.Close()
	r, err := z.Open()
	if err != nil {
		return "", "", 0, err
	}
	defer r.Close()
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(dest, h), io.LimitReader(r, modpackMaxFile0275+1))
	if e != nil {
		return "", "", 0, e
	}
	if n > modpackMaxFile0275 || uint64(n) != z.UncompressedSize64 {
		return "", "", 0, errors.New("override decompressed size mismatch")
	}
	if err = dest.Sync(); err != nil {
		return "", "", 0, err
	}
	if err = dest.Close(); err != nil {
		return "", "", 0, err
	}
	return name, hex.EncodeToString(h.Sum(nil)), n, nil
}
func modpackReportFromSpec0275(spec modpackSpec0275) modpackReport0275 {
	return modpackReport0275{SchemaVersion: "launcher.modpack-import.v1", Format: spec.Format, Name: spec.Name, Minecraft: spec.Minecraft, Loader: spec.Loader, LoaderVersion: spec.LoaderVersion, PackSHA256: spec.PackSHA256, Skipped: spec.Skipped, Status: "inspected", FileCount: len(spec.Files), OverrideCount: len(spec.Overrides)}
}
func importModpack0275(ctx context.Context, archive, destination, manual, api, key string, includeOptional bool, options factoryBuildOptions0271) (modpackReport0275, error) {
	return importModpackWithGates0276(ctx, archive, destination, manual, api, key, includeOptional, options, "", "local")
}
func importModpackWithGates0276(ctx context.Context, archive, destination, manual, api, key string, includeOptional bool, options factoryBuildOptions0271, permissionFile, distribution string) (modpackReport0275, error) {
	if distribution != "local" && distribution != "redistributable" {
		return modpackReport0275{}, errors.New("Параметр --distribution должен иметь значение local или redistributable")
	}

	spec, zr, err := parseModpack0275(archive, includeOptional)
	if err != nil {
		return modpackReport0275{}, err
	}
	defer zr.Close()
	report := modpackReportFromSpec0275(spec)
	report.Distribution = distribution
	if destination == "" {
		return report, errors.New("Требуется: --client-dir")
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return report, err
	}
	if _, e := os.Lstat(abs); e == nil {
		return report, errors.New("Для импорта модпака нужен новый несуществующий каталог; существующие клиенты никогда не перезаписываются")
	} else if !errors.Is(e, os.ErrNotExist) {
		return report, e
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		return report, err
	}
	work, err := os.MkdirTemp(filepath.Dir(abs), ".modpack-stage-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(work)
	cache := filepath.Join(work, "downloads")
	if err = os.Mkdir(cache, 0700); err != nil {
		return report, err
	}
	client := secureHTTPClient()
	client.Timeout = 3 * time.Minute
	if api == "" {
		api = "https://api.curseforge.com"
	}
	if spec.Format == "curseforge" && key == "" && len(spec.Files) > 0 {
		for _, f := range spec.Files {
			report.Missing = append(report.Missing, modpackMissing0275{Code: "api_key_required", Path: f.Source, Source: f.Source, Reason: "CurseForge API key required", ManualAction: "provide LAUNCHER_CURSEFORGE_API_KEY to resolve upstream hash; no unverified manual override is accepted"})
		}
		report.Status = "blocked"
		return report, errors.New("Необходим API-ключ CurseForge; артефакты не опубликованы")
	}
	downloaded := make([]mirrorArtifact0274, 0, len(spec.Files)+len(spec.Overrides)+1)
	imported := make([]modpackFile0275, 0, len(spec.Files)+len(spec.Overrides))
	byPath := map[string]bool{}
	var remoteBytes int64
	for i := range spec.Files {
		f := spec.Files[i]
		if spec.Format == "curseforge" {
			if e := curseFileMetadata0275(ctx, client, api, key, &f); e != nil {
				report.Missing = append(report.Missing, modpackMissing0275{Code: "metadata_unavailable", Path: f.Source, Source: f.Source, Reason: e.Error(), ManualAction: "resolve exact CurseForge project/file metadata and verified artifact"})
				continue
			}
		}
		if err := packOutputPath0275(f.Path); err != nil {
			return report, err
		}
		if f.Size > modpackMaxBytes0275-remoteBytes {
			return report, errors.New("Общий размер загрузок модпака превышает 2 ГиБ")
		}
		remoteBytes += f.Size
		if byPath[strings.ToLower(f.Path)] {
			return report, fmt.Errorf("Повторяющийся найденный файл мода %s", f.Path)
		}
		byPath[strings.ToLower(f.Path)] = true
		downloadedFile, sha, size, e := fetchModpackArtifact0275(ctx, client, cache, f, manual)
		if e != nil {
			report.Missing = append(report.Missing, missingModpackArtifact0276(f, e))
			continue
		}
		f.Acquisition = "download"
		if manual != "" && f.ManualName != "" {
			for _, rel := range []string{f.Path, f.ManualName} {
				candidate, e := secureManualSource0276(manual, rel)
				if e == nil {
					sum, _, e := hashFile(candidate)
					if e == nil && sum == sha {
						f.Acquisition = "manual-verified"
						break
					}
				}
			}
		}
		f.SHA256 = sha
		f.Size = size
		f.URLs = nil
		imported = append(imported, f)
		downloaded = append(downloaded, mirrorArtifact0274{Path: f.Path, File: downloadedFile, SHA256: sha})
	}
	for _, p := range sortedZipNames0275(spec.Overrides) {
		if byPath[strings.ToLower(p)] {
			return report, fmt.Errorf("Переопределение конфликтует с загруженным файлом %s", p)
		}
		f, sha, size, e := readZipOverride0275(spec.Overrides[p], cache)
		if e != nil {
			return report, e
		}
		downloaded = append(downloaded, mirrorArtifact0274{Path: p, File: f, SHA256: sha})
		imported = append(imported, modpackFile0275{Path: p, Source: "archive:override", SHA256: sha, Size: size})
	}
	sort.Slice(imported, func(i, j int) bool { return imported[i].Path < imported[j].Path })
	if distribution == "redistributable" && len(report.Missing) == 0 {
		permissions, e := readArtifactPermissions0276(permissionFile)
		if e != nil {
			report.Missing = append(report.Missing, modpackMissing0275{Code: "permissions_unavailable", Path: "permissions", Source: "permissions", Reason: e.Error(), ManualAction: "supply valid --permissions-file with exact per-file rights"})
		} else {
			result := verifyPermissionGrants0276(spec.PackSHA256, "", imported, permissions)
			report.Missing = append(report.Missing, result.Missing...)
		}
	}
	if len(report.Missing) > 0 {
		report.Status = "blocked"
		return report, fmt.Errorf("Недоступно %d обязательных артефактов модпака; результат не опубликован", len(report.Missing))
	}
	options.Loader = spec.Loader
	options.LoaderVersion = spec.LoaderVersion
	options.Minecraft = spec.Minecraft
	options.ClientDir = filepath.Join(work, "client")
	options.StrictUpstream = true
	if options.Loader == "vanilla" {
		options.LoaderVersion = ""
	}
	if _, err = executeFactoryBuild0271(ctx, options); err != nil {
		return report, fmt.Errorf("Установка клиента: %w", err)
	}
	// Сами доказательства входят в неизменяемую исходную квитанцию. Сохраняются только ID
	// и хеши, но не закрытые API-ключи или локальные пути кэша.
	report.Imported = imported
	report.Status = "complete"
	evidence, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return report, err
	}
	evidenceFile := filepath.Join(cache, "modpack-evidence.json")
	if err = os.WriteFile(evidenceFile, append(evidence, '\n'), 0600); err != nil {
		return report, err
	}
	evidenceHash := sha256HexBytes(append(evidence, '\n'))
	downloaded = append(downloaded, mirrorArtifact0274{Path: modpackEvidencePath0275, File: evidenceFile, SHA256: evidenceHash})
	plan, err := mirrorTransactional0274(ctx, options.ClientDir, func(stage string) ([]mirrorAction0274, error) {
		return mirrorAddArtifacts0274(ctx, stage, downloaded, "modpack-import")
	})
	if err != nil {
		return report, err
	}
	if err = verifyFactoryPlan0271(options.ClientDir, plan); err != nil {
		return report, err
	}
	if err = os.Rename(options.ClientDir, abs); err != nil {
		return report, err
	}
	report.PlanSHA256 = plan.ReproducibilitySHA256
	return report, nil
}
func handleModpack0275(args []string) error {
	if len(args) == 0 {
		return errors.New("modpack: inspect-modpack|import-modpack")
	}
	archive := flagValue(args[1:], "--file", "")
	if archive == "" {
		return errors.New("Необходимо указать --file с путём к .mrpack или ZIP-файлу CurseForge")
	}
	flags := args[1:]
	optional := strings.EqualFold(flagValue(flags, "--include-optional", "false"), "true")
	output := flagValue(flags, "--output", "")
	reportFile := flagValue(flags, "--report", "")
	dir := flagValue(flags, "--client-dir", "")
	if err := rejectFactoryOutputPath0271(dir, output); err != nil {
		return err
	}
	if err := rejectFactoryOutputPath0271(dir, reportFile); err != nil {
		return err
	}
	switch args[0] {
	case "inspect-modpack", "inspectmodpack":
		spec, zr, err := parseModpack0275(archive, optional)
		if err != nil {
			return err
		}
		zr.Close()
		report := modpackReportFromSpec0275(spec)
		for _, f := range spec.Files {
			if f.Path != "" {
				report.Pending = append(report.Pending, f.Path)
			} else {
				report.Pending = append(report.Pending, f.Source)
			}
		}
		sort.Strings(report.Pending)
		return writeOrPrintJSON(output, report)
	case "import-modpack", "importmodpack":
		target, err := parseVanillaTargets(flagValue(flags, "--target", currentVanillaTarget().OS+"/"+currentVanillaTarget().Arch))
		if err != nil {
			return err
		}
		workers, err := strconv.Atoi(flagValue(flags, "--workers", "12"))
		if err != nil {
			return err
		}
		timeout, err := time.ParseDuration(flagValue(flags, "--processor-timeout", "10m"))
		if err != nil {
			return err
		}
		options := factoryBuildOptions0271{Targets: target, Workers: workers, SharedCacheDir: strings.TrimSpace(flagValue(flags, "--shared-cache-dir", "")), ProcessorTimeout: timeout, ProcessorSandbox: flagValue(flags, "--processor-sandbox", "process"), VersionManifest: flagValue(flags, "--version-manifest", ""), AssetBaseURL: flagValue(flags, "--asset-base-url", ""), LibraryBaseURL: flagValue(flags, "--library-base-url", ""), MetaBaseURL: flagValue(flags, "--meta-base-url", ""), InstallerURL: flagValue(flags, "--installer-url", ""), InstallerSHA1: flagValue(flags, "--installer-sha1", ""), InstallerSourceFile: flagValue(flags, "--installer-file", ""), InstallerSourceSHA256: flagValue(flags, "--installer-sha256", ""), MavenMetadataURL: flagValue(flags, "--maven-metadata-url", ""), JavaExecutable: flagValue(flags, "--java", "")}
		manual := flagValue(flags, "--manual-dir", "")
		key := flagValue(flags, "--curseforge-api-key", os.Getenv("LAUNCHER_CURSEFORGE_API_KEY"))
		report, err := importModpackWithGates0276(context.Background(), archive, dir, manual, flagValue(flags, "--curseforge-api", ""), key, optional, options, flagValue(flags, "--permissions-file", ""), flagValue(flags, "--distribution", "local"))
		if reportFile != "" {
			if e := writeOrPrintJSON(reportFile, report); e != nil {
				return e
			}
		}
		if err != nil {
			return err
		}
		return writeOrPrintJSON(output, report)
	default:
		return fmt.Errorf("Неизвестная операция модпака %q", args[0])
	}
}
