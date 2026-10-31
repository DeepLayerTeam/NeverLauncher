// Package gravitinventory inventories and exports Gravit source installations.
// It never executes untrusted JARs or retains source credentials in reports.
package gravitinventory

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	Format                 = "launcher.gravit-source-inventory.v1"
	MaxSourceBytes   int64 = 512 << 20
	MaxExpandedBytes int64 = 2 << 30
	MaxFiles               = 30000
	MaxConfigBytes   int64 = 2 << 20
	ManifestPath           = ".migration/inventory.json"
)

type File struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Sensitive bool   `json:"sensitive,omitempty"`
}
type Inventory struct {
	Format           string         `json:"format"`
	SourceSHA256     string         `json:"sourceSha256"`
	SourceBytes      int64          `json:"sourceBytes"`
	SourceEntries    int            `json:"sourceEntries"`
	TotalBytes       int64          `json:"totalBytes"`
	SensitiveEntries int            `json:"sensitiveEntries"`
	Categories       map[string]int `json:"categories"`
	AuthProviders    map[string]int `json:"authProviders"`
	TextureProviders map[string]int `json:"textureProviders"`
	OptionalActions  map[string]int `json:"optionalActions"`
	ServerReferences int            `json:"serverReferences"`
	Files            []File         `json:"files"`
	ManifestSHA256   string         `json:"manifestSha256"`
}

// canonical excludes the manifest hash itself; it is the exact JSON included
// in every exported ZIP. Report fields are derived from file bytes, not headers.
func (v Inventory) canonical() ([]byte, error) {
	v.ManifestSHA256 = ""
	return json.MarshalIndent(v, "", "  ")
}
func (v Inventory) Manifest() ([]byte, error) {
	if v.Format != Format {
		return nil, errors.New("unsupported source inventory format")
	}
	b, e := v.canonical()
	if e != nil {
		return nil, e
	}
	d := sha256.Sum256(b)
	if hex.EncodeToString(d[:]) != v.ManifestSHA256 {
		return nil, errors.New("inventory manifest checksum mismatch")
	}
	return append(b, '\n'), nil
}

func entryKind(n string) (string, bool) {
	l := strings.ToLower(n)
	base := path.Base(l)
	switch {
	case base == "launchserver.json":
		return "launchserver", true
	case base == "launchserverruntime.json" || base == "launchserverruntimeconfig.json" || strings.HasPrefix(l, "runtime/") || strings.Contains(l, "/runtime/"):
		return "runtime", strings.HasSuffix(l, ".json")
	case base == "serverwrapper.json" || base == "serverwrapperconfig.json" || strings.Contains(l, "serverwrapper/"):
		return "server_wrapper", true
	case strings.HasPrefix(l, "profiles/") && strings.HasSuffix(l, ".json") || strings.Contains(l, "/profiles/") && strings.HasSuffix(l, ".json"):
		return "client_profile", true
	case strings.HasPrefix(l, "modules/") || strings.Contains(l, "/modules/"):
		return "module", strings.HasSuffix(l, ".env") || strings.HasSuffix(l, ".json")
	case strings.HasPrefix(l, "libraries/") || strings.Contains(l, "/libraries/") || strings.HasPrefix(l, "lib/") || strings.Contains(l, "/lib/"):
		return "library", false
	case strings.HasPrefix(l, "assets/") || strings.Contains(l, "/assets/"):
		return "asset", false
	case strings.HasPrefix(l, "clients/") || strings.Contains(l, "/clients/") || strings.HasPrefix(l, "updates/") || strings.Contains(l, "/updates/"):
		return "client", false
	case strings.HasPrefix(l, "skins/") || strings.Contains(l, "/skins/") || strings.HasPrefix(l, "cloaks/") || strings.Contains(l, "/cloaks/") || strings.HasPrefix(l, "capes/"):
		return "texture", false
	case strings.HasSuffix(l, ".pem") || strings.HasSuffix(l, ".key") || strings.HasSuffix(l, ".p12") || strings.HasSuffix(l, ".pfx") || strings.Contains(l, "/keys/"):
		return "key", true
	case base == ".env" || strings.HasSuffix(l, ".env") || strings.Contains(l, "auth") && strings.HasSuffix(l, ".json"):
		return "authentication", true
	default:
		return "other", false
	}
}
func sensitive(n, kind string) bool {
	l := strings.ToLower(n)
	base := path.Base(l)
	return kind == "key" || kind == "launchserver" || kind == "server_wrapper" || kind == "authentication" || base == ".env" || strings.HasSuffix(l, ".env") || strings.Contains(l, "password") || strings.Contains(l, "secret") || strings.Contains(l, "private")
}
func validName(n string, isDir bool) error {
	if n == "" || strings.HasPrefix(n, "/") || strings.ContainsAny(n, "\\:\x00\r\n\t") || strings.HasPrefix(strings.ToLower(n), ".migration/") || strings.EqualFold(n, ".migration") {
		return fmt.Errorf("unsafe/reserved ZIP path %q", n)
	}
	p := strings.TrimSuffix(n, "/")
	if path.Clean(p) != p || p == "." || p == ".." || strings.HasPrefix(p, "../") || len(n) > 2048 {
		return fmt.Errorf("unsafe ZIP path %q", n)
	}
	if isDir != strings.HasSuffix(n, "/") {
		return fmt.Errorf("invalid ZIP directory marker %q", n)
	}
	return nil
}
func safeFiles(z *zip.Reader) ([]*zip.File, error) {
	if len(z.File) == 0 || len(z.File) > MaxFiles {
		return nil, errors.New("ZIP entry count exceeds limit (30000)")
	}
	seen := make(map[string]struct{}, len(z.File))
	names := make(map[string]bool, len(z.File))
	var total int64
	files := make([]*zip.File, 0, len(z.File))
	for _, f := range z.File {
		isDir := f.FileInfo().IsDir()
		if e := validName(f.Name, isDir); e != nil {
			return nil, e
		}
		if f.Mode().Type() != 0 && !isDir {
			return nil, fmt.Errorf("unsupported special file %q", f.Name)
		}
		n := strings.ToLower(strings.TrimSuffix(f.Name, "/"))
		if _, ok := seen[n]; ok {
			return nil, fmt.Errorf("duplicate ZIP path %q", f.Name)
		}
		seen[n] = struct{}{}
		names[n] = isDir
		if isDir {
			continue
		}
		if f.Flags&1 != 0 || (f.Method != zip.Store && f.Method != zip.Deflate) {
			return nil, fmt.Errorf("encrypted/unsupported ZIP member %q", f.Name)
		}
		if f.UncompressedSize64 > uint64(MaxExpandedBytes) || f.UncompressedSize64 > uint64(MaxExpandedBytes)-uint64(total) {
			return nil, errors.New("ZIP expanded size exceeds 2 GiB")
		}
		total += int64(f.UncompressedSize64)
		if f.UncompressedSize64 > f.CompressedSize64*1000+8192 {
			return nil, fmt.Errorf("ZIP expansion ratio too high at %q", f.Name)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, errors.New("ZIP does not contain source files")
	}
	for n, isDir := range names {
		for p := path.Dir(n); p != "."; p = path.Dir(p) {
			if dir, ok := names[p]; ok && !dir {
				return nil, fmt.Errorf("file/directory conflict: %q", n)
			}
		}
		_ = isDir
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}
func copyChecked(ctx context.Context, src *zip.File, dst io.Writer) (int64, error) {
	reader, e := src.Open()
	if e != nil {
		return 0, e
	}
	defer reader.Close()
	buf := make([]byte, 128<<10)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return size, err
		}
		n, err := reader.Read(buf)
		if n > 0 {
			size += int64(n)
			if size > int64(src.UncompressedSize64) {
				return size, errors.New("ZIP expanded beyond declared size")
			}
			wrote, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				return size, writeErr
			}
			if wrote != n {
				return size, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return size, err
		}
	}
	if size != int64(src.UncompressedSize64) {
		return size, errors.New("ZIP member size differs from header")
	}
	return size, nil
}
func readObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	if e := uniqueJSON(d); e != nil {
		return nil, e
	}
	var trailing any
	if e := d.Decode(&trailing); e != io.EOF {
		return nil, errors.New("extra JSON data")
	}
	var obj map[string]json.RawMessage
	if e := json.Unmarshal(data, &obj); e != nil || obj == nil {
		return nil, errors.New("expected JSON object")
	}
	return obj, nil
}
func uniqueJSON(d *json.Decoder) error {
	tok, e := d.Token()
	if e != nil {
		return errors.New("invalid JSON")
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return errors.New("duplicate/invalid JSON key")
			}
			seen[s] = true
			if len(seen) > 100000 {
				return errors.New("JSON object too large")
			}
			if e := uniqueJSON(d); e != nil {
				return e
			}
		}
		_, e := d.Token()
		return e
	case json.Delim('['):
		i := 0
		for d.More() {
			i++
			if i > 100000 {
				return errors.New("JSON array too large")
			}
			if e := uniqueJSON(d); e != nil {
				return e
			}
		}
		_, e := d.Token()
		return e
	default:
		return nil
	}
}
func typeField(data json.RawMessage) string {
	var ob map[string]json.RawMessage
	if json.Unmarshal(data, &ob) != nil {
		return "unknown"
	}
	var s string
	if json.Unmarshal(ob["type"], &s) != nil {
		return "unknown"
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 64 {
		return "unknown"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "unknown"
		}
	}
	if s == "" {
		return "unknown"
	}
	return s
}
func gather(v *Inventory, kind string, config []byte) error {
	obj, e := readObject(config)
	if e != nil {
		return e
	}
	if kind == "launchserver" {
		var auth map[string]json.RawMessage
		if json.Unmarshal(obj["auth"], &auth) == nil {
			for _, a := range auth {
				var pair map[string]json.RawMessage
				if json.Unmarshal(a, &pair) == nil {
					var core json.RawMessage = pair["core"]
					v.AuthProviders[typeField(core)]++
					if texture, ok := pair["textureProvider"]; ok {
						v.TextureProviders[typeField(texture)]++
					}
				}
			}
		}
		if x, ok := obj["textureProvider"]; ok {
			v.TextureProviders[typeField(x)]++
		}
	}
	if kind == "client_profile" {
		for _, field := range []string{"updateOptional", "optional", "optionals", "optionalFiles", "optionalActions"} {
			var options []map[string]json.RawMessage
			if raw := obj[field]; len(raw) > 0 && json.Unmarshal(raw, &options) == nil {
				for _, option := range options {
					var actions []json.RawMessage
					if json.Unmarshal(option["actions"], &actions) == nil {
						for _, action := range actions {
							v.OptionalActions[typeField(action)]++
						}
					}
				}
			}
		}
		var servers []json.RawMessage
		if json.Unmarshal(obj["servers"], &servers) == nil {
			v.ServerReferences += len(servers)
		}
	}
	return nil
}

// Inspect performs a complete streaming read, including CRC validation and
// SHA-256 of every member; no ZIP filename is interpreted as a host file path.
func Inspect(ctx context.Context, src io.ReaderAt, archiveSize int64, sourceDigest string) (Inventory, error) {
	if archiveSize < 1 || archiveSize > MaxSourceBytes || len(sourceDigest) != 64 {
		return Inventory{}, errors.New("source archive size/digest invalid")
	}
	z, e := zip.NewReader(src, archiveSize)
	if e != nil {
		return Inventory{}, e
	}
	files, e := safeFiles(z)
	if e != nil {
		return Inventory{}, e
	}
	v := Inventory{Format: Format, SourceSHA256: sourceDigest, SourceBytes: archiveSize, SourceEntries: len(files), Files: make([]File, 0, len(files)), Categories: map[string]int{}, AuthProviders: map[string]int{}, TextureProviders: map[string]int{}, OptionalActions: map[string]int{}}
	for _, f := range files {
		kind, parse := entryKind(f.Name)
		h := sha256.New()
		var target io.Writer = h
		var capture bytes.Buffer
		if parse {
			if f.UncompressedSize64 > uint64(MaxConfigBytes) {
				return Inventory{}, fmt.Errorf("configuration %q exceeds 2 MiB", f.Name)
			}
			target = io.MultiWriter(h, &capture)
		}
		n, e := copyChecked(ctx, f, target)
		if e != nil {
			return Inventory{}, fmt.Errorf("ZIP member %q: %w", f.Name, e)
		}
		item := File{Path: f.Name, Kind: kind, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Sensitive: sensitive(f.Name, kind)}
		if parse && strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			if e := gather(&v, kind, capture.Bytes()); e != nil {
				return Inventory{}, fmt.Errorf("invalid %s at %q: %w", kind, f.Name, e)
			}
		}
		v.TotalBytes += n
		v.Categories[kind]++
		if item.Sensitive {
			v.SensitiveEntries++
		}
		v.Files = append(v.Files, item)
	}
	b, e := v.canonical()
	if e != nil {
		return Inventory{}, e
	}
	digest := sha256.Sum256(b)
	v.ManifestSHA256 = hex.EncodeToString(digest[:])
	return v, nil
}

// Export creates a byte-for-byte verifiable, reproducible ZIP of all source
// files and a canonical checksum manifest. Export is sensitive: it may contain
// credentials; callers must use TLS and save to a mode-0600 file.
func Export(ctx context.Context, out io.Writer, src io.ReaderAt, size int64, v Inventory) error {
	// The second inspection is deliberate: the export cannot be made with
	// a mismatched/modified snapshot, even when the source is a mutable file.
	actual, e := Inspect(ctx, src, size, v.SourceSHA256)
	if e != nil {
		return e
	}
	if actual.ManifestSHA256 != v.ManifestSHA256 {
		return errors.New("source changed since inventory")
	}
	z, e := zip.NewReader(src, size)
	if e != nil {
		return e
	}
	files, e := safeFiles(z)
	if e != nil {
		return e
	}
	manifest, e := v.Manifest()
	if e != nil {
		return e
	}
	zw := zip.NewWriter(out)
	write := func(name string, content func(io.Writer) error) error {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
		hdr.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		hdr.SetMode(0600)
		w, e := zw.CreateHeader(hdr)
		if e != nil {
			return e
		}
		return content(w)
	}
	if e := write(ManifestPath, func(w io.Writer) error { _, e := w.Write(manifest); return e }); e != nil {
		return e
	}
	for _, f := range files {
		current := f
		if e := write(current.Name, func(w io.Writer) error { _, e := copyChecked(ctx, current, w); return e }); e != nil {
			return e
		}
	}
	return zw.Close()
}

// Spool makes a bounded, private temporary copy of an HTTP request with an
// independently verified source digest. Caller must Close and Remove the file.
func Spool(ctx context.Context, source io.Reader) (*os.File, int64, string, error) {
	f, e := os.CreateTemp("", "gravit-source-*.zip")
	if e != nil {
		return nil, 0, "", e
	}
	_ = f.Chmod(0600)
	// On Unix unlink immediately: a killed worker cannot leave sensitive
	// config/credential ZIPs in a discoverable temp path.
	if runtime.GOOS != "windows" {
		if err := os.Remove(f.Name()); err != nil {
			f.Close()
			return nil, 0, "", err
		}
	}
	cleanup := func(err error) (*os.File, int64, string, error) {
		name := f.Name()
		f.Close()
		os.Remove(name)
		return nil, 0, "", err
	}
	h := sha256.New()
	n, e := copyLimited(ctx, io.MultiWriter(f, h), source, MaxSourceBytes)
	if e != nil {
		return cleanup(e)
	}
	if n == 0 {
		return cleanup(errors.New("empty Gravit source ZIP"))
	}
	if e = f.Sync(); e != nil {
		return cleanup(e)
	}
	return f, n, hex.EncodeToString(h.Sum(nil)), nil
}
func copyLimited(ctx context.Context, dst io.Writer, src io.Reader, max int64) (int64, error) {
	var n int64
	buf := make([]byte, 128<<10)
	for {
		if e := ctx.Err(); e != nil {
			return n, e
		}
		r, e := src.Read(buf)
		if r > 0 {
			n += int64(r)
			if n > max {
				return n, errors.New("source ZIP exceeds 512 MiB")
			}
			if _, w := dst.Write(buf[:r]); w != nil {
				return n, w
			}
		}
		if e == io.EOF {
			return n, nil
		}
		if e != nil {
			return n, e
		}
	}
}
