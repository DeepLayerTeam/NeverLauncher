// Package installer verifies and installs offline signed NeverLauncher bundles.
// The trust root MUST be passed independently from the release bundle.
package installer

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const maxFile = int64(512 << 20)
const maxTotal = int64(1 << 30)

type Entry struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Executable bool   `json:"executable"`
}
type Manifest struct {
	Format  string  `json:"format"`
	Version string  `json:"version"`
	Files   []Entry `json:"files"`
}

type verifiedFile struct {
	Entry Entry
	Data  []byte
}
type Verified struct {
	Manifest Manifest
	files    []verifiedFile
}

func validRel(s string) bool {
	if s == "" || strings.ContainsAny(s, "\\\x00") || strings.HasPrefix(s, "/") || path.Clean(s) != s || s == "." {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." || part == "" {
			return false
		}
	}
	return true
}
func validVersion(s string) bool {
	if s == "" || len(s) > 64 || strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func decodeKey(filename string, size int) ([]byte, error) {
	stat, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0022 != 0 {
		return nil, errors.New("signing key file must be regular and not writable by others")
	}
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("expected %d-byte hex Ed25519 key", size)
	}
	return decoded, nil
}

// Verify reads the complete archive BEFORE returning a verified set of files.
// It rejects unknown entries, duplicates, nonregular files and zip bombs.
func Verify(archive, trustKey string) (*Verified, error) {
	pub, err := decodeKey(trustKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	entries := make(map[string]*zip.File)
	var total uint64
	for _, f := range z.File {
		if !validRel(f.Name) || !f.Mode().IsRegular() || f.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unsupported bundle entry %q", f.Name)
		}
		if _, ok := entries[f.Name]; ok {
			return nil, errors.New("duplicate bundle entry")
		}
		if f.UncompressedSize64 > uint64(maxFile) {
			return nil, errors.New("oversized file")
		}
		total += f.UncompressedSize64
		if total > uint64(maxTotal) {
			return nil, errors.New("oversized bundle")
		}
		entries[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f := entries[name]
		if f == nil {
			return nil, fmt.Errorf("missing %s", name)
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(io.LimitReader(r, maxFile+1))
	}
	raw, err := read("manifest.json")
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("manifest too large")
	}
	sigRaw, err := read("manifest.sig")
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return nil, errors.New("bundle signature verification failed")
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if manifest.Format != "neverlauncher-offline-bundle-v1" || !validVersion(manifest.Version) || len(manifest.Files) == 0 {
		return nil, errors.New("invalid signed manifest")
	}
	if len(entries) != len(manifest.Files)+2 {
		return nil, errors.New("bundle contains unsigned entries")
	}
	seen := make(map[string]bool)
	res := &Verified{Manifest: manifest}
	for _, item := range manifest.Files {
		if !validRel(item.Path) || strings.HasPrefix(item.Path, ".") || seen[item.Path] || item.Size < 0 || item.Size > maxFile || len(item.SHA256) != 64 {
			return nil, errors.New("invalid or duplicate manifest item")
		}
		seen[item.Path] = true
		data, err := read("payload/" + item.Path)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		if int64(len(data)) != item.Size || !strings.EqualFold(hex.EncodeToString(hash[:]), item.SHA256) {
			return nil, fmt.Errorf("payload checksum mismatch: %s", item.Path)
		}
		res.files = append(res.files, verifiedFile{item, data})
	}
	return res, nil
}
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Install performs a no-overwrite atomic directory commit. It never runs the
// installed binary nor follows bundle-controlled symlinks.
func (v *Verified) Install(target string) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || target == "/" {
		return errors.New("target must be absolute, clean, and not root")
	}
	if _, err := os.Lstat(target); err == nil {
		return errors.New("destination already exists; existing installation is untouched")
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(target)
	st, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("destination parent is unsafe")
	}
	temp, err := os.MkdirTemp(parent, ".neverlauncher-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if err := os.Chmod(temp, 0700); err != nil {
		return err
	}
	for _, f := range v.files {
		dest := filepath.Join(temp, filepath.FromSlash(f.Entry.Path))
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		perm := os.FileMode(0644)
		if f.Entry.Executable {
			perm = 0755
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			return err
		}
		if _, err = out.Write(f.Data); err != nil {
			out.Close()
			return err
		}
		if err = out.Sync(); err != nil {
			out.Close()
			return err
		}
		if err = out.Close(); err != nil {
			return err
		}
	}
	// Release artifacts contain no installer-generated secrets. Set public read/exec
	// permissions so a dedicated systemd service user can execute root-installed
	// binaries; credentials are provisioned separately with mode 0600.
	if err := filepath.Walk(temp, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(p, 0755)
		}
		return nil
	}); err != nil {
		return err
	}
	// Sync nested directories before atomic publication.
	dirs := map[string]bool{temp: true}
	for _, f := range v.files {
		for d := filepath.Dir(filepath.Join(temp, filepath.FromSlash(f.Entry.Path))); strings.HasPrefix(d, temp); d = filepath.Dir(d) {
			dirs[d] = true
			if d == temp {
				break
			}
		}
	}
	names := make([]string, 0, len(dirs))
	for name := range dirs {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, name := range names {
		if err := syncDir(name); err != nil {
			return err
		}
	}
	// Linux renameat2 NOREPLACE ensures a race can't replace an existing install.
	if err := noReplace(temp, target); err != nil {
		return err
	}
	if err := syncDir(parent); err != nil {
		return fmt.Errorf("published but parent fsync failed: %w", err)
	}
	return nil
}
func Pack(source, version, privateKey, destination string) error {
	if !validVersion(version) {
		return errors.New("invalid version")
	}
	seed, err := decodeKey(privateKey, ed25519.SeedSize)
	if err == nil {
		st, e := os.Stat(privateKey)
		if e != nil || st.Mode().Perm()&0077 != 0 {
			return errors.New("private signing seed must be 0600")
		}
	}
	if err != nil {
		return err
	}
	var manifest Manifest
	manifest.Format = "neverlauncher-offline-bundle-v1"
	manifest.Version = version
	payload := make(map[string][]byte)
	var total int64
	err = filepath.Walk(source, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("bundle source contains nonregular file")
		}
		rel, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !validRel(rel) || rel == "manifest.json" || rel == "manifest.sig" {
			return errors.New("unsafe path")
		}
		if info.Size() > maxFile {
			return errors.New("file too large")
		}
		total += info.Size()
		if total > maxTotal {
			return errors.New("bundle too large")
		}
		contents, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		h := sha256.Sum256(contents)
		manifest.Files = append(manifest.Files, Entry{Path: rel, Size: int64(len(contents)), SHA256: hex.EncodeToString(h[:]), Executable: info.Mode()&0111 != 0})
		payload[rel] = contents
		return nil
	})
	if err != nil {
		return err
	}
	if len(manifest.Files) == 0 {
		return errors.New("empty source")
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), raw)
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	z := zip.NewWriter(out)
	write := func(name string, data []byte, executable bool) error {
		mode := os.FileMode(0600)
		if executable {
			mode = 0700
		}
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(mode)
		w, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	if err := write("manifest.json", raw, false); err != nil {
		return err
	}
	if err := write("manifest.sig", []byte(hex.EncodeToString(sig)), false); err != nil {
		return err
	}
	for _, file := range manifest.Files {
		if err := write("payload/"+file.Path, payload[file.Path], file.Executable); err != nil {
			return err
		}
	}
	if err := z.Close(); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
