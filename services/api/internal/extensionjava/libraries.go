package extensionjava

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const libraryPrefix0482 = "META-INF/launcher/libs/"
const libraryLock0482 = "META-INF/launcher/libraries.lock"

var libraryPath0482 = regexp.MustCompile(`^META-INF/launcher/libs/[a-zA-Z0-9._-]+\.jar$`)
var coordinate0482 = regexp.MustCompile(`^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$`)
var version0482 = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?(-[A-Za-z0-9.-]+)?(\+[A-Za-z0-9.-]+)?$`)
var digest0482 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type LibraryInfo0482 struct {
	Path          string `json:"path"`
	Coordinate    string `json:"coordinate"`
	Version       string `json:"version"`
	APIConstraint string `json:"apiConstraint"`
}

func readBounded0482(file *zip.File, max int64) ([]byte, error) {
	if file.UncompressedSize64 > uint64(max) {
		return nil, errors.New("oversized library entry")
	}
	r, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("library exceeds size limit")
	}
	return data, nil
}

// inspectLibraries0482 проверяет настоящие байты внутри подписанного JAR хоста. Для
// каждого встроенного JAR обязательна блокировка; внешний Class-Path никогда не
// принимается.
func inspectLibraries0482(zr *zip.ReadCloser, outerClasses map[string]bool) ([]LibraryInfo0482, int, int, error) {
	entries := map[string]*zip.File{}
	for _, f := range zr.File {
		entries[f.Name] = f
	}
	lock := entries[libraryLock0482]
	var lines []string
	if lock != nil {
		text, err := readBounded0482(lock, 65536)
		if err != nil {
			return nil, 0, 0, err
		}
		if !utf8.Valid(text) {
			return nil, 0, 0, errors.New("library lock must be UTF-8")
		}
		lines = strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
		if len(lines) == 0 || len(lines) == 1 && lines[0] == "" {
			return nil, 0, 0, errors.New("empty library lock")
		}
		if len(lines) > 64 {
			return nil, 0, 0, errors.New("more than 64 libraries")
		}
	}
	recorded := map[string]bool{}
	coords := map[string]bool{}
	classes := map[string]bool{}
	for class := range outerClasses {
		classes[class] = true
	}
	var info []LibraryInfo0482
	var maxMajor, extraClasses int
	var total int64
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			return nil, 0, 0, errors.New("invalid library lock row")
		}
		name, id, version, hash, api := fields[0], fields[1], fields[2], fields[3], fields[4]
		if !libraryPath0482.MatchString(name) || !coordinate0482.MatchString(id) || !version0482.MatchString(version) || !digest0482.MatchString(hash) || api == "" || recorded[name] || coords[id] {
			return nil, 0, 0, errors.New("invalid or duplicate dependency identity")
		}
		recorded[name] = true
		coords[id] = true
		file := entries[name]
		if file == nil || file.FileInfo().IsDir() {
			return nil, 0, 0, fmt.Errorf("bundled library %s missing", name)
		}
		contents, err := readBounded0482(file, 16<<20)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("read %s: %w", name, err)
		}
		total += int64(len(contents))
		if total > 64<<20 {
			return nil, 0, 0, errors.New("bundled libraries exceed 64 MiB")
		}
		sum := sha256.Sum256(contents)
		if hex.EncodeToString(sum[:]) != hash {
			return nil, 0, 0, fmt.Errorf("library checksum mismatch %s", name)
		}
		archive, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("invalid nested JAR %s: %w", name, err)
		}
		if len(archive.File) == 0 || len(archive.File) > 4096 {
			return nil, 0, 0, errors.New("invalid nested JAR entry count")
		}
		names := map[string]bool{}
		var expanded uint64
		for _, part := range archive.File {
			fn := part.Name
			if fn == "" || strings.HasPrefix(fn, "/") || strings.ContainsAny(fn, "\\\x00") || strings.Contains(fn, "//") || path.Clean(fn) != strings.TrimSuffix(fn, "/") || strings.Contains("/"+fn, "/../") || fn == ".." || names[fn] || part.Mode()&os.ModeSymlink != 0 {
				return nil, 0, 0, fmt.Errorf("invalid nested JAR entry %q", fn)
			}
			names[fn] = true
			if part.UncompressedSize64 > 16<<20 {
				return nil, 0, 0, errors.New("nested JAR oversized entry")
			}
			expanded += part.UncompressedSize64
			if expanded > 64<<20 {
				return nil, 0, 0, errors.New("nested JAR expansion exceeds limit")
			}
			if strings.EqualFold(fn, "META-INF/MANIFEST.MF") {
				data, err := readBounded0482(part, 65536)
				if err != nil {
					return nil, 0, 0, err
				}
				lower := strings.ToLower(strings.ReplaceAll(string(data), "\r\n", "\n"))
				if strings.Contains("\n"+lower, "\nclass-path:") || strings.Contains("\n"+lower, "\nmulti-release: true") {
					return nil, 0, 0, errors.New("nested library external classpath or multi-release forbidden")
				}
			}
			if strings.HasPrefix(fn, "META-INF/versions/") {
				return nil, 0, 0, errors.New("versioned nested libraries are unsupported")
			}
			if !strings.HasSuffix(fn, ".class") {
				if _, err := readBounded0482(part, 16<<20); err != nil {
					return nil, 0, 0, err
				}
				continue
			}
			if strings.HasPrefix(fn, "java/") || strings.HasPrefix(fn, "javax/") || strings.HasPrefix(fn, "sun/") || strings.HasPrefix(fn, "jdk/") || strings.HasPrefix(fn, "ru/launcher/sdk/") || strings.HasPrefix(fn, "com/sun/") || strings.HasPrefix(fn, "org/w3c/") || strings.HasPrefix(fn, "org/xml/") {
				return nil, 0, 0, fmt.Errorf("library overrides protected namespace: %s", fn)
			}
			if classes[fn] {
				return nil, 0, 0, fmt.Errorf("class conflict between host and libraries: %s", fn)
			}
			classes[fn] = true
			extraClasses++
			payload, err := readBounded0482(part, 16<<20)
			if err != nil {
				return nil, 0, 0, err
			}
			if len(payload) < 8 || binary.BigEndian.Uint32(payload[:4]) != 0xcafebabe || binary.BigEndian.Uint16(payload[4:6]) == 65535 {
				return nil, 0, 0, fmt.Errorf("invalid nested class %s", fn)
			}
			major := int(binary.BigEndian.Uint16(payload[6:8]))
			if major < 45 || major > 100 {
				return nil, 0, 0, fmt.Errorf("unsupported nested class version %s", fn)
			}
			if major > maxMajor {
				maxMajor = major
			}
		}
		info = append(info, LibraryInfo0482{Path: name, Coordinate: id, Version: version, APIConstraint: api})
	}
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, libraryPrefix0482) && strings.HasSuffix(f.Name, ".jar") && !recorded[f.Name] {
			return nil, 0, 0, fmt.Errorf("unlocked nested JAR %s", f.Name)
		}
	}
	return info, extraClasses, maxMajor, nil
}
