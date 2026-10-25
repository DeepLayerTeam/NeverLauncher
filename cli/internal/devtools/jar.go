// Package devtools contains executable, offline Java bytecode tooling.
// Its findings are heuristics, not malware certification.
package devtools

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxJarBytes int64 = 256 << 20
const maxEntryBytes uint64 = 16 << 20
const maxEntries = 100000

type Finding struct {
	Class    string `json:"class"`
	Rule     string `json:"rule"`
	Evidence string `json:"evidence"`
}
type JarReport struct {
	Input       string    `json:"input"`
	SHA256      string    `json:"sha256"`
	Classes     int       `json:"classes"`
	Entries     int       `json:"entries"`
	Signed      bool      `json:"signed"`
	BytecodeMax int       `json:"bytecodeMajorMax"`
	Findings    []Finding `json:"findings"`
	Warnings    []string  `json:"warnings"`
}
type TransformReport struct {
	JarReport
	Output            string `json:"output"`
	OutputSHA256      string `json:"outputSha256"`
	ModifiedClasses   int    `json:"modifiedClasses"`
	RemovedAttributes int    `json:"removedDebugAttributes"`
}

type cpItem struct {
	kind byte
	a, b uint16
	val  string
}
type classParser struct {
	b  []byte
	i  int
	cp []cpItem
}

func (p *classParser) take(n int) ([]byte, error) {
	if n < 0 || n > len(p.b)-p.i {
		return nil, io.ErrUnexpectedEOF
	}
	b := p.b[p.i : p.i+n]
	p.i += n
	return b, nil
}
func (p *classParser) u1() (byte, error) {
	b, e := p.take(1)
	if e != nil {
		return 0, e
	}
	return b[0], nil
}
func (p *classParser) u2() (uint16, error) {
	b, e := p.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (p *classParser) u4() (uint32, error) {
	b, e := p.take(4)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint32(b), nil
}
func appendU2(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func appendU4(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }
func (p *classParser) utf(i uint16) string {
	if i == 0 || int(i) >= len(p.cp) || p.cp[i].kind != 1 {
		return ""
	}
	return p.cp[i].val
}
func (p *classParser) class(i uint16) string {
	if i == 0 || int(i) >= len(p.cp) || p.cp[i].kind != 7 {
		return ""
	}
	return p.utf(p.cp[i].a)
}
func (p *classParser) pool() (int, error) {
	magic, e := p.u4()
	if e != nil {
		return 0, e
	}
	if magic != 0xcafebabe {
		return 0, errors.New("not a JVM classfile")
	}
	_, e = p.u2()
	if e != nil {
		return 0, e
	}
	major, e := p.u2()
	if e != nil {
		return 0, e
	}
	if major < 45 || major > 70 {
		return 0, fmt.Errorf("unsupported class version %d", major)
	}
	count, e := p.u2()
	if e != nil {
		return 0, e
	}
	if count == 0 {
		return 0, errors.New("empty constant pool")
	}
	p.cp = make([]cpItem, count)
	for i := 1; i < int(count); i++ {
		t, e := p.u1()
		if e != nil {
			return 0, e
		}
		v := cpItem{kind: t}
		switch t {
		case 1:
			n, e := p.u2()
			if e != nil {
				return 0, e
			}
			b, e := p.take(int(n))
			if e != nil {
				return 0, e
			}
			v.val = string(b)
		case 3, 4:
			_, e = p.take(4)
		case 5, 6:
			_, e = p.take(8)
			if e == nil {
				i++
			}
		case 7, 8, 16, 19, 20:
			v.a, e = p.u2()
		case 9, 10, 11, 12, 17, 18:
			v.a, e = p.u2()
			if e == nil {
				v.b, e = p.u2()
			}
		case 15:
			_, e = p.u1()
			if e == nil {
				v.a, e = p.u2()
			}
		default:
			return 0, fmt.Errorf("unknown constant pool tag %d", t)
		}
		if e != nil {
			return 0, e
		}
		p.cp[i] = v
	}
	return int(major), nil
}
func (p *classParser) suspicious(className string) []Finding {
	rules := map[string]string{
		"java/lang/Runtime.exec": "process-execution", "java/lang/ProcessBuilder": "process-execution", "java/lang/System.load": "native-library", "java/lang/System.loadLibrary": "native-library",
		"java/lang/reflect": "reflection", "java/lang/invoke/MethodHandles$Lookup.defineClass": "class-definition", "sun/misc/Unsafe": "unsafe-access", "jdk/internal/misc/Unsafe": "unsafe-access",
		"java/net/Socket": "network-access", "java/net/URL.openConnection": "network-access", "java/nio/file/Files": "filesystem-access",
	}
	var result []Finding
	seen := make(map[string]bool)
	for _, e := range p.cp {
		var target string
		if e.kind == 7 {
			target = p.utf(e.a)
		}
		if e.kind == 10 || e.kind == 11 {
			owner := p.class(e.a)
			if int(e.b) < len(p.cp) {
				nt := p.cp[e.b]
				if nt.kind == 12 {
					target = owner + "." + p.utf(nt.a)
				}
			}
		}
		for pat, rule := range rules {
			if target == pat || strings.HasPrefix(target, pat+"/") {
				k := rule + ":" + target
				if !seen[k] {
					result = append(result, Finding{Class: className, Rule: rule, Evidence: target})
					seen[k] = true
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Rule != result[j].Rule {
			return result[i].Rule < result[j].Rule
		}
		return result[i].Evidence < result[j].Evidence
	})
	return result
}
func (p *classParser) attributes(remove map[string]bool, code bool) ([]byte, int, error) {
	count, e := p.u2()
	if e != nil {
		return nil, 0, e
	}
	out := []byte{0, 0}
	kept := 0
	removed := 0
	for i := 0; i < int(count); i++ {
		name, e := p.u2()
		if e != nil {
			return nil, 0, e
		}
		length, e := p.u4()
		if e != nil {
			return nil, 0, e
		}
		if uint64(length) > uint64(len(p.b)-p.i) {
			return nil, 0, io.ErrUnexpectedEOF
		}
		raw, _ := p.take(int(length))
		attr := p.utf(name)
		if attr == "" {
			return nil, 0, errors.New("invalid attribute name")
		}
		if remove[attr] {
			removed++
			continue
		}
		if code && attr == "Code" {
			nested, e2, err := stripCode(raw, p.cp)
			if err != nil {
				return nil, 0, err
			}
			raw = nested
			removed += e2
		}
		out = appendU2(out, name)
		out = appendU4(out, uint32(len(raw)))
		out = append(out, raw...)
		kept++
	}
	binary.BigEndian.PutUint16(out[:2], uint16(kept))
	return out, removed, nil
}
func stripCode(raw []byte, cp []cpItem) ([]byte, int, error) {
	q := &classParser{b: raw, cp: cp}
	_, e := q.take(4)
	if e != nil {
		return nil, 0, e
	}
	cl, e := q.u4()
	if e != nil {
		return nil, 0, e
	}
	if uint64(cl) > uint64(len(raw)-q.i) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	_, e = q.take(int(cl))
	if e != nil {
		return nil, 0, e
	}
	ex, e := q.u2()
	if e != nil {
		return nil, 0, e
	}
	_, e = q.take(int(ex) * 8)
	if e != nil {
		return nil, 0, e
	}
	head := append([]byte{}, raw[:q.i]...)
	tail, n, e := q.attributes(map[string]bool{"LineNumberTable": true, "LocalVariableTable": true, "LocalVariableTypeTable": true}, false)
	if e != nil {
		return nil, 0, e
	}
	if q.i != len(raw) {
		return nil, 0, errors.New("trailing Code attribute bytes")
	}
	return append(head, tail...), n, nil
}
func (p *classParser) members() ([]byte, int, error) {
	count, e := p.u2()
	if e != nil {
		return nil, 0, e
	}
	out := appendU2(nil, count)
	removed := 0
	for i := 0; i < int(count); i++ {
		h, e := p.take(6)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, h...)
		attrs, n, e := p.attributes(nil, true)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, attrs...)
		removed += n
	}
	return out, removed, nil
}
func parseClass(raw []byte, strip bool, className string) ([]byte, int, int, []Finding, error) {
	p := &classParser{b: raw}
	major, e := p.pool()
	if e != nil {
		return nil, 0, 0, nil, e
	}
	findings := p.suspicious(className)
	out := append([]byte{}, raw[:p.i]...)
	h, e := p.take(6)
	if e != nil {
		return nil, 0, 0, nil, e
	}
	out = append(out, h...)
	interfaces, e := p.u2()
	if e != nil {
		return nil, 0, 0, nil, e
	}
	start := p.i - 2
	_, e = p.take(int(interfaces) * 2)
	if e != nil {
		return nil, 0, 0, nil, e
	}
	out = append(out, raw[start:p.i]...)
	fields, n, e := p.members()
	if e != nil {
		return nil, 0, 0, nil, e
	}
	out = append(out, fields...)
	methods, m, e := p.members()
	if e != nil {
		return nil, 0, 0, nil, e
	}
	out = append(out, methods...)
	a, k, e := p.attributes(map[string]bool{"SourceFile": true, "SourceDebugExtension": true}, false)
	if e != nil {
		return nil, 0, 0, nil, e
	}
	out = append(out, a...)
	if p.i != len(raw) {
		return nil, 0, 0, nil, errors.New("trailing classfile bytes")
	}
	if !strip {
		return nil, major, 0, findings, nil
	}
	return out, major, n + m + k, findings, nil
}
func loadJar(file string) (*zip.ReadCloser, string, error) {
	f, e := os.Open(file)
	if e != nil {
		return nil, "", e
	}
	s, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, "", e
	}
	if !s.Mode().IsRegular() {
		f.Close()
		return nil, "", errors.New("JAR must be a regular file")
	}
	if s.Size() > maxJarBytes {
		f.Close()
		return nil, "", errors.New("JAR exceeds size limit")
	}
	sum := sha256.New()
	_, e = io.Copy(sum, f)
	f.Close()
	if e != nil {
		return nil, "", e
	}
	r, e := zip.OpenReader(file)
	return r, hex.EncodeToString(sum.Sum(nil)), e
}
func scanJar(file string, output string) (JarReport, *TransformReport, error) {
	var report JarReport
	reader, digest, e := loadJar(file)
	if e != nil {
		return report, nil, e
	}
	defer reader.Close()
	report.Input = file
	report.SHA256 = digest
	report.Findings = []Finding{}
	report.Warnings = []string{}
	report.Entries = len(reader.File)
	if report.Entries > maxEntries {
		return report, nil, errors.New("too many JAR entries")
	}
	seen := make(map[string]bool)
	var total uint64
	for _, f := range reader.File {
		n := f.Name
		if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, "\\") || path.Clean(n) != strings.TrimSuffix(n, "/") || strings.HasPrefix(n, "../") || strings.Contains(n, "/../") || f.Mode()&os.ModeSymlink != 0 {
			return report, nil, fmt.Errorf("unsafe JAR entry %q", n)
		}
		if seen[n] {
			return report, nil, fmt.Errorf("duplicate JAR entry %q", n)
		}
		seen[n] = true
		total += f.UncompressedSize64
		if f.UncompressedSize64 > maxEntryBytes || total > uint64(maxJarBytes) {
			return report, nil, errors.New("JAR expansion limit exceeded")
		}
		u := strings.ToUpper(n)
		if strings.HasPrefix(u, "META-INF/") && (strings.HasSuffix(u, ".SF") || strings.HasSuffix(u, ".RSA") || strings.HasSuffix(u, ".DSA") || strings.HasSuffix(u, ".EC")) {
			report.Signed = true
		}
	}
	if output != "" && report.Signed {
		return report, nil, errors.New("refusing to transform a signed JAR: transformation would invalidate signatures")
	}
	var tmp *os.File
	var zw *zip.Writer
	var cleanup func()
	var transform *TransformReport
	if output != "" {
		absIn, _ := filepath.Abs(file)
		absOut, e := filepath.Abs(output)
		if e != nil {
			return report, nil, e
		}
		if absIn == absOut {
			return report, nil, errors.New("output must differ from input")
		}
		info, e := os.Lstat(output)
		if e == nil {
			return report, nil, fmt.Errorf("output already exists (%s)", info.Mode())
		}
		if !os.IsNotExist(e) {
			return report, nil, e
		}
		tmp, e = os.CreateTemp(filepath.Dir(absOut), ".never-devtools-*.jar")
		if e != nil {
			return report, nil, e
		}
		cleanup = func() { tmp.Close(); os.Remove(tmp.Name()) }
		defer cleanup()
		zw = zip.NewWriter(tmp)
		transform = &TransformReport{Output: absOut}
	}
	for _, f := range reader.File {
		rc, e := f.Open()
		if e != nil {
			return report, nil, e
		}
		b, e := io.ReadAll(io.LimitReader(rc, int64(maxEntryBytes)+1))
		rc.Close()
		if e != nil {
			return report, nil, e
		}
		if len(b) > int(maxEntryBytes) {
			return report, nil, errors.New("JAR entry overflow")
		}
		isClass := strings.HasSuffix(f.Name, ".class") && !strings.HasSuffix(f.Name, "/")
		if isClass {
			report.Classes++
			newClass, major, removed, findings, e := parseClass(b, output != "", f.Name)
			if e != nil {
				return report, nil, fmt.Errorf("%s: %w", f.Name, e)
			}
			if major > report.BytecodeMax {
				report.BytecodeMax = major
			}
			report.Findings = append(report.Findings, findings...)
			if output != "" {
				b = newClass
				transform.RemovedAttributes += removed
				if removed > 0 {
					transform.ModifiedClasses++
				}
			}
		}
		if zw != nil {
			h := &zip.FileHeader{Name: f.Name, Method: zip.Deflate}
			if f.FileInfo().IsDir() {
				h.Method = zip.Store
			}
			h.SetMode(f.Mode().Perm())
			h.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
			w, e := zw.CreateHeader(h)
			if e != nil {
				return report, nil, e
			}
			if _, e = w.Write(b); e != nil {
				return report, nil, e
			}
		}
	}
	if report.Classes == 0 {
		return report, nil, errors.New("JAR has no class files")
	}
	if report.Signed {
		report.Warnings = append(report.Warnings, "JAR signatures are present; class analysis does not verify trust chains")
	}
	report.Warnings = append(report.Warnings, "Indicators are heuristic; absence of findings does not imply safe code")
	if zw != nil {
		if e = zw.Close(); e != nil {
			return report, nil, e
		}
		if e = tmp.Sync(); e != nil {
			return report, nil, e
		}
		if e = tmp.Close(); e != nil {
			return report, nil, e
		}
		if e = os.Link(tmp.Name(), output); e != nil {
			return report, nil, e
		}
		out, _, e2 := loadJar(output)
		if e2 != nil {
			os.Remove(output)
			return report, nil, e2
		}
		out.Close()
		digestFile, e2 := os.Open(output)
		if e2 != nil {
			return report, nil, e2
		}
		h := sha256.New()
		_, e2 = io.Copy(h, digestFile)
		digestFile.Close()
		if e2 != nil {
			return report, nil, e2
		}
		transform.OutputSHA256 = hex.EncodeToString(h.Sum(nil))
		transform.JarReport = report
	}
	return report, transform, nil
}
func AnalyzeJar(file string) (JarReport, error) { r, _, e := scanJar(file, ""); return r, e }
func StripDebugJar(input, output string) (TransformReport, error) {
	_, r, e := scanJar(input, output)
	if e != nil {
		return TransformReport{}, e
	}
	return *r, nil
}

// Encode a deterministic JSON body from bytes without any network calls.
func CleanClass(bytes []byte) ([]byte, error) {
	out, _, _, _, e := parseClass(bytes, true, "test")
	return out, e
}
