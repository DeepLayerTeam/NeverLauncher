// Package gravitmodules statically inspects source-pinned Gravit modules and
// ServerWrapper settings. It NEVER loads, links or executes untrusted code.
package gravitmodules

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
	"sort"
	"strings"
	"unicode/utf8"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

const Format = "launcher.gravit-modules.v1"
const maxJar int64 = 32 << 20
const maxJarEntries = 12000
const maxJarExpanded uint64 = 128 << 20
const maxWrapper int64 = 2 << 20

type Module struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Name           string `json:"name"`
	Implementation string `json:"implementation"` // built_in_equivalent | compatible_adapter | source_port | blocker
	Status         string `json:"status"`         // manual | blocked
	Reason         string `json:"reason"`
	LaunchHook     bool   `json:"launchHook"`
	AuthHook       bool   `json:"authHook"`
	SourcesPresent bool   `json:"sourcesPresent"`
}
type Wrapper struct {
	Path                 string `json:"path"`
	SHA256               string `json:"sha256"`
	Mode                 string `json:"mode"` // inline | config | environment
	ServerName           string `json:"serverName,omitempty"`
	LegacyAddressPresent bool   `json:"legacyAddressPresent"`
	LegacyTokenPresent   bool   `json:"legacyTokenPresent"`
	Replacement          string `json:"replacement"`
	Status               string `json:"status"` // manual | blocked
	Reason               string `json:"reason"`
}
type Report struct {
	Format          string    `json:"format"`
	SourceSHA256    string    `json:"sourceSha256"`
	InventorySHA256 string    `json:"inventorySha256"`
	Modules         []Module  `json:"modules"`
	Wrappers        []Wrapper `json:"wrappers"`
	Blockers        []string  `json:"blockers"`
	Ready           bool      `json:"ready"`
	CutoverAllowed  bool      `json:"cutoverAllowed"` // never inferred from static inspection
}

func safePath(p string) bool {
	return p != "" && len(p) <= 2048 && !strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\:\x00\r\n\t") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}
func readFile(ctx context.Context, f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("file exceeds static inspection limit")
	}
	r, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	var b bytes.Buffer
	p := make([]byte, 64<<10)
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		n, err := r.Read(p)
		if n > 0 {
			if int64(b.Len()+n) > limit {
				return nil, errors.New("oversized expanded file")
			}
			b.Write(p[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if uint64(b.Len()) != f.UncompressedSize64 {
		return nil, errors.New("truncated ZIP entry")
	}
	return b.Bytes(), nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func jarEvidence(ctx context.Context, b []byte) (name string, auth, launch bool, err error) {
	z, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		return "", false, false, fmt.Errorf("invalid module JAR: %w", e)
	}
	if len(z.File) == 0 || len(z.File) > maxJarEntries {
		return "", false, false, errors.New("JAR entry count outside bounds")
	}
	seen := map[string]bool{}
	var expanded uint64
	for _, f := range z.File {
		p := strings.TrimSuffix(f.Name, "/")
		if !safePath(p) || f.Mode()&os.ModeSymlink != 0 || f.Flags&1 != 0 || (f.Method != zip.Store && f.Method != zip.Deflate) {
			return "", false, false, errors.New("unsafe JAR member")
		}
		k := strings.ToLower(p)
		if seen[k] {
			return "", false, false, errors.New("duplicate JAR member")
		}
		seen[k] = true
		if f.FileInfo().IsDir() {
			continue
		}
		if f.UncompressedSize64 > maxJarExpanded-expanded {
			return "", false, false, errors.New("JAR expanded size exceeds limit")
		}
		expanded += f.UncompressedSize64
		if f.UncompressedSize64 > f.CompressedSize64*400+8192 {
			return "", false, false, errors.New("JAR expansion ratio exceeds limit")
		}
		lower := strings.ToLower(p)
		if lower == "meta-inf/manifest.mf" {
			if f.UncompressedSize64 > 64<<10 {
				return "", false, false, errors.New("manifest too large")
			}
			data, er := readFile(ctx, f, 64<<10)
			if er != nil {
				return "", false, false, er
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), "implementation-title:") {
					name = strings.TrimSpace(line[len("implementation-title:"):])
					if len(name) > 100 || !utf8.ValidString(name) {
						name = ""
					}
				}
			}
		}
		// Scan actual class constant pools and service descriptors (never execute them).
		// Conservative substring matching can over-block; it cannot declare a module safe.
		if strings.HasSuffix(lower, ".class") || strings.HasPrefix(lower, "meta-inf/services/") {
			if f.UncompressedSize64 > 4<<20 {
				return "", false, false, errors.New("oversized class/service descriptor")
			}
			data, er := readFile(ctx, f, 4<<20)
			if er != nil {
				return "", false, false, er
			}
			for _, s := range []string{"AuthProvider", "AuthCoreProvider", "AuthHandler", "AuthRequest", "auth.provider", "auth.core", "AuthProviderPair"} {
				if bytes.Contains(data, []byte(s)) {
					auth = true
				}
			}
			for _, s := range []string{"LaunchServer", "ClientProfile", "LaunchRequest", "LauncherEngine", "ClientLauncher", "LauncherModule", "launchserver"} {
				if bytes.Contains(data, []byte(s)) {
					launch = true
				}
			}
		}
	}
	return name, auth, launch, nil
}
func parseWrapper(raw []byte, p, sha string) Wrapper {
	w := Wrapper{Path: p, SHA256: sha, Replacement: "Never ServerBridge (new Ed25519 enrollment)", Status: "manual"}
	if strings.HasSuffix(strings.ToLower(p), ".env") || strings.EqualFold(path.Base(p), ".env") {
		w.Mode = "environment"
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "export ") {
				line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			}
			if strings.HasPrefix(line, "SERVERWRAPPER_ADDRESS=") {
				w.LegacyAddressPresent = true
			}
			if strings.HasPrefix(line, "SERVERWRAPPER_CHECK_SERVER_TOKEN=") {
				w.LegacyTokenPresent = true
			}
			if strings.Contains(line, "launcher.authlib.inlineClass=") {
				w.Mode = "inline"
			}
		}
		w.Reason = "remove legacy environment and authlib flags; register a Never ServerBridge node with a new key"
		return w
	}
	w.Mode = "config"
	var obj map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if e := decoder.Decode(&obj); e != nil || obj == nil {
		w.Status = "blocked"
		w.Reason = "invalid wrapper JSON"
		return w
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		w.Status = "blocked"
		w.Reason = "multiple JSON documents"
		return w
	}
	for _, key := range []string{"serverName", "name"} {
		if v, ok := obj[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && len(s) <= 128 && utf8.ValidString(s) {
				w.ServerName = s
				break
			}
		}
	}
	for key := range obj {
		k := strings.ToLower(key)
		if strings.Contains(k, "token") || strings.Contains(k, "secret") {
			w.LegacyTokenPresent = true
		}
		if strings.Contains(k, "address") || strings.Contains(k, "url") {
			w.LegacyAddressPresent = true
		}
	}
	w.Reason = "legacy ServerWrapper/authlib configuration must be replaced by a newly enrolled ServerBridge node; no secrets are adopted"
	return w
}
func legacyWrapperJar(p string) bool {
	base := strings.ToLower(path.Base(p))
	return base == "serverwrapper.jar" || base == "serverwrapperinline.jar" || strings.HasPrefix(base, "launcherauthlib") && strings.HasSuffix(base, ".jar")
}
func moduleJar(p string) bool {
	s := strings.ToLower(p)
	return strings.HasSuffix(s, ".jar") && (strings.HasPrefix(s, "modules/") || strings.Contains(s, "/modules/") || legacyWrapperJar(p))
}
func wrapperFile(p string) bool {
	s := strings.ToLower(p)
	base := path.Base(s)
	return base == "serverwrapper.json" || base == "serverwrapperconfig.json" || (strings.Contains(s, "serverwrapper/") && base == "config.json") || base == "serverwrapper.env" || base == ".env"
}

// Analyze checks archive identity and every candidate's digests against MIG03.
// It does not persist bytes or untrusted strings such as password/token values.
func Analyze(ctx context.Context, file *os.File, size int64, inventory inv.Inventory) (Report, error) {
	result := Report{Format: Format, SourceSHA256: inventory.SourceSHA256, InventorySHA256: inventory.ManifestSHA256, Modules: []Module{}, Wrappers: []Wrapper{}, Blockers: []string{}}
	if _, e := inventory.Manifest(); e != nil {
		return Report{}, e
	}
	if size != inventory.SourceBytes {
		return Report{}, errors.New("source size differs from saved inventory")
	}
	if size < 1 || size > inv.MaxSourceBytes {
		return Report{}, errors.New("source size outside MIG03 bounds")
	}
	// An internal caller is not allowed to bypass whole-archive pinning.
	check := sha256.New()
	section := io.NewSectionReader(file, 0, size)
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		n, e := section.Read(buf)
		if n > 0 {
			_, _ = check.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return Report{}, e
		}
	}
	if hex.EncodeToString(check.Sum(nil)) != inventory.SourceSHA256 {
		return Report{}, errors.New("source SHA-256 differs from MIG03 inventory")
	}
	z, e := zip.NewReader(file, size)
	if e != nil {
		return Report{}, e
	}
	indexed := map[string]inv.File{}
	for _, f := range inventory.Files {
		indexed[f.Path] = f
	}
	sources := map[string]bool{}
	for _, f := range z.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".java") {
			sources[strings.ToLower(f.Name)] = true
		}
	}
	sort.Slice(z.File, func(i, j int) bool { return z.File[i].Name < z.File[j].Name })
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		p := f.Name
		if !moduleJar(p) && !wrapperFile(p) {
			continue
		}
		entry, ok := indexed[p]
		if !ok || int64(f.UncompressedSize64) != entry.Size {
			return Report{}, fmt.Errorf("entry missing from MIG03: %s", p)
		}
		limit := maxJar
		if wrapperFile(p) && !moduleJar(p) {
			limit = maxWrapper
		}
		if f.UncompressedSize64 > uint64(limit) {
			result.Blockers = append(result.Blockers, p+": source exceeds inspection limit")
			continue
		}
		b, err := readFile(ctx, f, limit)
		if err != nil {
			return Report{}, fmt.Errorf("cannot read %s: %w", p, err)
		}
		sha := digest(b)
		if sha != entry.SHA256 {
			return Report{}, fmt.Errorf("source changed since inventory: %s", p)
		}
		if moduleJar(p) {
			m := Module{Path: p, SHA256: sha, Name: path.Base(p), Implementation: "blocker", Status: "blocked"}
			n, auth, launch, er := jarEvidence(ctx, b)
			// Do not persist JAR-supplied manifest text: it is untrusted and may contain secrets.
			_ = n
			m.AuthHook = auth
			m.LaunchHook = launch
			prefix := strings.TrimSuffix(strings.ToLower(p), ".jar")
			for s := range sources {
				if strings.HasPrefix(s, prefix+"/") || strings.HasPrefix(s, "src/") && strings.Contains(s, strings.ToLower(strings.TrimSuffix(path.Base(p), ".jar"))) {
					m.SourcesPresent = true
					break
				}
			}
			if er != nil {
				m.Reason = "unsafe or invalid JAR: " + er.Error()
			} else if legacyWrapperJar(p) {
				// These old binaries are never imported. Name indicates only
				// the replacement role, NOT vendor authenticity or trust.
				m.Implementation = "built_in_equivalent"
				m.Status = "manual"
				m.Reason = "legacy wrapper/authlib binary must be removed, not executed; replace with Never ServerBridge and independently test login/join"
			} else if auth || launch {
				m.Reason = "module references authentication/launcher API; source port and behavioral tests required"
			} else if m.SourcesPresent {
				m.Implementation = "source_port"
				m.Reason = "source available but adapter not validated; explicit port and tests required"
			} else {
				m.Reason = "unrecognized executable JAR: no approved equivalent/adapter; source port or removal required"
			}
			result.Modules = append(result.Modules, m)
			if m.Status == "blocked" {
				result.Blockers = append(result.Blockers, p+": "+m.Reason)
			}
		} else {
			w := parseWrapper(b, p, sha)
			// Generic .env is only a wrapper when its keys actually refer to it.
			if (path.Base(strings.ToLower(p)) == ".env" || strings.HasSuffix(strings.ToLower(p), ".env")) && !w.LegacyAddressPresent && !w.LegacyTokenPresent && w.Mode != "inline" {
				continue
			}
			result.Wrappers = append(result.Wrappers, w)
			if w.Status == "blocked" {
				result.Blockers = append(result.Blockers, p+": "+w.Reason)
			}
		}
	}
	result.Ready = len(result.Blockers) == 0
	return result, nil
}
