// Package gravitcontent converts an inventoried Gravit installation into
// hash-pinned Never build-workspace inputs. No source JAR is ever executed.
package gravitcontent

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
	"path"
	"sort"
	"strings"

	inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

const MaxFileBytes int64 = 64 << 20 // encrypted workspace upload is buffered by the existing builder
const MaxImportFiles = 25000

type File struct {
	SourcePath string `json:"sourcePath"`
	TargetPath string `json:"targetPath"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Ownership  string `json:"ownership"`
}

// SkippedFile is an audit record for a client-tree member deliberately not
// staged. A protected/user-owned path is never copied to Never's managed tree.
type SkippedFile struct {
	SourcePath string `json:"sourcePath"`
	Reason     string `json:"reason"`
}

type Plan struct {
	SourceDirectory string                              `json:"sourceDirectory"`
	SkippedFiles    []SkippedFile                       `json:"skippedFiles"`
	Format          string                              `json:"format"`
	SourceSHA256    string                              `json:"sourceSha256"`
	InventorySHA256 string                              `json:"inventorySha256"`
	ProfilePath     string                              `json:"profilePath"`
	Profile         model.GravitImportResult02210       `json:"profile"`
	Optional        *model.GravitOptionalMigration02411 `json:"optional,omitempty"`
	Files           []File                              `json:"files"`
	FilesSHA256     string                              `json:"filesSha256"`
	Ready           bool                                `json:"ready"`
	Blockers        []string                            `json:"blockers"`
}

func safeTarget(p string) bool {
	for _, r := range p {
		if r < 32 || r == 127 {
			return false
		}
	}
	return p != "" && len(p) < 1024 && !strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\:\x00\r\n\t") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.HasPrefix(strings.ToLower(p), ".")
}

// safeSourceDirectory accepts a Gravit-relative client installation directory,
// not an arbitrary path in the source ZIP. The inventory is already authenticated
// and rejects traversal, but relative input must also be checked independently.
func safeSourceDirectory(s string) bool {
	if !safeTarget(s) || len(s) > 512 {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// Gravit's update/exclusion rules are literal file paths or subtree names,
// not unrestricted regexes or globs. Reuse the pattern produced by the model
// converter, which has already validated every path and collision.
func matchesFileRule(file string, patterns []string) bool {
	for _, rule := range patterns {
		if strings.HasSuffix(rule, "/**") {
			prefix := strings.TrimSuffix(rule, "**")
			if strings.HasPrefix(file, prefix) {
				return true
			}
		} else if file == rule {
			return true
		}
	}
	return false
}
func hiddenClientFile(file string) bool {
	for _, segment := range strings.Split(file, "/") {
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}
	return false
}
func protectedClientFile(file string) bool {
	// Paths containing players' worlds, settings, screenshots and resource packs
	// must never be deployed as if they were launcher-managed, even when the
	// upstream update list is misconfigured.
	first := strings.ToLower(strings.SplitN(file, "/", 2)[0])
	switch first {
	case "saves", "screenshots", "resourcepacks", "shaderpacks", "logs", "crash-reports":
		return true
	}
	switch strings.ToLower(file) {
	case "options.txt", "servers.dat", "usercache.json", "usernamecache.json":
		return true
	}
	return false
}

// The optional catalog converter validates semantics, but it needs the source
// file candidates before it can resolve ownership. Only exact file action keys
// (never redirects, JVM commands or script arguments) grant candidacy.
func optionalFilePaths(raw json.RawMessage) map[string]bool {
	paths := map[string]bool{}
	if len(raw) == 0 {
		return paths
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return paths
	}
	for _, item := range items {
		var actions []map[string]json.RawMessage
		if json.Unmarshal(item["actions"], &actions) != nil {
			continue
		}
		for _, action := range actions {
			var kind string
			if json.Unmarshal(action["type"], &kind) != nil || !strings.EqualFold(kind, "file") {
				continue
			}
			var entries map[string]string
			if json.Unmarshal(action["files"], &entries) != nil {
				continue
			}
			for source, target := range entries {
				if target == "" && safeTarget(source) {
					paths[source] = true
				}
			}
		}
	}
	return paths
}

func sourcePaths(obj map[string]json.RawMessage, key string) ([]string, error) {
	b, ok := obj[key]
	if !ok {
		return nil, nil
	}
	var paths []string
	if e := json.Unmarshal(b, &paths); e != nil || paths == nil {
		return nil, fmt.Errorf("invalid %s paths", key)
	}
	if len(paths) > 4096 {
		return nil, fmt.Errorf("%s path limit exceeded", key)
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !safeTarget(p) {
			return nil, fmt.Errorf("unsafe %s path: %q", key, p)
		}
		if !strings.HasSuffix(strings.ToLower(p), ".jar") && !strings.Contains(path.Base(p), ".") {
			p += "/**"
		}
		out = append(out, p)
	}
	return out, nil
}

func sourceFile(z *zip.Reader, name string, limit int64) ([]byte, error) {
	for _, f := range z.File {
		if f.Name != name {
			continue
		}
		if int64(f.UncompressedSize64) > limit {
			return nil, errors.New("source entry exceeds size limit")
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(r, limit+1))
		ce := r.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		if int64(len(b)) > limit {
			return nil, errors.New("source entry exceeds limit")
		}
		return b, nil
	}
	return nil, errors.New("missing source file")
}

// Prepare verifies the entire input against the recorded MIG03 inventory, then
// selects ONE profile's client tree and shared libraries/assets. Files from
// other profiles, launchserver, auth, wrappers, keys and custom modules are
// never copied into a client workspace.
func Prepare(ctx context.Context, src io.ReaderAt, size int64, saved inv.Inventory, profilePath, projectID, profileID, name, loader string) (Plan, error) {
	out := Plan{Format: "launcher.gravit-content.v1", SourceSHA256: saved.SourceSHA256, InventorySHA256: saved.ManifestSHA256, ProfilePath: profilePath, Files: []File{}, SkippedFiles: []SkippedFile{}, Blockers: []string{}}
	actual, e := inv.Inspect(ctx, src, size, saved.SourceSHA256)
	if e != nil {
		return out, e
	}
	if actual.SourceBytes != saved.SourceBytes || actual.ManifestSHA256 != saved.ManifestSHA256 {
		return out, errors.New("source differs from committed inventory")
	}
	z, e := zip.NewReader(src, size)
	if e != nil {
		return out, e
	}
	if !safeTarget(profilePath) || !strings.HasPrefix(strings.ToLower(profilePath), "profiles/") || !strings.HasSuffix(strings.ToLower(profilePath), ".json") {
		return out, errors.New("explicit profiles/*.json source path required")
	}
	meta := map[string]inv.File{}
	for _, f := range saved.Files {
		meta[f.Path] = f
	}
	profileMeta, ok := meta[profilePath]
	if !ok || profileMeta.Kind != "client_profile" {
		return out, errors.New("profile not in verified inventory")
	}
	raw, e := sourceFile(z, profilePath, 1<<20)
	if e != nil {
		return out, e
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != profileMeta.SHA256 {
		return out, errors.New("profile content differs from inventory")
	}
	// The old converter reports all nonempty optional arrays as blocked. Extract
	// and independently verify them with the production OptionalFile converter;
	// only then remove this handled field from its isolated conversion copy.
	var obj map[string]json.RawMessage
	if e = json.Unmarshal(raw, &obj); e != nil || obj == nil {
		return out, errors.New("profile must be a JSON object")
	}
	optionRaw := obj["updateOptional"]
	if len(optionRaw) > 0 {
		var vals []json.RawMessage
		if e = json.Unmarshal(optionRaw, &vals); e != nil || vals == nil {
			return out, errors.New("invalid optional array")
		}
		if len(vals) > 0 {
			obj["updateOptional"] = json.RawMessage(`[]`)
		}
	}
	clean, e := json.Marshal(obj)
	if e != nil {
		return out, e
	}
	converted, e := model.ConvertGravitProfile02210(clean, projectID, profileID, name, loader)
	if e != nil {
		return out, e
	}
	out.Profile = converted
	// A source profile may carry supported manually-reviewed server references;
	// NEVER interpret a 'manual' field as permission to configure a server.
	for _, fld := range converted.Fields {
		if fld.Status == "blocked" {
			out.Blockers = append(out.Blockers, "profile."+fld.Field+": "+fld.Reason)
		}
	}
	stem := strings.TrimSuffix(path.Base(profilePath), path.Ext(profilePath))
	if stem == "" || stem == "." {
		return out, errors.New("invalid profile basename")
	}
	// The Gravit profile's `dir` is the client tree identity. It is not
	// necessarily equal to the JSON filename (renames are commonplace). Never
	// fall back to the basename when an explicit dir was provided: that could
	// import another profile's files without an operator noticing.
	sourceDirectory := stem
	if dirRaw, exists := obj["dir"]; exists {
		if e = json.Unmarshal(dirRaw, &sourceDirectory); e != nil || !safeSourceDirectory(sourceDirectory) {
			return out, errors.New("invalid Gravit client dir")
		}
	}
	if !safeSourceDirectory(sourceDirectory) {
		return out, errors.New("invalid Gravit client directory")
	}
	out.SourceDirectory = sourceDirectory
	prefixes := []string{"updates/" + sourceDirectory + "/", "clients/" + sourceDirectory + "/"}
	used := map[string]string{}
	clientFiles := 0
	optionalCandidates := []model.ManifestFile{}
	// `update` identifies Gravit-managed members; everything else in the
	// client tree is potentially player-owned data. A source JAR listed on the
	// classpath is also required, even when omitted from `update`.
	updateRules, e := sourcePaths(obj, "update")
	if e != nil {
		out.Blockers = append(out.Blockers, e.Error())
		// A blocked source must not gain a more permissive interpretation.
		updateRules = []string{".migration/no-match"}
	}
	optionalFiles := optionalFilePaths(optionRaw)
	classpath := make(map[string]bool, len(converted.Settings.Runtime.Launch.ClasspathEntries))
	for _, cp := range converted.Settings.Runtime.Launch.ClasspathEntries {
		classpath[cp] = true
	}
	ownerExcluded := make([]string, 0)
	for _, rule := range converted.Settings.FileRules {
		if rule.Action == "exclude" {
			ownerExcluded = append(ownerExcluded, rule.Pattern)
		}
	}
	for _, f := range saved.Files {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		var target string
		switch {
		case f.Sensitive || f.Kind == "module" || f.Kind == "runtime" || f.Kind == "authentication" || f.Kind == "server_wrapper" || f.Kind == "launchserver" || f.Kind == "key" || f.Kind == "texture":
			continue
		case strings.HasPrefix(f.Path, prefixes[0]):
			target = strings.TrimPrefix(f.Path, prefixes[0])
		case strings.HasPrefix(f.Path, prefixes[1]):
			target = strings.TrimPrefix(f.Path, prefixes[1])
		case strings.HasPrefix(f.Path, "libraries/") || strings.HasPrefix(f.Path, "assets/"):
			target = f.Path
		default:
			continue
		}
		if !safeTarget(target) || f.Size > MaxFileBytes {
			out.Blockers = append(out.Blockers, "unsafe/oversized client member: "+f.Path)
			continue
		}
		clientTree := strings.HasPrefix(f.Path, prefixes[0]) || strings.HasPrefix(f.Path, prefixes[1])
		if clientTree && (matchesFileRule(target, ownerExcluded) || protectedClientFile(target) || hiddenClientFile(target)) {
			out.SkippedFiles = append(out.SkippedFiles, SkippedFile{f.Path, "player-owned or protected client path"})
			if classpath[target] {
				out.Blockers = append(out.Blockers, "classpath references protected user data: "+target)
			}
			continue
		}
		if clientTree && !matchesFileRule(target, updateRules) && !classpath[target] && !optionalFiles[target] {
			out.SkippedFiles = append(out.SkippedFiles, SkippedFile{f.Path, "not listed in Gravit update or classpath"})
			continue
		}
		fold := strings.ToLower(target)
		if prior, duplicate := used[fold]; duplicate {
			out.Blockers = append(out.Blockers, "destination collision between "+prior+" and "+f.Path)
			continue
		}
		used[fold] = f.Path
		if strings.HasSuffix(f.Path, "/") || len(f.SHA256) != 64 {
			out.Blockers = append(out.Blockers, "invalid member: "+f.Path)
			continue
		}
		out.Files = append(out.Files, File{SourcePath: f.Path, TargetPath: target, Size: f.Size, SHA256: f.SHA256, Ownership: "required"})
		if clientTree {
			clientFiles++
		}
		if optionalFiles[target] {
			if classpath[target] {
				out.Blockers = append(out.Blockers, "optional file is required by base classpath: "+target)
			}
			optionalCandidates = append(optionalCandidates, model.ManifestFile{Path: target, SHA256: f.SHA256, Size: f.Size, Ownership: "optional", Required: false})
		}
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].TargetPath < out.Files[j].TargetPath })
	sort.Slice(out.SkippedFiles, func(i, j int) bool { return out.SkippedFiles[i].SourcePath < out.SkippedFiles[j].SourcePath })
	if clientFiles == 0 {
		out.Blockers = append(out.Blockers, "no managed files for selected Gravit client directory: "+sourceDirectory)
	}
	if len(out.Files) > MaxImportFiles {
		out.Blockers = append(out.Blockers, "client file limit exceeded")
	}
	if len(optionRaw) > 0 && !bytes.Equal(bytes.TrimSpace(optionRaw), []byte("[]")) {
		migrated, e := model.ConvertGravitOptionalView02411(raw, model.NewComponentCatalog0241(nil, 1), optionalCandidates)
		if e != nil {
			return out, e
		}
		out.Optional = &migrated
		if !migrated.Ready {
			out.Blockers = append(out.Blockers, "unsupported or unresolved optional actions")
		}
		optional := map[string]bool{}
		for _, c := range migrated.Catalog.Components {
			for _, p := range c.Files {
				optional[p] = true
			}
		}
		for i := range out.Files {
			if optional[out.Files[i].TargetPath] {
				out.Files[i].Ownership = "optional"
			}
		}
	}
	// Verify classpath membership now, not after stage/sign. Missing JARs must
	// not be silently downloaded or synthesized by the migration service.
	selected := map[string]bool{}
	for _, f := range out.Files {
		selected[f.TargetPath] = true
	}
	for _, p := range converted.Settings.Runtime.Launch.ClasspathEntries {
		if !selected[p] {
			out.Blockers = append(out.Blockers, "missing classpath library: "+p)
		}
	}
	fdata, e := json.Marshal(out.Files)
	if e != nil {
		return out, e
	}
	d := sha256.Sum256(fdata)
	out.FilesSHA256 = hex.EncodeToString(d[:])
	out.Ready = len(out.Blockers) == 0
	return out, nil
}

// Reader indexes the authenticated source ZIP once: importing 25,000 files
// must not perform quadratic linear searches through its central directory.
type Reader struct{ entries map[string]*zip.File }

func NewReader(src io.ReaderAt, size int64) (*Reader, error) {
	z, e := zip.NewReader(src, size)
	if e != nil {
		return nil, e
	}
	entries := make(map[string]*zip.File, len(z.File))
	for _, f := range z.File {
		if _, duplicate := entries[f.Name]; duplicate {
			return nil, errors.New("duplicate ZIP member")
		}
		entries[f.Name] = f
	}
	return &Reader{entries: entries}, nil
}
func (r *Reader) ReadVerified(ctx context.Context, item File) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if item.Size > MaxFileBytes || !safeTarget(item.TargetPath) {
		return nil, errors.New("file exceeds staging limits")
	}
	f, ok := r.entries[item.SourcePath]
	if !ok {
		return nil, errors.New("file absent from source ZIP")
	}
	if int64(f.UncompressedSize64) != item.Size {
		return nil, errors.New("source file size changed")
	}
	stream, e := f.Open()
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(stream, MaxFileBytes+1))
	ce := stream.Close()
	if e != nil {
		return nil, e
	}
	if ce != nil {
		return nil, ce
	}
	h := sha256.Sum256(b)
	if int64(len(b)) != item.Size || hex.EncodeToString(h[:]) != item.SHA256 {
		return nil, fmt.Errorf("content checksum mismatch: %q", item.SourcePath)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return b, nil
}
func ReadVerifiedFile(ctx context.Context, src io.ReaderAt, size int64, item File) ([]byte, error) {
	r, e := NewReader(src, size)
	if e != nil {
		return nil, e
	}
	return r.ReadVerified(ctx, item)
}
func WorkspaceID(run, profilePath string) string {
	h := sha256.Sum256([]byte(run + "\x00" + profilePath))
	return "ws-gravit-" + hex.EncodeToString(h[:16])
}
