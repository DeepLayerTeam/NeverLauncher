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

	inv "gitflic.ru/skif4er/neverlauncher/services/api/internal/gravitinventory"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
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

type Plan struct {
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
	return p != "" && len(p) < 1024 && !strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\:\x00\r\n\t") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.HasPrefix(strings.ToLower(p), ".never-")
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
	out := Plan{Format: "neverlauncher.gravit-content.v1", SourceSHA256: saved.SourceSHA256, InventorySHA256: saved.ManifestSHA256, ProfilePath: profilePath, Files: []File{}, Blockers: []string{}}
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
	// Select exactly one source installation, and shared libraries/assets.
	prefixes := []string{"updates/" + stem + "/", "clients/" + stem + "/"}
	used := map[string]bool{}
	optionalCandidates := []model.ManifestFile{}
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
		fold := strings.ToLower(target)
		if used[fold] {
			out.Blockers = append(out.Blockers, "destination collision: "+target)
			continue
		}
		used[fold] = true
		if strings.HasSuffix(f.Path, "/") || len(f.SHA256) != 64 {
			out.Blockers = append(out.Blockers, "invalid member: "+f.Path)
			continue
		}
		out.Files = append(out.Files, File{SourcePath: f.Path, TargetPath: target, Size: f.Size, SHA256: f.SHA256, Ownership: "required"})
		optionalCandidates = append(optionalCandidates, model.ManifestFile{Path: target, SHA256: f.SHA256, Size: f.Size, Ownership: "optional", Required: false})
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].TargetPath < out.Files[j].TargetPath })
	if len(out.Files) == 0 || len(out.Files) > MaxImportFiles {
		out.Blockers = append(out.Blockers, "no supported client files or file limit exceeded")
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
