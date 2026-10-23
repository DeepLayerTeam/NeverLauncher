// Package texturegravit migrates real Gravit TextureProvider records into
// normalized NeverLauncher texture storage. It never imports auth tokens,
// private URLs, remote identities, or unverified PNG bytes.
package texturegravit

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/storage"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/texturepng"
)

// SourceRow matches GravitLauncher/TextureProvider's PostgreSQL textures table.
// ObjectKey is a trusted offline export extension; file_url is never fetched.
type SourceRow struct {
	ID          string          `json:"id"`
	UserUUID    string          `json:"user_uuid"`
	TextureType string          `json:"texture_type"`
	FileHash    string          `json:"file_hash"`
	FileURL     string          `json:"file_url"`
	Metadata    json.RawMessage `json:"metadata"`
	ObjectKey   string          `json:"object_key,omitempty"`
}

type Mapping struct {
	SourceUUID string `json:"source_uuid"`
	TargetUUID string `json:"target_uuid"`
}

type Record struct {
	ID               string `json:"id"`
	UUID             string `json:"sourceUuid,omitempty"`
	TargetUUID       string `json:"targetUuid,omitempty"`
	Kind             string `json:"kind,omitempty"`
	Status           string `json:"status"` // imported, already-imported, skipped-existing, unmatched, quarantined, blocked
	Reason           string `json:"reason,omitempty"`
	NormalizedDigest string `json:"normalizedDigest,omitempty"`
}

type Report struct {
	Format     string         `json:"format"`
	SourceID   string         `json:"sourceId"`
	DryRun     bool           `json:"dryRun"`
	StartedAt  time.Time      `json:"startedAt"`
	FinishedAt time.Time      `json:"finishedAt"`
	Counts     map[string]int `json:"counts"`
	Rows       []Record       `json:"rows"`
}

type Database interface {
	GetMinecraftProfileByUUID(string) (model.MinecraftProfile, error)
	GravitImportState02510(context.Context, string, string, model.MinecraftProfile, string) (bool, int64, bool, error)
	StageTextureUpload0253(context.Context, model.MinecraftProfile, repository.VerifiedTexture0252) error
	UploadTexture0252(context.Context, model.MinecraftProfile, repository.VerifiedTexture0252) (model.TextureAssignment0251, error)
}

type Source interface {
	Open(context.Context, string) (io.ReadCloser, error)
}

type Runner struct {
	Database       Database
	Destination    storage.Storage
	Source         Source
	SourceID       string
	Mapping        map[string]string // exact source UUID -> administrator-confirmed local UUID
	ObjectTemplate string            // e.g. skins/%hash%.png or %kind%/%hash%.png
	Replace        bool              // only explicitly authorized operators may overwrite existing local assignment
	DryRun         bool
}

var shaHex = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var uuidHex = regexp.MustCompile(`^[0-9a-f]{32}$`)
var sourceIDFormat = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,99}$`)

func CanonicalUUID(raw string) (string, error) {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", ""))
	if !uuidHex.MatchString(s) {
		return "", errors.New("invalid source Minecraft UUID")
	}
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

func LoadMappings(data []byte) (map[string]string, error) {
	var rows []Mapping
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(rows))
	for _, p := range rows {
		from, err := CanonicalUUID(p.SourceUUID)
		if err != nil {
			return nil, err
		}
		to, err := CanonicalUUID(p.TargetUUID)
		if err != nil {
			return nil, err
		}
		if old, ok := result[from]; ok && old != to {
			return nil, fmt.Errorf("ambiguous mapping for %s", from)
		}
		result[from] = to
	}
	return result, nil
}

func LoadJSON(data []byte) ([]SourceRow, error) {
	if len(data) == 0 || len(data) > 32<<20 {
		return nil, errors.New("source export must be at most 32 MiB")
	}
	var rows []SourceRow
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("expected TextureProvider textures JSON array: %w", err)
	}
	if len(rows) > 100000 {
		return nil, errors.New("too many TextureProvider records")
	}
	return rows, nil
}

// ReadPostgres reads the official upstream TextureProvider schema, with no
// arbitrary SQL/identifiers supplied by the caller. Database credentials stay
// in the operator process and never appear in reports.
func ReadPostgres(ctx context.Context, db *sql.DB) ([]SourceRow, error) {
	rows, err := db.QueryContext(ctx, `SELECT id::text,user_uuid::text,texture_type,file_hash,file_url,COALESCE(metadata,'{}'::jsonb) FROM textures ORDER BY user_uuid,texture_type,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	output := make([]SourceRow, 0)
	for rows.Next() {
		if len(output) >= 100000 {
			return nil, errors.New("too many source records (max 100000)")
		}
		var r SourceRow
		if err = rows.Scan(&r.ID, &r.UserUUID, &r.TextureType, &r.FileHash, &r.FileURL, &r.Metadata); err != nil {
			return nil, err
		}
		output = append(output, r)
	}
	return output, rows.Err()
}

func ValidateObjectKey(key string) error {
	if key == "" || len(key) > 512 || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.ContainsAny(key, "\x00\r\n") {
		return errors.New("invalid relative object key")
	}
	for _, v := range strings.Split(key, "/") {
		if v == "" || v == "." || v == ".." {
			return errors.New("path traversal or empty component in object key")
		}
	}
	return nil
}

// RenderKey only substitutes the importer-controlled, strictly validated
// source hash and kind. No URL/hostname from file_url is used as an S3 key.
func RenderKey(template, kind, hash string) (string, error) {
	if kind != "skin" && kind != "cape" || !shaHex.MatchString(hash) {
		return "", errors.New("invalid texture kind/hash")
	}
	if template == "" {
		template = "%kind%/%hash%.png"
	}
	key := strings.NewReplacer("%hash%", hash, "%kind%", kind, "%KIND%", strings.ToUpper(kind)).Replace(template)
	if strings.Contains(key, "%") {
		return "", errors.New("unknown object-key template placeholder")
	}
	return key, ValidateObjectKey(key)
}

func VerifySourceHash(hash string, b []byte) error {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if !shaHex.MatchString(hash) {
		return errors.New("unrecognized TextureProvider digest format (expected SHA-1 or SHA-256)")
	}
	var sum string
	if len(hash) == 40 {
		v := sha1.Sum(b)
		sum = hex.EncodeToString(v[:])
	} else {
		v := sha256.Sum256(b)
		sum = hex.EncodeToString(v[:])
	}
	if sum != hash {
		return errors.New("source PNG digest mismatch")
	}
	return nil
}

func (r *Runner) Run(ctx context.Context, rows []SourceRow) (Report, error) {
	out := Report{Format: "neverlauncher.gravit-texture-import.v1", SourceID: r.SourceID, DryRun: r.DryRun, StartedAt: time.Now().UTC(), Counts: map[string]int{}, Rows: make([]Record, 0, len(rows))}
	if !sourceIDFormat.MatchString(r.SourceID) || r.Database == nil || r.Source == nil || r.Destination == nil {
		return out, errors.New("source ID, source reader, destination and database required")
	}
	if len(rows) > 100000 {
		return out, errors.New("too many texture rows")
	}
	// Duplicate rows would otherwise accidentally update the same assignment.
	seen := map[string]bool{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			out.FinishedAt = time.Now().UTC()
			return out, err
		}
		rec := r.importOne(ctx, row, seen)
		out.Counts[rec.Status]++
		out.Rows = append(out.Rows, rec)
	}
	out.FinishedAt = time.Now().UTC()
	return out, nil
}

func (r *Runner) importOne(ctx context.Context, row SourceRow, seen map[string]bool) Record {
	rec := Record{ID: row.ID, UUID: row.UserUUID, Kind: strings.ToLower(row.TextureType), Status: "quarantined"}
	fail := func(status string, err error) Record { rec.Status = status; rec.Reason = err.Error(); return rec }
	if len(row.ID) < 1 || len(row.ID) > 150 {
		return fail("quarantined", errors.New("invalid or missing upstream row ID"))
	}
	if rec.Kind != "skin" && rec.Kind != "cape" {
		return fail("quarantined", errors.New("unknown TextureProvider texture type"))
	}
	normalizedUUID, err := CanonicalUUID(row.UserUUID)
	if err != nil {
		return fail("unmatched", err)
	}
	if seen[row.ID] {
		return fail("quarantined", errors.New("duplicate upstream row ID"))
	}
	seen[row.ID] = true
	target := normalizedUUID
	if dest, exists := r.Mapping[normalizedUUID]; exists {
		target = dest
	}
	rec.TargetUUID = target
	profile, err := r.Database.GetMinecraftProfileByUUID(target)
	if err != nil {
		return fail("unmatched", errors.New("no verified local Minecraft profile for source UUID; explicit mapping required"))
	}
	if profile.Realm != "local" || profile.Issuer != "neverlauncher" || profile.UUID == "" || profile.UserID == "" {
		return fail("unmatched", errors.New("official or non-local UUID cannot be imported"))
	}
	if canonical, err := CanonicalUUID(profile.UUID); err != nil || canonical != target {
		return fail("unmatched", errors.New("target profile UUID is not canonical"))
	}
	imported, rev, exists, err := r.Database.GravitImportState02510(ctx, r.SourceID, row.ID, profile, rec.Kind)
	if err != nil {
		return fail("blocked", err)
	}
	if imported {
		rec.Status = "already-imported"
		return rec
	}
	if exists && !r.Replace {
		return fail("skipped-existing", errors.New("local texture selection exists; use explicit --replace to overwrite"))
	}
	modelName := "classic"
	if len(row.Metadata) > 0 && string(row.Metadata) != "null" {
		var metadata map[string]json.RawMessage
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			return fail("quarantined", errors.New("invalid texture metadata JSON"))
		}
		if raw, ok := metadata["model"]; ok {
			var name string
			if json.Unmarshal(raw, &name) != nil {
				return fail("quarantined", errors.New("invalid model metadata"))
			}
			if strings.EqualFold(name, "slim") {
				if rec.Kind == "cape" {
					return fail("quarantined", errors.New("cape cannot select a slim model"))
				}
				modelName = "slim"
			} else if name != "" && !strings.EqualFold(name, "default") && !strings.EqualFold(name, "classic") {
				return fail("quarantined", errors.New("unsupported skin model"))
			}
		}
	}
	hash := strings.ToLower(strings.TrimSpace(row.FileHash))
	if !shaHex.MatchString(hash) {
		return fail("quarantined", errors.New("unsupported or missing source hash"))
	}
	key := row.ObjectKey
	if key == "" {
		key, err = RenderKey(r.ObjectTemplate, rec.Kind, hash)
		if err != nil {
			return fail("quarantined", err)
		}
	}
	if err := ValidateObjectKey(key); err != nil {
		return fail("quarantined", err)
	}
	// file_url is deliberately ignored; a compromised row cannot initiate an
	// internal HTTP request. Source readers are local-root or preconfigured S3.
	body, err := r.Source.Open(ctx, key)
	if err != nil {
		return fail("quarantined", fmt.Errorf("missing/corrupt source object: %w", err))
	}
	payload, readErr := io.ReadAll(io.LimitReader(body, texturepng.MaxEncodedBytes+1))
	closeErr := body.Close()
	if readErr != nil {
		return fail("quarantined", readErr)
	}
	if closeErr != nil {
		return fail("quarantined", closeErr)
	}
	if len(payload) > texturepng.MaxEncodedBytes {
		return fail("quarantined", errors.New("source image exceeds 4 MiB"))
	}
	if err = VerifySourceHash(hash, payload); err != nil {
		return fail("quarantined", err)
	}
	processed, err := texturepng.Process(bytes.NewReader(payload), rec.Kind, modelName)
	if err != nil {
		return fail("quarantined", fmt.Errorf("invalid PNG: %w", err))
	}
	rec.NormalizedDigest = processed.Digest
	if r.DryRun {
		rec.Status = "validated-dry-run"
		return rec
	}
	expectedKey := "texture-blobs/sha256/" + processed.Digest[:2] + "/" + processed.Digest + ".png"
	input := repository.VerifiedTexture0252{Digest: processed.Digest, Width: processed.Width, Height: processed.Height, Size: int64(len(processed.PNG)), Driver: r.Destination.Driver(), ObjectKey: expectedKey,
		Kind: rec.Kind, Model: modelName, Visibility: "public", Source: "managed-gravit-import", ExpectedRevision: rev, GravitSourceID: r.SourceID, GravitRowID: row.ID, GravitExternalUUID: normalizedUUID, GravitOriginalHash: hash}
	if err = r.Database.StageTextureUpload0253(ctx, profile, input); err != nil {
		return fail("blocked", err)
	}
	savedKey, n, err := storage.PutTextureImmutable0253(ctx, r.Destination, processed.Digest, processed.PNG)
	if err != nil {
		return fail("blocked", err)
	}
	if savedKey != expectedKey || n != input.Size {
		return fail("blocked", errors.New("storage key/size verification failed"))
	}
	_, err = r.Database.UploadTexture0252(ctx, profile, input)
	if errors.Is(err, repository.ErrGravitAlreadyImported02510) {
		rec.Status = "already-imported"
		return rec
	}
	if err != nil {
		return fail("blocked", err)
	}
	rec.Status = "imported"
	return rec
}

// LocalSource never follows untrusted URLs. Files must resolve beneath the
// configured operator-owned root; symlinks pointing outside are rejected.
type LocalSource struct{ Root string }

func (s LocalSource) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ValidateObjectKey(key); err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(s.Root)
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	p, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(key)))
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(root, p)
	if err != nil {
		return nil, err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("source object escapes local root")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > texturepng.MaxEncodedBytes {
		f.Close()
		return nil, errors.New("not a regular PNG file within size limit")
	}
	return f, nil
}
