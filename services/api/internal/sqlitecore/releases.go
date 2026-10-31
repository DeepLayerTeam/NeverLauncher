package sqlitecore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

const releaseFields = `id,project_id,profile_id,channel,version,status,manifest,published_at`

func scanRelease(s interface{ Scan(...any) error }) (model.ReleaseVersion, error) {
	var v model.ReleaseVersion
	var raw string
	var published int64
	if e := s.Scan(&v.ID, &v.ProjectID, &v.ProfileID, &v.Channel, &v.Version, &v.Status, &raw, &published); e != nil {
		return v, e
	}
	if e := json.Unmarshal([]byte(raw), &v.Manifest); e != nil {
		return v, e
	}
	if e := model.ValidateManifestSchema(v.Manifest); e != nil {
		return v, e
	}
	if v.ProjectID != v.Manifest.ProjectID || v.ProfileID != v.Manifest.ProfileID || v.Channel != v.Manifest.Channel || v.Version != v.Manifest.Version {
		return v, errors.New("release/manifest identity mismatch")
	}
	v.PublishedAt = ts(published)
	return v, nil
}
func (r *Repository) GetRelease(ctx context.Context, projectID, releaseID string) (v model.ReleaseVersion, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var e error
		v, e = scanRelease(q.QueryRowContext(ctx, "SELECT "+releaseFields+" FROM releases WHERE project_id=? AND id=?", projectID, releaseID))
		return notFound(e)
	})
	return
}
func (r *Repository) ListReleases(ctx context.Context, projectID string) (out []model.ReleaseVersion, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		rows, e := q.QueryContext(ctx, "SELECT "+releaseFields+" FROM releases WHERE project_id=? ORDER BY published_at DESC,version DESC", projectID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			v, e := scanRelease(rows)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return
}

// CreateDraft freezes the profile revision before any release file/editing
// operations; a concurrent profile update cannot alter the signed identity.
func (r *Repository) CreateDraft(ctx context.Context, projectID, profileID, channel, version, actor string) (out model.ReleaseVersion, err error) {
	if strings.TrimSpace(actor) == "" {
		return out, errors.New("draft mutation requires audit actor")
	}
	projectID = strings.TrimSpace(projectID)
	profileID = strings.TrimSpace(profileID)
	channel = strings.TrimSpace(channel)
	version = strings.TrimSpace(version)
	if projectID == "" || profileID == "" || channel == "" || version == "" {
		return out, errors.New("project/profile/channel/version required")
	}
	id := fmt.Sprintf("%s-%s-%s", projectID, profileID, version)
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		snapshot, e := readSnapshot(q.QueryRowContext(ctx, `SELECT h.schema_version,h.revision,h.digest,h.spec FROM profiles p JOIN profile_revisions h ON h.project_id=p.project_id AND h.profile_id=p.id AND h.revision=p.revision AND h.digest=p.digest WHERE p.project_id=? AND p.id=?`, projectID, profileID), projectID, profileID)
		if e != nil {
			return e
		}
		// Match existing behavior: draft creation creates an unprotected channel
		// only when not already present, never changing protected setting.
		if _, e = q.ExecContext(ctx, `INSERT INTO channels(project_id,id,name,description,protected) VALUES(?,?,?,'',0) ON CONFLICT(project_id,id) DO NOTHING`, projectID, channel, channel); e != nil {
			return conflict(e)
		}
		m := model.Manifest{SchemaVersion: model.ManifestSchemaV2, ProfileSnapshot: &snapshot, ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Files: []model.ManifestFile{}}
		if e = model.ValidateManifestSchema(m); e != nil {
			return e
		}
		raw, e := json.Marshal(m)
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO releases(id,project_id,profile_id,channel,version,status,manifest,published_at) VALUES(?,?,?,?,?,'draft',?,0)`, id, projectID, profileID, channel, version, string(raw))
		if e != nil {
			return conflict(e)
		}
		out = model.ReleaseVersion{ID: id, ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, Status: "draft", Manifest: m}
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "version:draft", Target: id})
	})
	return
}
func (r *Repository) UpdateDraftManifest(ctx context.Context, projectID, releaseID string, m model.Manifest, actor string) (v model.ReleaseVersion, err error) {
	if strings.TrimSpace(actor) == "" {
		return v, errors.New("manifest mutation requires audit actor")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		current, e := scanRelease(q.QueryRowContext(ctx, "SELECT "+releaseFields+" FROM releases WHERE project_id=? AND id=?", projectID, releaseID))
		if e != nil {
			return notFound(e)
		}
		if current.Status != "draft" {
			return ErrImmutable
		}
		m.ProjectID, m.ProfileID, m.Channel, m.Version = current.ProjectID, current.ProfileID, current.Channel, current.Version
		if m.Files == nil {
			m.Files = []model.ManifestFile{}
		}
		if e = model.ValidateReleaseManifestTransition(current.Manifest, m); e != nil {
			return e
		}
		raw, e := json.Marshal(m)
		if e != nil {
			return e
		}
		res, e := q.ExecContext(ctx, `UPDATE releases SET manifest=? WHERE project_id=? AND id=? AND status='draft'`, string(raw), projectID, releaseID)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrImmutable
		}
		current.Manifest = m
		v = current
		return recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "version:manifest", Target: releaseID})
	})
	return
}

func verifyTrustedSignature(m model.Manifest, roots []ed25519.PublicKey) error {
	if len(roots) == 0 {
		return errors.New("production release requires configured trusted Ed25519 root")
	}
	// A signed draft is not a runnable production release. Enforce the
	// minimum executable metadata before writing the published channel head.
	if strings.TrimSpace(m.Minecraft.Version) == "" || m.Runtime.Java.MajorVersion == 0 || (m.Runtime.Launch.MainClass == "" && m.Minecraft.MainClass == "") {
		return errors.New("cannot publish incomplete Minecraft/runtime launch metadata")
	}
	if m.Signature == nil || !strings.EqualFold(m.Signature.Algorithm, "Ed25519") {
		return errors.New("release must have Ed25519 signature")
	}
	if m.RollbackSource != nil || m.GameReleaseGeneration != 0 || m.TrustEpoch != 0 {
		return errors.New("DEP01 core does not implement game trust generation/rollback verification")
	}
	pub, e := hex.DecodeString(m.Signature.PublicKey)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	sig, e := hex.DecodeString(m.Signature.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	trusted := false
	for _, root := range roots {
		if len(root) == ed25519.PublicKeySize && bytes.Equal(pub, root) {
			trusted = true
			break
		}
	}
	if !trusted {
		return errors.New("manifest signer is not a configured trusted root")
	}
	unsigned := m
	unsigned.Signature = nil
	raw, e := json.Marshal(unsigned)
	if e != nil {
		return e
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return errors.New("manifest Ed25519 signature verification failed")
	}
	return model.ValidateManifestSchema(m)
}

// PublishDraft checks the trusted signature (not merely its presence), uses
// a revision CAS and atomically moves channel head + publishes + appends audit.
// The caller must enforce authorization and product-specific launch/trust checks
// before calling; this DB method enforces cryptographic and storage invariants.
func (r *Repository) PublishDraft(ctx context.Context, projectID, releaseID string, expectedHeadRevision int64, roots []ed25519.PublicKey, actor string) (out model.ReleaseVersion, err error) {
	if strings.TrimSpace(actor) == "" {
		return out, errors.New("actor required")
	}
	if expectedHeadRevision < 0 {
		return out, ErrConflict
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		current, e := scanRelease(q.QueryRowContext(ctx, "SELECT "+releaseFields+" FROM releases WHERE project_id=? AND id=?", projectID, releaseID))
		if e != nil {
			return notFound(e)
		}
		if current.Status != "draft" {
			return ErrImmutable
		}
		if e = verifyTrustedSignature(current.Manifest, roots); e != nil {
			return e
		}
		var rev int64
		e = q.QueryRowContext(ctx, `SELECT revision FROM channel_heads WHERE project_id=? AND profile_id=? AND channel=?`, current.ProjectID, current.ProfileID, current.Channel).Scan(&rev)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if rev != expectedHeadRevision {
			return ErrConflict
		}
		// Channel head pointer uses the hash of the exact persisted signed JSON.
		raw, e := json.Marshal(current.Manifest)
		if e != nil {
			return e
		}
		digest := sha256.Sum256(raw)
		now := nowNS()
		res, e := q.ExecContext(ctx, `UPDATE releases SET status='published',published_at=? WHERE project_id=? AND id=? AND status='draft'`, now, projectID, releaseID)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrImmutable
		}
		if rev == 0 {
			_, e = q.ExecContext(ctx, `INSERT INTO channel_heads(project_id,profile_id,channel,revision,release_id,version,manifest_digest,updated_at) VALUES(?,?,?,1,?,?,?,?)`, current.ProjectID, current.ProfileID, current.Channel, releaseID, current.Version, hex.EncodeToString(digest[:]), now)
		} else {
			res, e = q.ExecContext(ctx, `UPDATE channel_heads SET revision=revision+1,release_id=?,version=?,manifest_digest=?,updated_at=? WHERE project_id=? AND profile_id=? AND channel=? AND revision=?`, releaseID, current.Version, hex.EncodeToString(digest[:]), now, current.ProjectID, current.ProfileID, current.Channel, rev)
			if e == nil {
				n, e = res.RowsAffected()
				if e == nil && n != 1 {
					return ErrConflict
				}
			}
		}
		if e != nil {
			return conflict(e)
		}
		if e = recordAudit(ctx, q, model.AuditEvent{Actor: actor, Action: "version:publish", Target: releaseID}); e != nil {
			return e
		}
		current.Status = "published"
		current.PublishedAt = ts(now)
		out = current
		return nil
	})
	return
}

type ChannelHead struct {
	ProjectID      string    `json:"projectId"`
	ProfileID      string    `json:"profileId"`
	Channel        string    `json:"channel"`
	Revision       int64     `json:"revision"`
	ReleaseID      string    `json:"releaseId"`
	Version        string    `json:"version"`
	ManifestDigest string    `json:"manifestDigest"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (r *Repository) GetChannelHead(ctx context.Context, projectID, profileID, channel string) (h ChannelHead, err error) {
	h.ProjectID, h.ProfileID, h.Channel = projectID, profileID, channel
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var nsValue int64
		e := q.QueryRowContext(ctx, `SELECT revision,release_id,version,manifest_digest,updated_at FROM channel_heads WHERE project_id=? AND profile_id=? AND channel=?`, projectID, profileID, channel).Scan(&h.Revision, &h.ReleaseID, &h.Version, &h.ManifestDigest, &nsValue)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		h.UpdatedAt = ts(nsValue)
		return e
	})
	return
}

// Published reads fail closed if the signed release and immutable channel
// pointer do not verify against the supplied trusted roots.
func (r *Repository) Published(ctx context.Context, projectID, profileID, channel string, roots []ed25519.PublicKey) (out model.ReleaseVersion, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var digest, raw string
		var published int64
		e := q.QueryRowContext(ctx, `SELECT r.id,r.project_id,r.profile_id,r.channel,r.version,r.status,r.manifest,r.published_at,h.manifest_digest FROM channel_heads h JOIN releases r ON r.id=h.release_id AND r.project_id=h.project_id AND r.profile_id=h.profile_id AND r.channel=h.channel WHERE h.project_id=? AND h.profile_id=? AND h.channel=? AND r.status='published'`, projectID, profileID, channel).Scan(&out.ID, &out.ProjectID, &out.ProfileID, &out.Channel, &out.Version, &out.Status, &raw, &published, &digest)
		if e != nil {
			return notFound(e)
		}
		out.PublishedAt = ts(published)
		sum := sha256.Sum256([]byte(raw))
		if hex.EncodeToString(sum[:]) != digest {
			return errors.New("published channel manifest digest mismatch")
		}
		if e = json.Unmarshal([]byte(raw), &out.Manifest); e != nil {
			return e
		}
		if out.Manifest.ProjectID != projectID || out.Manifest.ProfileID != profileID || out.Manifest.Channel != channel || out.Manifest.Version != out.Version {
			return errors.New("published manifest identity mismatch")
		}
		return verifyTrustedSignature(out.Manifest, roots)
	})
	return
}
