package sqlitecore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

const maxPackageBytes = 16 << 20

type StoredPackage struct {
	Digest    string    `json:"digest"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}
type ExtensionPackage struct {
	ExtensionID  string    `json:"extensionId"`
	Version      string    `json:"version"`
	Digest       string    `json:"digest"`
	Publisher    string    `json:"publisher"`
	SignatureHex string    `json:"signatureHex,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
}
type SQLiteExtensionInstall struct {
	ExtensionID   string    `json:"extensionId"`
	Scope         string    `json:"scope"`
	ScopeID       string    `json:"scopeId"`
	Version       string    `json:"version"`
	PackageDigest string    `json:"packageDigest"`
	State         string    `json:"state"`
	Generation    int64     `json:"generation"`
	Actor         string    `json:"actor"`
	UpdatedAt     time.Time `json:"updatedAt"`
}
type SQLiteExtensionState struct {
	ExtensionID string    `json:"extensionId"`
	Scope       string    `json:"scope"`
	ScopeID     string    `json:"scopeId"`
	Key         string    `json:"key"`
	Value       string    `json:"value"`
	Digest      string    `json:"digest"`
	Generation  int64     `json:"generation"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func packageDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (r *Repository) PutPackage(ctx context.Context, data []byte, actor string) (out StoredPackage, created bool, err error) {
	if len(data) == 0 || len(data) > maxPackageBytes {
		return out, false, errors.New("package must be 1..16MiB")
	}
	digest := packageDigest(data)
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := authorizedExtensionActor(ctx, q, "global", "", actor); e != nil {
			return e
		}
		res, e := q.ExecContext(ctx, `INSERT INTO package_blobs(digest,data,size_bytes,created_at) VALUES(?,?,?,?) ON CONFLICT(digest) DO NOTHING`, digest, data, len(data), nowNS())
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		created = n == 1
		var existing []byte
		var size int
		var createdAt int64
		if e = q.QueryRowContext(ctx, `SELECT data,size_bytes,created_at FROM package_blobs WHERE digest=?`, digest).Scan(&existing, &size, &createdAt); e != nil {
			return e
		}
		if size != len(data) || packageDigest(existing) != digest {
			return errors.New("persisted package content corrupt")
		}
		out = StoredPackage{digest, size, ts(createdAt)}
		if created {
			return recordAudit(ctx, q, audit(actor, "package:store", digest))
		}
		return nil
	})
	return
}
func (r *Repository) ReadPackage(ctx context.Context, digest string) (payload []byte, err error) {
	if !isHex256(digest) {
		return nil, errors.New("invalid SHA-256 digest")
	}
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		e := q.QueryRowContext(ctx, `SELECT data FROM package_blobs WHERE digest=?`, digest).Scan(&payload)
		if e != nil {
			return notFound(e)
		}
		if packageDigest(payload) != digest {
			return errors.New("persisted package SHA-256 mismatch")
		}
		return nil
	})
	return
}
func (r *Repository) RegisterExtensionPublisher(ctx context.Context, id, keyHex, actor string) error {
	if !durableFieldsNonempty(id) || actor == "" {
		return errors.New("publisher id and actor required")
	}
	key, e := hex.DecodeString(keyHex)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("publisher requires Ed25519 public key")
	}
	digest := packageDigest(key)
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := authorizedExtensionActor(ctx, q, "global", "", actor); e != nil {
			return e
		}
		var existing []byte
		var active int
		e := q.QueryRowContext(ctx, `SELECT public_key,active FROM extension_publishers WHERE id=?`, id).Scan(&existing, &active)
		if e == nil {
			if string(existing) != string(key) {
				return ErrConflict
			}
			return nil
		}
		if !isNoRows(e) {
			return e
		}
		now := nowNS()
		if _, e = q.ExecContext(ctx, `INSERT INTO extension_publishers(id,public_key,fingerprint,active,created_at,updated_at) VALUES(?,?,?,1,?,?)`, id, key, digest, now, now); e != nil {
			return conflict(e)
		}
		return recordAudit(ctx, q, audit(actor, "extension:publisher-trust", id))
	})
}
func (r *Repository) SetExtensionPublisherActive(ctx context.Context, id, actor string, active bool) error {
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := authorizedExtensionActor(ctx, q, "global", "", actor); e != nil {
			return e
		}
		n := 0
		if active {
			n = 1
		}
		res, e := q.ExecContext(ctx, `UPDATE extension_publishers SET active=?,updated_at=? WHERE id=?`, n, nowNS(), id)
		if e != nil {
			return e
		}
		rows, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if rows != 1 {
			return ErrNotFound
		}
		if !active {
			// Revoke installed active packages immediately, and preserve history.
			// For every active installation of this publisher, create a generation-bumped disabled revision.
			items, e := q.QueryContext(ctx, `SELECT i.extension_id,i.scope,i.scope_id,i.generation,i.version,i.package_digest
   FROM extension_installs i JOIN extension_packages p ON p.extension_id=i.extension_id AND p.version=i.version AND p.digest=i.package_digest
   WHERE p.publisher=? AND i.state='enabled'`, id)
			if e != nil {
				return e
			}
			var installs []SQLiteExtensionInstall
			for items.Next() {
				var v SQLiteExtensionInstall
				if e = items.Scan(&v.ExtensionID, &v.Scope, &v.ScopeID, &v.Generation, &v.Version, &v.PackageDigest); e != nil {
					break
				}
				installs = append(installs, v)
			}
			e = errors.Join(e, items.Err(), items.Close())
			if e != nil {
				return e
			}
			for _, v := range installs {
				if _, e = q.ExecContext(ctx, `UPDATE extension_installs SET state='disabled',generation=generation+1,actor=?,updated_at=? WHERE extension_id=? AND scope=? AND scope_id=?`, actor, nowNS(), v.ExtensionID, v.Scope, v.ScopeID); e != nil {
					return e
				}
				if _, e = q.ExecContext(ctx, `INSERT INTO extension_install_history(extension_id,scope,scope_id,generation,version,package_digest,state,actor,created_at) VALUES(?,?,?,?,?,?,'disabled',?,?)`, v.ExtensionID, v.Scope, v.ScopeID, v.Generation+1, v.Version, v.PackageDigest, actor, nowNS()); e != nil {
					return e
				}
			}
		}
		return recordAudit(ctx, q, audit(actor, "extension:publisher-status", id))
	})
}

func extensionSignatureMessage(id, version, digest string) []byte {
	return []byte("Launcher/extension-package/0.32.6\n" + id + "\n" + version + "\n" + digest + "\n")
}

// PublishExtensionPackage verifies the actual persisted bytes and a trusted
// Ed25519 signature over the extension ID/version/digest tuple, just a caller manifest.
func (r *Repository) PublishExtensionPackage(ctx context.Context, input ExtensionPackage, actor string) (out ExtensionPackage, err error) {
	if !durableFieldsNonempty(input.ExtensionID, input.Version, input.Publisher) || !isHex256(input.Digest) {
		return out, errors.New("invalid extension package tuple")
	}
	sig, e := hex.DecodeString(input.SignatureHex)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return out, errors.New("invalid Ed25519 signature")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := authorizedExtensionActor(ctx, q, "global", "", actor); e != nil {
			return e
		}
		var key []byte
		var active int
		if e := q.QueryRowContext(ctx, `SELECT public_key,active FROM extension_publishers WHERE id=?`, input.Publisher).Scan(&key, &active); e != nil {
			return notFound(e)
		}
		if active != 1 || !ed25519.Verify(ed25519.PublicKey(key), extensionSignatureMessage(input.ExtensionID, input.Version, input.Digest), sig) {
			return ErrAuthentication
		}
		var data []byte
		if e := q.QueryRowContext(ctx, `SELECT data FROM package_blobs WHERE digest=?`, input.Digest).Scan(&data); e != nil {
			return notFound(e)
		}
		if packageDigest(data) != input.Digest {
			return errors.New("package checksum mismatch")
		}
		var existingDigest, existingPublisher string
		var existingSig []byte
		var created int64
		e := q.QueryRowContext(ctx, `SELECT digest,publisher,signature,created_at FROM extension_packages WHERE extension_id=? AND version=?`, input.ExtensionID, input.Version).Scan(&existingDigest, &existingPublisher, &existingSig, &created)
		if e == nil {
			if existingDigest != input.Digest || existingPublisher != input.Publisher || string(existingSig) != string(sig) {
				return ErrImmutable
			}
			out = input
			out.CreatedAt = ts(created)
			return nil
		}
		if !isNoRows(e) {
			return e
		}
		created = nowNS()
		if _, e = q.ExecContext(ctx, `INSERT INTO extension_packages(extension_id,version,digest,publisher,signature,created_at) VALUES(?,?,?,?,?,?)`, input.ExtensionID, input.Version, input.Digest, input.Publisher, sig, created); e != nil {
			return conflict(e)
		}
		out = input
		out.CreatedAt = ts(created)
		return recordAudit(ctx, q, audit(actor, "extension:package-publish", input.ExtensionID+"@"+input.Version))
	})
	return
}
func (r *Repository) GetExtensionPackage(ctx context.Context, id, version string) (out ExtensionPackage, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var created int64
		var sig []byte
		e := q.QueryRowContext(ctx, `SELECT extension_id,version,digest,publisher,signature,created_at FROM extension_packages WHERE extension_id=? AND version=?`, id, version).Scan(&out.ExtensionID, &out.Version, &out.Digest, &out.Publisher, &sig, &created)
		if e != nil {
			return notFound(e)
		}
		out.SignatureHex = hex.EncodeToString(sig)
		out.CreatedAt = ts(created)
		return nil
	})
	return
}

func authorizedExtensionActor(ctx context.Context, q sqlitedurable.Executor, scope, scopeID, actor string) error {
	if actor == "" {
		return ErrAuthentication
	}
	var role, status string
	if e := q.QueryRowContext(ctx, `SELECT role_id,status FROM users WHERE id=?`, actor).Scan(&role, &status); e != nil || status != "active" {
		return ErrAuthentication
	}
	if role == "owner" || role == "admin" {
		return nil
	}
	if scope != "project" || scopeID == "" {
		return ErrAuthentication
	}
	if e := q.QueryRowContext(ctx, `SELECT role_id FROM project_user_roles WHERE project_id=? AND user_id=?`, scopeID, actor).Scan(&role); e != nil {
		return ErrAuthentication
	}
	if role != "owner" && role != "admin" {
		return ErrAuthentication
	}
	return nil
}
func readExtensionInstall(ctx context.Context, q sqlitedurable.Executor, id, scope, scopeID string) (v SQLiteExtensionInstall, e error) {
	var timestamp int64
	e = q.QueryRowContext(ctx, `SELECT extension_id,scope,scope_id,version,package_digest,state,generation,actor,updated_at FROM extension_installs WHERE extension_id=? AND scope=? AND scope_id=?`, id, scope, scopeID).Scan(&v.ExtensionID, &v.Scope, &v.ScopeID, &v.Version, &v.PackageDigest, &v.State, &v.Generation, &v.Actor, &timestamp)
	if e != nil {
		return v, notFound(e)
	}
	v.UpdatedAt = ts(timestamp)
	return v, nil
}
func (r *Repository) GetExtensionInstall326(ctx context.Context, id, scope, scopeID string) (v SQLiteExtensionInstall, e error) {
	e = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		v, e = readExtensionInstall(ctx, q, id, scope, scopeID)
		return e
	})
	return
}

// Compare-and-swap install with immutable generations; revocation disables active installs.
// It only persists verified package selection; actual extension execution is a separate stage.
func (r *Repository) ApplyExtensionInstall326(ctx context.Context, v SQLiteExtensionInstall, expected int64) (out SQLiteExtensionInstall, err error) {
	if !durableFieldsNonempty(v.ExtensionID, v.Actor) || (v.Scope != "global" && v.Scope != "project") || (v.Scope == "project" && v.ScopeID == "") || expected < 0 || !map[string]bool{"enabled": true, "disabled": true, "absent": true, "error": true}[v.State] {
		return out, errors.New("invalid extension install operation")
	}
	if v.State == "enabled" && (v.Version == "" || !isHex256(v.PackageDigest)) {
		return out, errors.New("enabled extension requires verified package")
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := authorizedExtensionActor(ctx, q, v.Scope, v.ScopeID, v.Actor); e != nil {
			return e
		}
		if v.State == "enabled" {
			var n int
			e := q.QueryRowContext(ctx, `SELECT p.active FROM extension_packages a JOIN extension_publishers p ON p.id=a.publisher
   JOIN package_blobs b ON b.digest=a.digest WHERE a.extension_id=? AND a.version=? AND a.digest=?`, v.ExtensionID, v.Version, v.PackageDigest).Scan(&n)
			if e != nil || n != 1 {
				return ErrAuthentication
			}
		}
		previous, e := readExtensionInstall(ctx, q, v.ExtensionID, v.Scope, v.ScopeID)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if errors.Is(e, ErrNotFound) && expected != 0 {
			return ErrConflict
		}
		if e == nil && previous.Generation != expected {
			return ErrConflict
		}
		now := nowNS()
		generation := expected + 1
		if e == nil {
			_, e = q.ExecContext(ctx, `UPDATE extension_installs SET version=?,package_digest=?,state=?,generation=?,actor=?,updated_at=? WHERE extension_id=? AND scope=? AND scope_id=?`, v.Version, v.PackageDigest, v.State, generation, v.Actor, now, v.ExtensionID, v.Scope, v.ScopeID)
		} else {
			_, e = q.ExecContext(ctx, `INSERT INTO extension_installs(extension_id,scope,scope_id,version,package_digest,state,generation,actor,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ExtensionID, v.Scope, v.ScopeID, v.Version, v.PackageDigest, v.State, generation, v.Actor, now)
		}
		if e != nil {
			return conflict(e)
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO extension_install_history(extension_id,scope,scope_id,generation,version,package_digest,state,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ExtensionID, v.Scope, v.ScopeID, generation, v.Version, v.PackageDigest, v.State, v.Actor, now); e != nil {
			return e
		}
		if e = recordAudit(ctx, q, audit(v.Actor, "extension:install-"+v.State, v.ExtensionID)); e != nil {
			return e
		}
		out, e = readExtensionInstall(ctx, q, v.ExtensionID, v.Scope, v.ScopeID)
		return e
	})
	return
}

// PutExtensionState326 is atomic CAS on the same persistent database. Secrets
// MUST NOT be stored as plaintext here: use a cryptographic secret store instead.
func (r *Repository) PutExtensionState326(ctx context.Context, v SQLiteExtensionState, expected int64, actor string) (out SQLiteExtensionState, err error) {
	if !durableFieldsNonempty(v.ExtensionID, v.Key) || len(v.Key) > 128 || v.Scope != "global" && v.Scope != "project" || v.Scope == "project" && v.ScopeID == "" || len(v.Value) == 0 || len(v.Value) > 65536 || expected < 0 {
		return out, errors.New("invalid extension state key/value")
	}
	digest, e := durableHash([]byte(v.Value))
	if e != nil {
		return out, e
	}
	err = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := authorizedExtensionActor(ctx, q, v.Scope, v.ScopeID, actor); e != nil {
			return e
		}
		var state string
		if e := q.QueryRowContext(ctx, `SELECT state FROM extension_installs WHERE extension_id=? AND scope=? AND scope_id=?`, v.ExtensionID, v.Scope, v.ScopeID).Scan(&state); e != nil {
			return notFound(e)
		}
		if state != "enabled" {
			return ErrAuthentication
		}
		var generation int64
		e := q.QueryRowContext(ctx, `SELECT generation FROM extension_kv WHERE extension_id=? AND scope=? AND scope_id=? AND item_key=?`, v.ExtensionID, v.Scope, v.ScopeID, v.Key).Scan(&generation)
		if e != nil && !isNoRows(e) {
			return e
		}
		if isNoRows(e) && expected != 0 || e == nil && expected != generation {
			return ErrConflict
		}
		now := nowNS()
		if e == nil {
			_, e = q.ExecContext(ctx, `UPDATE extension_kv SET value_json=?,value_digest=?,generation=generation+1,actor=?,updated_at=? WHERE extension_id=? AND scope=? AND scope_id=? AND item_key=?`, v.Value, digest, actor, now, v.ExtensionID, v.Scope, v.ScopeID, v.Key)
		} else {
			_, e = q.ExecContext(ctx, `INSERT INTO extension_kv(extension_id,scope,scope_id,item_key,value_json,value_digest,generation,actor,updated_at) VALUES(?,?,?,?,?,?,1,?,?)`, v.ExtensionID, v.Scope, v.ScopeID, v.Key, v.Value, digest, actor, now)
		}
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO extension_kv_history(extension_id,scope,scope_id,item_key,generation,value_digest,actor,created_at) VALUES(?,?,?,?,?,?,?,?)`, v.ExtensionID, v.Scope, v.ScopeID, v.Key, expected+1, digest, actor, now)
		if e != nil {
			return e
		}
		if e = recordAudit(ctx, q, audit(actor, "extension:state-write", v.ExtensionID+":"+v.Key)); e != nil {
			return e
		}
		out = v
		out.Digest = digest
		out.Generation = expected + 1
		out.UpdatedAt = ts(now)
		return nil
	})
	return
}
func (r *Repository) GetExtensionState326(ctx context.Context, id, scope, scopeID, key string) (out SQLiteExtensionState, err error) {
	err = r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		var timestamp int64
		e := q.QueryRowContext(ctx, `SELECT extension_id,scope,scope_id,item_key,value_json,value_digest,generation,updated_at FROM extension_kv WHERE extension_id=? AND scope=? AND scope_id=? AND item_key=?`, id, scope, scopeID, key).Scan(&out.ExtensionID, &out.Scope, &out.ScopeID, &out.Key, &out.Value, &out.Digest, &out.Generation, &timestamp)
		if e != nil {
			return notFound(e)
		}
		if packageDigest([]byte(out.Value)) != out.Digest {
			return fmt.Errorf("extension state checksum mismatch")
		}
		out.UpdatedAt = ts(timestamp)
		return nil
	})
	return
}
