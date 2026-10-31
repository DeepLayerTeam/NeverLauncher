package sqlitecore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func (r *Repository) checkFullState(ctx context.Context, q sqlitedurable.Executor) error {
	checks := []string{
		`SELECT count(*) FROM bridge_commands c LEFT JOIN bridge_runtime r ON r.node_id=c.node_id WHERE r.node_id IS NULL OR c.attempt>1 OR (c.status='leased' AND (r.runtime_id<>c.runtime_id OR r.epoch<>c.runtime_epoch))`,
		`SELECT count(*) FROM extension_installs i LEFT JOIN extension_install_history h ON h.extension_id=i.extension_id AND h.scope=i.scope AND h.scope_id=i.scope_id AND h.generation=i.generation AND h.state=i.state AND h.package_digest=i.package_digest AND h.version=i.version WHERE h.extension_id IS NULL`,
		`SELECT count(*) FROM extension_installs i WHERE i.state='enabled' AND NOT EXISTS (
 SELECT 1 FROM extension_packages p JOIN extension_publishers pub ON pub.id=p.publisher JOIN package_blobs b ON b.digest=p.digest WHERE p.extension_id=i.extension_id AND p.version=i.version AND p.digest=i.package_digest AND pub.active=1)`,
		`SELECT count(*) FROM extension_kv k LEFT JOIN extension_kv_history h ON h.extension_id=k.extension_id AND h.scope=k.scope AND h.scope_id=k.scope_id AND h.item_key=k.item_key AND h.generation=k.generation AND h.value_digest=k.value_digest WHERE h.extension_id IS NULL`,
	}
	for _, sqlText := range checks {
		var n int64
		if e := q.QueryRowContext(ctx, sqlText).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return fmt.Errorf("sqlite full state invariant: %d records: %s", n, sqlText)
		}
	}
	rows, e := q.QueryContext(ctx, `SELECT digest,data FROM package_blobs`)
	if e != nil {
		return e
	}
	for rows.Next() {
		var digest string
		var raw []byte
		if e = rows.Scan(&digest, &raw); e != nil {
			break
		}
		if packageDigest(raw) != digest {
			e = errors.New("package blob checksum mismatch")
			break
		}
	}
	e = errors.Join(e, rows.Err(), rows.Close())
	if e != nil {
		return e
	}
	signed, e := q.QueryContext(ctx, `SELECT p.extension_id,p.version,p.digest,p.signature,pub.public_key FROM extension_packages p JOIN extension_publishers pub ON pub.id=p.publisher`)
	if e != nil {
		return e
	}
	for signed.Next() {
		var id, version, digest string
		var signature, key []byte
		if e = signed.Scan(&id, &version, &digest, &signature, &key); e != nil {
			break
		}
		if !ed25519.Verify(ed25519.PublicKey(key), extensionSignatureMessage(id, version, digest), signature) {
			e = errors.New("signed extension package signature changed")
			break
		}
	}
	e = errors.Join(e, signed.Err(), signed.Close())
	if e != nil {
		return e
	}
	cmd, e := q.QueryContext(ctx, `SELECT payload,payload_digest,request_digest,runtime_id,runtime_epoch,command_type,expires_at FROM bridge_commands`)
	if e != nil {
		return e
	}
	for cmd.Next() {
		var payload, digest, request, runtime, kind string
		var epoch, expires int64
		if e = cmd.Scan(&payload, &digest, &request, &runtime, &epoch, &kind, &expires); e != nil {
			break
		}
		h := sha256.Sum256([]byte(payload))
		if hex.EncodeToString(h[:]) != digest {
			e = errors.New("bridge command payload corrupted")
			break
		}
		requestHash := sha256.Sum256([]byte(runtime + "\n" + fmt.Sprint(epoch) + "\n" + kind + "\n" + payload + "\n" + fmt.Sprint(expires)))
		if hex.EncodeToString(requestHash[:]) != request {
			e = errors.New("bridge command identity corrupted")
			break
		}
	}
	e = errors.Join(e, cmd.Err(), cmd.Close())
	if e != nil {
		return e
	}
	kv, e := q.QueryContext(ctx, `SELECT value_json,value_digest FROM extension_kv`)
	if e != nil {
		return e
	}
	for kv.Next() {
		var payload, digest string
		if e = kv.Scan(&payload, &digest); e != nil {
			break
		}
		if packageDigest([]byte(payload)) != digest {
			e = errors.New("extension state digest mismatch")
			break
		}
	}
	return errors.Join(e, kv.Err(), kv.Close())
}
