package sqlitecore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

var (
	ErrReplay       = errors.New("signed node request nonce already used")
	ErrJoinRejected = errors.New("join ticket rejected, expired or already consumed")
	ErrNodeProof    = errors.New("invalid, stale or unauthorized node proof")
)

// NodeRegistration is an operator-managed trust anchor. Private keys are NEVER stored here.
// New keys require explicit rotation and increment the durable identity epoch.
type NodeRegistration struct {
	ID, ProjectID, ProfileID, Channel, PublicKeyHex, Actor string
}
type BridgeNode struct {
	ID            string `json:"id"`
	ProjectID     string `json:"projectId"`
	ProfileID     string `json:"profileId"`
	Channel       string `json:"channel"`
	Fingerprint   string `json:"fingerprint"`
	IdentityEpoch int64  `json:"identityEpoch"`
	Status        string `json:"status"`
}

// NodeProof is signed by the node's Ed25519 private key over CanonicalNodeRequest.
// Timestamp is Unix seconds. Nonce is 16..64 bytes, unpadded base64url.
type NodeProof struct {
	NodeID        string `json:"nodeId"`
	IdentityEpoch int64  `json:"identityEpoch"`
	Timestamp     int64  `json:"timestamp"`
	Nonce         string `json:"nonce"`
	Signature     string `json:"signature"`
}

// JoinGrant supplies the client with a one-use bearer. Only its SHA-256 hash is persisted.
type JoinGrant struct {
	Ticket     string    `json:"ticket"`
	ExpiresAt  time.Time `json:"expiresAt"`
	NodeID     string    `json:"nodeId"`
	PlayerUUID string    `json:"playerUuid"`
	Username   string    `json:"username"`
}
type RedeemedJoin struct {
	UserID             string    `json:"userId"`
	SessionID          string    `json:"sessionId"`
	MinecraftSessionID string    `json:"minecraftSessionId"`
	PlayerUUID         string    `json:"playerUuid"`
	Username           string    `json:"username"`
	NodeID             string    `json:"nodeId"`
	ProjectID          string    `json:"projectId"`
	ProfileID          string    `json:"profileId"`
	Channel            string    `json:"channel"`
	ConsumedAt         time.Time `json:"consumedAt"`
}

const (
	bridgeNonceWindow = 30 * time.Second
	bridgeNonceTTL    = 2 * time.Minute
	bridgeTicketTTL   = 120 * time.Second
)

func isHex256(v string) bool {
	if len(v) != 64 {
		return false
	}
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && strings.ToLower(v) == v
}
func CanonicalNodeRequest(action string, proof NodeProof, payloadHash string) string {
	return "Launcher/sqlite-bridge/0.32.4\n" + action + "\n" + proof.NodeID + "\n" +
		strconv.FormatInt(proof.IdentityEpoch, 10) + "\n" + strconv.FormatInt(proof.Timestamp, 10) + "\n" + proof.Nonce + "\n" + payloadHash + "\n"
}
func (r *Repository) RegisterNode(ctx context.Context, input NodeRegistration) (BridgeNode, error) {
	var out BridgeNode
	input.ID = strings.TrimSpace(input.ID)
	if input.ID == "" || len(input.ID) > 128 || strings.ContainsAny(input.ID, "\x00\n\r") || input.Actor == "" || input.ProjectID == "" || input.ProfileID == "" || input.Channel == "" {
		return out, errors.New("node identity, scope and operator required")
	}
	key, e := hex.DecodeString(input.PublicKeyHex)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return out, errors.New("Ed25519 public key must be 32 bytes in hex")
	}
	digest := sha256.Sum256(key)
	fingerprint := hex.EncodeToString(digest[:])
	e = r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var role, status string
		er := q.QueryRowContext(ctx, `SELECT role_id,status FROM users WHERE id=?`, input.Actor).Scan(&role, &status)
		if er != nil {
			return ErrAuthentication
		}
		if status != "active" {
			return ErrAuthentication
		}
		if role != "owner" && role != "admin" {
			er = q.QueryRowContext(ctx, `SELECT role_id FROM project_user_roles WHERE user_id=? AND project_id=?`, input.Actor, input.ProjectID).Scan(&role)
			if er != nil || (role != "owner" && role != "admin") {
				return ErrAuthentication
			}
		}
		now := nowNS()
		var priorKey []byte
		var priorEpoch int64
		er = q.QueryRowContext(ctx, `SELECT public_key,identity_epoch FROM bridge_nodes WHERE id=?`, input.ID).Scan(&priorKey, &priorEpoch)
		if er != nil && !errors.Is(er, sql.ErrNoRows) {
			return er
		}
		if er == nil {
			// Explicit key rotation must advance the generation even if the key is unchanged;
			// old proofs and pending tickets are invalidated in this same transaction.
			if _, er = q.ExecContext(ctx, `UPDATE bridge_join_tickets SET status='invalidated',terminal_at=? WHERE node_id=? AND status='active'`, now, input.ID); er != nil {
				return er
			}
			if er = invalidateBridgeRuntimeTx(ctx, q, input.ID, "node identity rotated", now); er != nil {
				return er
			}
			_, er = q.ExecContext(ctx, `UPDATE bridge_nodes SET project_id=?,profile_id=?,channel=?,public_key=?,fingerprint=?,identity_epoch=identity_epoch+1,status='active',updated_at=? WHERE id=?`, input.ProjectID, input.ProfileID, input.Channel, key, fingerprint, now, input.ID)
			if er != nil {
				return conflict(er)
			}
			out.IdentityEpoch = priorEpoch + 1
		} else {
			_, er = q.ExecContext(ctx, `INSERT INTO bridge_nodes(id,project_id,profile_id,channel,public_key,fingerprint,identity_epoch,status,created_at,updated_at) VALUES(?,?,?,?,?,?,1,'active',?,?)`, input.ID, input.ProjectID, input.ProfileID, input.Channel, key, fingerprint, now, now)
			if er != nil {
				return conflict(er)
			}
			out.IdentityEpoch = 1
		}
		out.ID, out.ProjectID, out.ProfileID, out.Channel, out.Fingerprint, out.Status = input.ID, input.ProjectID, input.ProfileID, input.Channel, fingerprint, "active"
		return recordAudit(ctx, q, audit(input.Actor, "bridge:node-enroll", input.ID))
	})
	return out, e
}
func (r *Repository) DisableNode(ctx context.Context, nodeID, actor string) error {
	if nodeID == "" || actor == "" {
		return errors.New("node and operator required")
	}
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		var project, role, status string
		if e := q.QueryRowContext(ctx, `SELECT project_id FROM bridge_nodes WHERE id=?`, nodeID).Scan(&project); e != nil {
			return notFound(e)
		}
		if e := q.QueryRowContext(ctx, `SELECT role_id,status FROM users WHERE id=?`, actor).Scan(&role, &status); e != nil || status != "active" {
			return ErrAuthentication
		}
		if role != "owner" && role != "admin" {
			if e := q.QueryRowContext(ctx, `SELECT role_id FROM project_user_roles WHERE user_id=? AND project_id=?`, actor, project).Scan(&role); e != nil || (role != "owner" && role != "admin") {
				return ErrAuthentication
			}
		}
		now := nowNS()
		if _, e := q.ExecContext(ctx, `UPDATE bridge_join_tickets SET status='invalidated',terminal_at=? WHERE node_id=? AND status='active'`, now, nodeID); e != nil {
			return e
		}
		if _, e := q.ExecContext(ctx, `UPDATE bridge_nodes SET status='disabled',identity_epoch=identity_epoch+1,updated_at=? WHERE id=?`, now, nodeID); e != nil {
			return e
		}
		if e := invalidateBridgeRuntimeTx(ctx, q, nodeID, "node disabled", now); e != nil {
			return e
		}
		return recordAudit(ctx, q, audit(actor, "bridge:node-disable", nodeID))
	})
}

// verifyProofTx compares persisted trust anchors and validates the signature, timestamp
// and random nonce. It trusts a caller-supplied fingerprint or epoch alone.
func verifyProofTx(ctx context.Context, q sqlitedurable.Executor, action string, proof NodeProof, payloadHash string, now time.Time) error {
	if proof.NodeID == "" || proof.IdentityEpoch < 1 || !isHex256(payloadHash) || (action != "ping" && action != "redeem" && action != "runtime" && action != "control-lease" && action != "control-ack") {
		return ErrNodeProof
	}
	nowSec := now.UTC().Unix()
	if proof.Timestamp < nowSec-int64(bridgeNonceWindow/time.Second) || proof.Timestamp > nowSec+int64(bridgeNonceWindow/time.Second) {
		return ErrNodeProof
	}
	nonce, e := base64.RawURLEncoding.DecodeString(proof.Nonce)
	if e != nil || len(nonce) < 16 || len(nonce) > 64 || base64.RawURLEncoding.EncodeToString(nonce) != proof.Nonce {
		return ErrNodeProof
	}
	sig, e := hex.DecodeString(proof.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return ErrNodeProof
	}
	var key []byte
	var epoch int64
	var status string
	e = q.QueryRowContext(ctx, `SELECT public_key,identity_epoch,status FROM bridge_nodes WHERE id=?`, proof.NodeID).Scan(&key, &epoch, &status)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrNodeProof
	}
	if e != nil {
		return e
	}
	if status != "active" || epoch != proof.IdentityEpoch || len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), []byte(CanonicalNodeRequest(action, proof, payloadHash)), sig) {
		return ErrNodeProof
	}
	return nil
}
func consumeNonceTx(ctx context.Context, q sqlitedurable.Executor, action string, proof NodeProof, now time.Time) error {
	nonce, _ := base64.RawURLEncoding.DecodeString(proof.Nonce)
	digest := sha256.Sum256(nonce)
	res, e := q.ExecContext(ctx, `INSERT INTO bridge_nonces(node_id,identity_epoch,nonce_hash,action,committed_at,expires_at) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING`, proof.NodeID, proof.IdentityEpoch, hex.EncodeToString(digest[:]), action, ns(now), ns(now.Add(bridgeNonceTTL)))
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrReplay
	}
	return nil
}

// ConsumeSignedNonce is used after verifying the caller's signed request payload.
// Its unique index survives crash/restart and cannot be bypassed via in-memory fallback.
func (r *Repository) ConsumeSignedNonce(ctx context.Context, proof NodeProof, payload []byte) error {
	digest := sha256.Sum256(payload)
	hash := hex.EncodeToString(digest[:])
	now := time.Now().UTC()
	return r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := verifyProofTx(ctx, q, "ping", proof, hash, now); e != nil {
			return e
		}
		return consumeNonceTx(ctx, q, "ping", proof, now)
	})
}

// IssueJoinTicket atomically checks a Never access session, matching Minecraft
// session, node scope and identity, and replaces any prior active ticket for the
// same node/player. Only the hashed token is persisted.
func (a *Auth) IssueJoinTicket(ctx context.Context, accessToken, minecraftToken, nodeID string) (JoinGrant, error) {
	var grant JoinGrant
	if !validBearer(accessToken, "nla_") || !validBearer(minecraftToken, "nlm_") || nodeID == "" {
		return grant, ErrAuthentication
	}
	raw, hash, e := bearer("nlj_")
	if e != nil {
		return grant, e
	}
	e = a.repo.store.Write(ctx, func(q sqlitedurable.Executor) error {
		now := nowNS()
		var userID, sid, uuid, name, project, profile, channel, fp, role, projectRole, mcsid string
		var epoch, authEpoch, mEpoch int64
		var tokenExpiry, sessExpiry, mExpiry, accessRevoked int64
		var userStatus, sessionStatus, mcStatus, nodeStatus string
		e := q.QueryRowContext(ctx, `SELECT u.id,s.id,m.id,p.uuid,p.name,u.role_id,s.auth_epoch,u.auth_epoch,
   t.expires_at,s.expires_at,m.expires_at,t.revoked_at,u.status,s.status,m.status
   FROM access_tokens t JOIN auth_sessions s ON s.id=t.session_id
   JOIN users u ON u.id=s.user_id JOIN minecraft_sessions m ON m.user_id=u.id AND m.session_id=s.id
   JOIN minecraft_profiles p ON p.user_id=u.id AND p.uuid=m.profile_uuid
   WHERE t.token_hash=? AND m.access_hash=?`, hashBearer(accessToken), hashBearer(minecraftToken)).Scan(&userID, &sid, &mcsid, &uuid, &name, &role, &authEpoch, &mEpoch, &tokenExpiry, &sessExpiry, &mExpiry, &accessRevoked, &userStatus, &sessionStatus, &mcStatus)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrAuthentication
		}
		if e != nil {
			return e
		}
		if userStatus != "active" || sessionStatus != "active" || mcStatus != "active" || authEpoch != mEpoch || accessRevoked != 0 || tokenExpiry <= now || sessExpiry <= now || mExpiry <= now {
			return ErrAuthentication
		}
		e = q.QueryRowContext(ctx, `SELECT project_id,profile_id,channel,identity_epoch,fingerprint,status FROM bridge_nodes WHERE id=?`, nodeID).Scan(&project, &profile, &channel, &epoch, &fp, &nodeStatus)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNodeProof
		}
		if e != nil {
			return e
		}
		if nodeStatus != "active" {
			return ErrNodeProof
		}
		if role != "owner" && role != "admin" {
			e = q.QueryRowContext(ctx, `SELECT role_id FROM project_user_roles WHERE user_id=? AND project_id=?`, userID, project).Scan(&projectRole)
			if e != nil || (projectRole != "owner" && projectRole != "admin" && projectRole != "player") {
				return ErrAuthentication
			}
		}
		expires := now + int64(bridgeTicketTTL)
		for _, n := range []int64{tokenExpiry, sessExpiry, mExpiry} {
			if n < expires {
				expires = n
			}
		}
		if expires <= now {
			return ErrAuthentication
		}
		if _, e = q.ExecContext(ctx, `UPDATE bridge_join_tickets SET status='replaced',terminal_at=? WHERE node_id=? AND username=? AND status='active'`, now, nodeID, name); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, `INSERT INTO bridge_join_tickets(token_hash,user_id,session_id,minecraft_session_id,access_token_hash,player_uuid,username,node_id,project_id,profile_id,channel,issued_identity_epoch,issued_fingerprint,status,created_at,expires_at)
  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?)`, hash, userID, sid, mcsid, hashBearer(accessToken), uuid, name, nodeID, project, profile, channel, epoch, fp, now, expires)
		if e != nil {
			return conflict(e)
		}
		if e = recordAudit(ctx, q, audit(userID, "bridge:join-issue", hash)); e != nil {
			return e
		}
		grant = JoinGrant{Ticket: raw, ExpiresAt: ts(expires), NodeID: nodeID, PlayerUUID: uuid, Username: name}
		return nil
	})
	return grant, e
}

// RedeemJoinTicket checks a node-signed proof over the ticket's hash, then
// burns its nonce and consumes the ticket atomically, with every auth/identity
// generation and session status revalidated under the BEGIN IMMEDIATE lock.
// No caller ever receives success before SQLite COMMIT succeeds.
func (r *Repository) RedeemJoinTicket(ctx context.Context, raw string, proof NodeProof, remoteIP string) (RedeemedJoin, error) {
	var out RedeemedJoin
	if !validBearer(raw, "nlj_") || len(remoteIP) > 128 || strings.ContainsAny(remoteIP, "\x00\n\r") {
		return out, ErrJoinRejected
	}
	hash := hashBearer(raw)
	now := time.Now().UTC()
	var rejected bool
	e := r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		if e := verifyProofTx(ctx, q, "redeem", proof, hash, now); e != nil {
			return e
		}
		if e := consumeNonceTx(ctx, q, "redeem", proof, now); e != nil {
			return e
		}
		var sessionStatus, userStatus, mcStatus, nodeStatus, tStatus string
		var nodeEpoch, issuedEpoch, authEpoch, currentEpoch int64
		var issuedFP, nodeFP string
		var expires, accessExpires, sessionExpires, mcExpires, accessRevoked int64
		e := q.QueryRowContext(ctx, `SELECT j.user_id,j.session_id,j.minecraft_session_id,j.player_uuid,j.username,j.node_id,j.project_id,j.profile_id,j.channel,
   j.status,j.expires_at,j.issued_identity_epoch,j.issued_fingerprint,n.identity_epoch,n.fingerprint,n.status,
   s.auth_epoch,u.auth_epoch,s.status,u.status,m.status,s.expires_at,m.expires_at,at.expires_at,at.revoked_at
   FROM bridge_join_tickets j JOIN bridge_nodes n ON n.id=j.node_id
   JOIN users u ON u.id=j.user_id JOIN auth_sessions s ON s.id=j.session_id AND s.user_id=u.id
   JOIN minecraft_sessions m ON m.id=j.minecraft_session_id AND m.user_id=u.id AND m.session_id=s.id AND m.profile_uuid=j.player_uuid
   JOIN access_tokens at ON at.token_hash=j.access_token_hash AND at.session_id=s.id
   WHERE j.token_hash=?`, hash).Scan(&out.UserID, &out.SessionID, &out.MinecraftSessionID, &out.PlayerUUID, &out.Username, &out.NodeID, &out.ProjectID, &out.ProfileID, &out.Channel, &tStatus, &expires, &issuedEpoch, &issuedFP, &nodeEpoch, &nodeFP, &nodeStatus, &authEpoch, &currentEpoch, &sessionStatus, &userStatus, &mcStatus, &sessionExpires, &mcExpires, &accessExpires, &accessRevoked)
		if errors.Is(e, sql.ErrNoRows) {
			// Burn a validly signed nonce even when the bearer is unknown.
			// Returning ErrJoinRejected from the callback would roll it back.
			rejected = true
			return nil
		}
		if e != nil {
			return e
		}
		if tStatus != "active" || expires <= ns(now) || issuedEpoch != nodeEpoch || proof.IdentityEpoch != issuedEpoch || out.NodeID != proof.NodeID || subtle.ConstantTimeCompare([]byte(issuedFP), []byte(nodeFP)) != 1 || nodeStatus != "active" || userStatus != "active" || sessionStatus != "active" || mcStatus != "active" || authEpoch != currentEpoch || sessionExpires <= ns(now) || mcExpires <= ns(now) || accessExpires <= ns(now) || accessRevoked != 0 {
			rejected = true
			return nil
		}
		// Explicitly fence the consumed state with a CAS; the SQL CHECK + trigger
		// prevent resurrection of a consumed ticket after crash or restore.
		res, e := q.ExecContext(ctx, `UPDATE bridge_join_tickets SET status='consumed',consumed_at=?,terminal_at=?,redeemed_nonce_hash=?,redeemed_remote_ip=? WHERE token_hash=? AND status='active'`, ns(now), ns(now), SignedPayloadHash(mustDecodeNonce(proof.Nonce)), remoteIP, hash)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			rejected = true
			return nil
		}
		if e = recordAudit(ctx, q, audit(out.UserID, "bridge:join-consume", hash)); e != nil {
			return e
		}
		out.ConsumedAt = now
		return nil
	})
	if e != nil {
		return RedeemedJoin{}, e
	}
	if rejected {
		return RedeemedJoin{}, ErrJoinRejected
	}
	return out, nil
}

// PruneExpiredReplayNonces only removes nonces whose signed timestamp must be
// stale already. Join tickets are retained for audit and resurrected.
func (r *Repository) PruneExpiredReplayNonces(ctx context.Context) (int64, error) {
	var count int64
	e := r.store.Write(ctx, func(q sqlitedurable.Executor) error {
		res, e := q.ExecContext(ctx, `DELETE FROM bridge_nonces WHERE expires_at<?`, nowNS()-int64(bridgeNonceWindow))
		if e != nil {
			return e
		}
		count, e = res.RowsAffected()
		return e
	})
	return count, e
}

// TicketStatus returns only durable metadata (no bearer). Useful for recovery
// from ambiguous commit: terminal consumed state must be retried.
func (r *Repository) TicketStatus(ctx context.Context, raw string) (string, error) {
	if !validBearer(raw, "nlj_") {
		return "", ErrJoinRejected
	}
	var status string
	e := r.store.Read(ctx, func(q sqlitedurable.Executor) error {
		return notFound(q.QueryRowContext(ctx, `SELECT status FROM bridge_join_tickets WHERE token_hash=?`, hashBearer(raw)).Scan(&status))
	})
	return status, e
}

// SignedPayloadHash is the exact 32-byte digest required in canonical signing.
func SignedPayloadHash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func mustDecodeNonce(raw string) []byte    { b, _ := base64.RawURLEncoding.DecodeString(raw); return b }
