package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const webauthnChallengeTTL117 = 5 * time.Minute

const (
	mfaOptional117          = "optional"
	mfaRequired117          = "required"
	mfaPhishingResistant117 = "phishing-resistant"
)

type passkeyCredential117 struct {
	ID             string    `json:"id"`
	UserID         string    `json:"userId"`
	CredentialID   []byte    `json:"-"`
	UserHandle     []byte    `json:"-"`
	PublicKeyCOSE  []byte    `json:"-"`
	Algorithm      int64     `json:"algorithm"`
	SignCount      uint32    `json:"signCount"`
	AAGUID         []byte    `json:"-"`
	Transports     []string  `json:"transports"`
	FriendlyName   string    `json:"friendlyName"`
	BackupEligible bool      `json:"backupEligible"`
	BackedUp       bool      `json:"backedUp"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	LastUsedAt     time.Time `json:"lastUsedAt,omitempty"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func (c passkeyCredential117) public() map[string]any {
	return map[string]any{"id": c.ID, "credentialId": base64.RawURLEncoding.EncodeToString(c.CredentialID), "friendlyName": c.FriendlyName, "algorithm": c.Algorithm, "transports": c.Transports, "backupEligible": c.BackupEligible, "backedUp": c.BackedUp, "status": c.Status, "createdAt": c.CreatedAt, "lastUsedAt": c.LastUsedAt, "updatedAt": c.UpdatedAt}
}

type webauthnChallenge117 struct {
	ID        string
	TokenHash string
	UserID    string
	Purpose   string
	Challenge []byte
	Metadata  map[string]any
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

type passkeyStore117 struct {
	mu              sync.Mutex
	credentials     map[string]passkeyCredential117 // id
	credentialIndex map[string]string               // base64 credential id -> id
	challenges      map[string]webauthnChallenge117 // token hash
	policies        map[string]string
	persistent      *passkeyPostgres117
}

type passkeyPostgres117 struct{ db *sql.DB }

func newPasskeyStore117() *passkeyStore117 {
	return &passkeyStore117{credentials: map[string]passkeyCredential117{}, credentialIndex: map[string]string{}, challenges: map[string]webauthnChallenge117{}, policies: map[string]string{}}
}

func newChallengeBytes117() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}
func tokenHash117(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }

func (s *passkeyStore117) createChallenge(userID, purpose string, challenge []byte, metadata map[string]any) (string, error) {
	if s.persistent != nil {
		return s.persistent.createChallenge(userID, purpose, challenge, metadata)
	}
	token, err := randomToken("wtx")
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	rec := webauthnChallenge117{ID: "wch-" + tokenHash117(token)[:24], TokenHash: tokenHash117(token), UserID: userID, Purpose: purpose, Challenge: append([]byte(nil), challenge...), Metadata: cloneMetadata117(metadata), CreatedAt: now, ExpiresAt: now.Add(webauthnChallengeTTL117)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupChallengesLocked()
	s.challenges[rec.TokenHash] = rec
	return token, nil
}

func (s *passkeyStore117) consumeChallenge(token, purpose string) (webauthnChallenge117, error) {
	if s.persistent != nil {
		return s.persistent.consumeChallenge(token, purpose)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupChallengesLocked()
	h := tokenHash117(strings.TrimSpace(token))
	rec, ok := s.challenges[h]
	if !ok || rec.Purpose != purpose || !rec.UsedAt.IsZero() || rec.ExpiresAt.Before(time.Now().UTC()) {
		return webauthnChallenge117{}, errors.New("WebAuthn transaction invalid or expired")
	}
	rec.UsedAt = time.Now().UTC()
	s.challenges[h] = rec
	return rec, nil
}

func (s *passkeyStore117) cleanupChallengesLocked() {
	now := time.Now().UTC()
	for k, v := range s.challenges {
		if v.ExpiresAt.Before(now) || !v.UsedAt.IsZero() {
			delete(s.challenges, k)
		}
	}
}

func (s *passkeyStore117) saveCredential(c passkeyCredential117) error {
	if s.persistent != nil {
		return s.persistent.saveCredential(c)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := base64.RawURLEncoding.EncodeToString(c.CredentialID)
	if existing, ok := s.credentialIndex[key]; ok && existing != c.ID {
		return errors.New("credential already registered")
	}
	if c.Status == "" {
		c.Status = "active"
	}
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	s.credentials[c.ID] = cloneCredential117(c)
	s.credentialIndex[key] = c.ID
	return nil
}

func (s *passkeyStore117) credentialByRawID(raw []byte) (passkeyCredential117, error) {
	if s.persistent != nil {
		return s.persistent.credentialByRawID(raw)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.credentialIndex[base64.RawURLEncoding.EncodeToString(raw)]
	if !ok {
		return passkeyCredential117{}, sql.ErrNoRows
	}
	c := s.credentials[id]
	if c.Status != "active" {
		return passkeyCredential117{}, sql.ErrNoRows
	}
	return cloneCredential117(c), nil
}
func (s *passkeyStore117) listByUser(userID string) []passkeyCredential117 {
	if s.persistent != nil {
		return s.persistent.listByUser(userID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []passkeyCredential117{}
	for _, c := range s.credentials {
		if c.UserID == userID && c.Status == "active" {
			out = append(out, cloneCredential117(c))
		}
	}
	return out
}
func (s *passkeyStore117) countByUser(userID string) int { return len(s.listByUser(userID)) }
func (s *passkeyStore117) updateUse(id, userID string, count uint32, backedUp bool) error {
	if s.persistent != nil {
		return s.persistent.updateUse(id, userID, count, backedUp)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok || c.UserID != userID || c.Status != "active" {
		return sql.ErrNoRows
	}
	if count > c.SignCount {
		c.SignCount = count
	}
	c.BackedUp = backedUp
	c.LastUsedAt = time.Now().UTC()
	c.UpdatedAt = c.LastUsedAt
	s.credentials[id] = c
	return nil
}
func (s *passkeyStore117) rename(id, userID, name string) error {
	if s.persistent != nil {
		return s.persistent.rename(id, userID, name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok || c.UserID != userID || c.Status != "active" {
		return sql.ErrNoRows
	}
	c.FriendlyName = name
	c.UpdatedAt = time.Now().UTC()
	s.credentials[id] = c
	return nil
}
func (s *passkeyStore117) revoke(id, userID string) error {
	if s.persistent != nil {
		return s.persistent.revoke(id, userID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok || c.UserID != userID || c.Status != "active" {
		return sql.ErrNoRows
	}
	c.Status = "revoked"
	c.UpdatedAt = time.Now().UTC()
	s.credentials[id] = c
	return nil
}
func (s *passkeyStore117) policy(userID string) string {
	if s.persistent != nil {
		return s.persistent.policy(userID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return normalizeMFARequirement117(s.policies[userID])
}
func (s *passkeyStore117) setPolicy(userID, req string) error {
	req = normalizeMFARequirement117(req)
	if req == "" {
		return errors.New("invalid MFA requirement")
	}
	if s.persistent != nil {
		return s.persistent.setPolicy(userID, req)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[userID] = req
	return nil
}

func normalizeMFARequirement117(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", mfaOptional117:
		return mfaOptional117
	case mfaRequired117:
		return mfaRequired117
	case mfaPhishingResistant117, "phishing_resistant", "phishingresistant":
		return mfaPhishingResistant117
	default:
		return ""
	}
}
func cloneMetadata117(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	raw, _ := json.Marshal(m)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}
func cloneCredential117(c passkeyCredential117) passkeyCredential117 {
	c.CredentialID = append([]byte(nil), c.CredentialID...)
	c.UserHandle = append([]byte(nil), c.UserHandle...)
	c.PublicKeyCOSE = append([]byte(nil), c.PublicKeyCOSE...)
	c.AAGUID = append([]byte(nil), c.AAGUID...)
	c.Transports = append([]string(nil), c.Transports...)
	return c
}

func (p *passkeyPostgres117) createChallenge(userID, purpose string, challenge []byte, metadata map[string]any) (string, error) {
	token, err := randomToken("wtx")
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(metadata)
	id := "wch-" + tokenHash117(token)[:24]
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var nullable any = nil
	if userID != "" {
		nullable = userID
	}
	// Bound table growth without making cleanup a separate scheduler dependency.
	_, _ = p.db.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE expires_at < now()-interval '1 hour' OR (used_at IS NOT NULL AND used_at < now()-interval '1 hour')`)
	_, err = p.db.ExecContext(ctx, `INSERT INTO webauthn_challenges(id,token_hash,user_id,purpose,challenge,metadata,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,now(),now()+interval '5 minutes')`, id, tokenHash117(token), nullable, purpose, challenge, string(raw))
	return token, err
}
func (p *passkeyPostgres117) consumeChallenge(token, purpose string) (webauthnChallenge117, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return webauthnChallenge117{}, err
	}
	defer tx.Rollback()
	var rec webauthnChallenge117
	var user sql.NullString
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT id,user_id,purpose,challenge,metadata,created_at,expires_at FROM webauthn_challenges WHERE token_hash=$1 AND purpose=$2 AND used_at IS NULL AND expires_at>now() FOR UPDATE`, tokenHash117(strings.TrimSpace(token)), purpose).Scan(&rec.ID, &user, &rec.Purpose, &rec.Challenge, &raw, &rec.CreatedAt, &rec.ExpiresAt)
	if err != nil {
		return webauthnChallenge117{}, errors.New("WebAuthn transaction invalid or expired")
	}
	rec.UserID = user.String
	_ = json.Unmarshal(raw, &rec.Metadata)
	rec.UsedAt = time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE webauthn_challenges SET used_at=$2 WHERE id=$1`, rec.ID, rec.UsedAt); err != nil {
		return webauthnChallenge117{}, err
	}
	if err = tx.Commit(); err != nil {
		return webauthnChallenge117{}, err
	}
	return rec, nil
}
func (p *passkeyPostgres117) saveCredential(c passkeyCredential117) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	raw, _ := json.Marshal(c.Transports)
	if c.Status == "" {
		c.Status = "active"
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO webauthn_credentials(id,user_id,credential_id,user_handle,public_key_cose,algorithm,sign_count,aaguid,transports,friendly_name,backup_eligible,backed_up,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,now(),now())`, c.ID, c.UserID, c.CredentialID, c.UserHandle, c.PublicKeyCOSE, c.Algorithm, c.SignCount, c.AAGUID, string(raw), c.FriendlyName, c.BackupEligible, c.BackedUp, c.Status); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mfa_methods(id,user_id,method_type,status,created_at,updated_at) VALUES($1,$2,'passkey','enabled',now(),now()) ON CONFLICT(user_id,method_type) DO UPDATE SET status='enabled',updated_at=now()`, "mfa-passkey-"+c.UserID, c.UserID); err != nil {
		return err
	}
	return tx.Commit()
}
func (p *passkeyPostgres117) scanCredential(row interface{ Scan(...any) error }) (passkeyCredential117, error) {
	var c passkeyCredential117
	var raw []byte
	var count int64
	var lastUsed sql.NullTime
	err := row.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.UserHandle, &c.PublicKeyCOSE, &c.Algorithm, &count, &c.AAGUID, &raw, &c.FriendlyName, &c.BackupEligible, &c.BackedUp, &c.Status, &c.CreatedAt, &lastUsed, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	if count < 0 || count > int64(^uint32(0)) {
		return c, errors.New("invalid WebAuthn sign counter")
	}
	c.SignCount = uint32(count)
	if lastUsed.Valid {
		c.LastUsedAt = lastUsed.Time.UTC()
	}
	_ = json.Unmarshal(raw, &c.Transports)
	return c, nil
}

const passkeySelect117 = `SELECT id,user_id,credential_id,user_handle,public_key_cose,algorithm,sign_count,aaguid,transports,friendly_name,backup_eligible,backed_up,status,created_at,last_used_at,updated_at FROM webauthn_credentials`

func (p *passkeyPostgres117) credentialByRawID(raw []byte) (passkeyCredential117, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return p.scanCredential(p.db.QueryRowContext(ctx, passkeySelect117+` WHERE credential_id=$1 AND status='active'`, raw))
}
func (p *passkeyPostgres117) listByUser(userID string) []passkeyCredential117 {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := p.db.QueryContext(ctx, passkeySelect117+` WHERE user_id=$1 AND status='active' ORDER BY created_at`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []passkeyCredential117{}
	for rows.Next() {
		c, e := p.scanCredential(rows)
		if e == nil {
			out = append(out, c)
		}
	}
	return out
}
func (p *passkeyPostgres117) updateUse(id, userID string, count uint32, backedUp bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := p.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count=GREATEST(sign_count,$3),backed_up=$4,last_used_at=now(),updated_at=now() WHERE id=$1 AND user_id=$2 AND status='active'`, id, userID, int64(count), backedUp)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (p *passkeyPostgres117) rename(id, userID, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := p.db.ExecContext(ctx, `UPDATE webauthn_credentials SET friendly_name=$3,updated_at=now() WHERE id=$1 AND user_id=$2 AND status='active'`, id, userID, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (p *passkeyPostgres117) revoke(id, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET status='revoked',updated_at=now() WHERE id=$1 AND user_id=$2 AND status='active'`, id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	var remaining int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND status='active'`, userID).Scan(&remaining); err != nil {
		return err
	}
	if remaining == 0 {
		methodID := "mfa-passkey-" + userID
		if _, err := tx.ExecContext(ctx, `UPDATE mfa_methods SET status='disabled',updated_at=now() WHERE id=$1 AND user_id=$2`, methodID, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET status='revoked' WHERE user_id=$1 AND method_id=$2 AND status='active'`, userID, methodID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (p *passkeyPostgres117) policy(userID string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var v string
	err := p.db.QueryRowContext(ctx, `SELECT requirement FROM mfa_policies WHERE user_id=$1`, userID).Scan(&v)
	if err != nil {
		return mfaOptional117
	}
	return normalizeMFARequirement117(v)
}
func (p *passkeyPostgres117) setPolicy(userID, req string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := p.db.ExecContext(ctx, `INSERT INTO mfa_policies(user_id,requirement,updated_at) VALUES($1,$2,now()) ON CONFLICT(user_id) DO UPDATE SET requirement=EXCLUDED.requirement,updated_at=now()`, userID, req)
	return err
}
func (p *passkeyPostgres117) summary() (credentials, challenges, policies int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = p.db.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_credentials WHERE status='active'`).Scan(&credentials); err != nil {
		return
	}
	if err = p.db.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_challenges WHERE used_at IS NULL AND expires_at>now()`).Scan(&challenges); err != nil {
		return
	}
	err = p.db.QueryRowContext(ctx, `SELECT count(*) FROM mfa_policies WHERE requirement<>'optional'`).Scan(&policies)
	return
}
func (s *passkeyStore117) summary() map[string]any {
	if s.persistent != nil {
		credentials, challenges, policies, err := s.persistent.summary()
		if err != nil {
			return map[string]any{"backend": "postgres-webauthn-0.11.7", "status": "unavailable", "error": err.Error()}
		}
		return map[string]any{"backend": "postgres-webauthn-0.11.7", "activePasskeys": credentials, "activeChallenges": challenges, "enforcedPolicies": policies}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for _, credential := range s.credentials {
		if credential.Status == "active" {
			active++
		}
	}
	return map[string]any{"backend": "in-process-dev-webauthn", "activePasskeys": active, "activeChallenges": len(s.challenges), "enforcedPolicies": len(s.policies)}
}

func validateFriendlyName117(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "Passkey", nil
	}
	if len([]rune(v)) > 80 {
		return "", fmt.Errorf("friendlyName too long")
	}
	return v, nil
}
