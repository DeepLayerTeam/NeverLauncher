package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
)

// PasswordCAS0295 is required for safe password upgrade after a successful
// password proof. Compare-and-swap rejects concurrent password resets.
type PasswordCAS0295 interface {
	ReplacePasswordIfMatch0295(context.Context, string, string, string) (bool, error)
}

func (r *MemoryRepository) ReplacePasswordIfMatch0295(_ context.Context, userID, priorHash, newHash string) (bool, error) {
	if newHash == "" || !strings.HasPrefix(newHash, "$argon2id$") {
		return false, errors.New("new local password hash must be Argon2id")
	}
	for i := range r.users {
		if r.users[i].ID == userID {
			if r.users[i].PasswordHash != priorHash || priorHash == "" {
				return false, nil
			}
			r.users[i].PasswordHash = newHash
			r.users[i].PasswordUpdatedAt = time.Now().UTC()
			r.users[i].UpdatedAt = time.Now().UTC()
			return true, nil
		}
	}
	return false, ErrNotFound
}

func (r *SQLRepository) ReplacePasswordIfMatch0295(ctx context.Context, userID, priorHash, newHash string) (bool, error) {
	if err := r.check(); err != nil {
		return false, err
	}
	if priorHash == "" || !strings.HasPrefix(newHash, "$argon2id$") {
		return false, errors.New("invalid CAS password upgrade")
	}
	result, err := r.db.ExecContext(ctx, `UPDATE users SET password_hash=$3,password_updated_at=now(),updated_at=now()
       WHERE id=$1 AND password_hash=$2 AND status='active'`, userID, priorHash, newHash)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed == 1, err
}

// FileAuthImporter0295 performs the complete migration of accounts, local
// identity rows and immutable Minecraft UUIDs in ONE PostgreSQL transaction.
type FileAuthImporter0295 interface {
	ImportFileAuth0295(context.Context, []fileauth.Account, bool) (int, error)
}

func (r *SQLRepository) ImportFileAuth0295(ctx context.Context, accounts []fileauth.Account, dryRun bool) (int, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	if len(accounts) == 0 || len(accounts) > fileauth.MaxAccounts {
		return 0, errors.New("invalid FileAuth account count")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// Serialize simultaneous import invocations, not concurrent authentications.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(2945,1)`); err != nil {
		return 0, err
	}
	for _, a := range accounts {
		if err := fileauth.ValidateAccount(a); err != nil {
			return 0, fmt.Errorf("invalid FileAuth account %q: %w", a.Username, err)
		}
		id := "gravit-fileauth-" + strings.ReplaceAll(a.UUID, "-", "")
		// Never update or merge an existing Never account based on nickname,
		// UUID, or email. Any collision rolls back the WHOLE batch.
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 OR lower(email)=lower($2))`, id, a.Email).Scan(&exists); err != nil {
			return 0, err
		}
		if exists {
			return 0, fmt.Errorf("FileAuth import conflict for account %q (existing Never account)", a.Username)
		}
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM minecraft_profiles WHERE lower(name)=lower($1) OR uuid=$2)`, a.Username, a.UUID).Scan(&exists); err != nil {
			return 0, err
		}
		if exists {
			return 0, fmt.Errorf("FileAuth import conflict for Minecraft name/UUID %q", a.Username)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status,project_roles,password_hash,password_updated_at,created_at,updated_at)
            VALUES($1,$2,$3,'player','active','{}'::jsonb,$4,now(),now(),now())`, id, a.Email, a.Username, a.PasswordHash); err != nil {
			return 0, fmt.Errorf("import user %q: %w", a.Username, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO auth_identities(id,user_id,provider,issuer,subject,email,username,display_name,claims,created_at,updated_at)
            VALUES($1,$2,'local','launcher',$2,$3,$3,$4,'{}'::jsonb,now(),now())`, "identity-local-"+id, id, a.Email, a.Username); err != nil {
			return 0, fmt.Errorf("import identity %q: %w", a.Username, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO minecraft_profiles(user_id,uuid,name,issuer,realm,subject,identity_version,created_at,updated_at)
            VALUES($1,$2,$3,'launcher','local',$2,'legacy-fileauth-v1',now(),now())`, id, a.UUID, a.Username); err != nil {
			return 0, fmt.Errorf("import Minecraft UUID %q: %w", a.Username, err)
		}
		// Only the username/UUID are recorded in audit; never the source hash.
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,created_at) VALUES($1,'local-import','auth:fileauth:import',$2,now())`, "fileauth-import-"+id, id); err != nil {
			return 0, fmt.Errorf("import audit %q: %w", a.Username, err)
		}
	}
	if dryRun {
		return len(accounts), nil
	} // deferred rollback
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(accounts), nil
}
