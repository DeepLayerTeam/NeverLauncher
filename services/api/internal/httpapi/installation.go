package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type installationStateP0 struct {
	TokenHash   string
	TokenUsedAt sql.NullTime
	Completed   bool
	CompletedAt sql.NullTime
}

var devInstallationP0 = struct {
	sync.Mutex
	state installationStateP0
}{}

func bootstrapTokenHashP0(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}
func isProdP0(env string) bool {
	return strings.EqualFold(strings.TrimSpace(env), "production") || strings.EqualFold(strings.TrimSpace(env), "prod")
}

func InitializeInstallationSecurityP0(cfg config.Config) error {
	if isMemoryRepository950(cfg.RepositoryDriver) {
		return nil
	}
	db, err := sql.Open(firstNonEmpty(cfg.SQLDriver, "pgx"), cfg.DatabaseDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		return err
	}
	state, err := loadInstallationStateP0(ctx, db)
	if err != nil {
		return err
	}
	if state.Completed || state.TokenUsedAt.Valid {
		return nil
	}
	token := strings.TrimSpace(cfg.BootstrapToken)
	if state.TokenHash == "" {
		if token == "" {
			if isProdP0(cfg.Environment) {
				return errors.New("fresh production installation requires NEVERLAUNCHER_BOOTSTRAP_TOKEN")
			}
			return nil
		}
		_, err = db.ExecContext(ctx, `UPDATE neverlauncher_installation_state SET bootstrap_token_hash=$1, updated_at=now() WHERE singleton=TRUE AND bootstrap_token_hash=''`, bootstrapTokenHashP0(token))
		return err
	}
	if token != "" && subtle.ConstantTimeCompare([]byte(state.TokenHash), []byte(bootstrapTokenHashP0(token))) != 1 {
		return errors.New("NEVERLAUNCHER_BOOTSTRAP_TOKEN does not match initialized installation token")
	}
	return nil
}

func loadInstallationStateP0(ctx context.Context, db *sql.DB) (installationStateP0, error) {
	var s installationStateP0
	err := db.QueryRowContext(ctx, `SELECT bootstrap_token_hash, bootstrap_token_used_at, installation_completed, completed_at FROM neverlauncher_installation_state WHERE singleton=TRUE`).Scan(&s.TokenHash, &s.TokenUsedAt, &s.Completed, &s.CompletedAt)
	return s, err
}

func (s Server) installationStateP0(ctx context.Context) (installationStateP0, error) {
	if isMemoryRepository950(s.Config.RepositoryDriver) {
		devInstallationP0.Lock()
		defer devInstallationP0.Unlock()
		st := devInstallationP0.state
		if st.TokenHash == "" && strings.TrimSpace(s.Config.BootstrapToken) != "" {
			st.TokenHash = bootstrapTokenHashP0(s.Config.BootstrapToken)
			devInstallationP0.state = st
		}
		return st, nil
	}
	db, err := sql.Open(firstNonEmpty(s.Config.SQLDriver, "pgx"), s.Config.DatabaseDSN)
	if err != nil {
		return installationStateP0{}, err
	}
	defer db.Close()
	return loadInstallationStateP0(ctx, db)
}

func (s Server) consumeBootstrapTokenP0(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("bootstrap token required")
	}
	hash := bootstrapTokenHashP0(token)
	if isMemoryRepository950(s.Config.RepositoryDriver) {
		devInstallationP0.Lock()
		defer devInstallationP0.Unlock()
		st := devInstallationP0.state
		if st.TokenHash == "" {
			st.TokenHash = bootstrapTokenHashP0(s.Config.BootstrapToken)
		}
		if st.Completed || st.TokenUsedAt.Valid {
			return errors.New("bootstrap token already consumed")
		}
		if subtle.ConstantTimeCompare([]byte(st.TokenHash), []byte(hash)) != 1 {
			return errors.New("invalid bootstrap token")
		}
		st.TokenUsedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		devInstallationP0.state = st
		return nil
	}
	db, err := sql.Open(firstNonEmpty(s.Config.SQLDriver, "pgx"), s.Config.DatabaseDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := db.ExecContext(ctx, `UPDATE neverlauncher_installation_state SET bootstrap_token_used_at=now(), updated_at=now() WHERE singleton=TRUE AND installation_completed=FALSE AND bootstrap_token_used_at IS NULL AND bootstrap_token_hash=$1`, hash)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return errors.New("invalid, consumed, or disabled bootstrap token")
	}
	return nil
}

func (s Server) completeInstallationP0(ctx context.Context) error {
	if isMemoryRepository950(s.Config.RepositoryDriver) {
		devInstallationP0.Lock()
		defer devInstallationP0.Unlock()
		st := devInstallationP0.state
		st.Completed = true
		st.CompletedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		devInstallationP0.state = st
		return nil
	}
	db, err := sql.Open(firstNonEmpty(s.Config.SQLDriver, "pgx"), s.Config.DatabaseDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := db.ExecContext(ctx, `UPDATE neverlauncher_installation_state SET installation_completed=TRUE, completed_at=COALESCE(completed_at,now()), bootstrap_token_hash='', updated_at=now() WHERE singleton=TRUE AND bootstrap_token_used_at IS NOT NULL`)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("installation state cannot be completed before bootstrap token is consumed")
	}
	return nil
}

func bootstrapTokenFromRequestP0(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-NeverLauncher-Bootstrap-Token")); v != "" {
		return v
	}
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(h, "Bootstrap ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bootstrap "))
	}
	return ""
}

func (s Server) createBootstrapAdminP0(ctx context.Context, email, displayName, password, actor, token string) (model.User, error) {
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)
	password = strings.TrimSpace(password)
	if email == "" || password == "" {
		return model.User{}, errors.New("email and password are required")
	}
	if len(password) < 12 {
		return model.User{}, errors.New("bootstrap admin password must be at least 12 characters")
	}
	userID := "admin-" + strings.NewReplacer("@", "-", ".", "-", "+", "-").Replace(strings.ToLower(email))
	now := time.Now().UTC()
	user := model.User{ID: userID, Email: email, DisplayName: firstNonEmpty(displayName, "Administrator"), RoleID: "owner", Status: "active", ProjectRoles: map[string]string{"*": "owner"}, PasswordHash: hashPassword(password), PasswordUpdatedAt: now, CreatedAt: now, UpdatedAt: now}
	if isMemoryRepository950(s.Config.RepositoryDriver) {
		if len(s.Repo.ListUsers()) > 0 {
			return model.User{}, errors.New("bootstrap admin is disabled after the first user exists")
		}
		if err := s.consumeBootstrapTokenP0(ctx, token); err != nil {
			return model.User{}, err
		}
		created, err := s.Repo.SaveUser(user)
		if err != nil {
			return model.User{}, err
		}
		return created, nil
	}
	db, err := sql.Open(firstNonEmpty(s.Config.SQLDriver, "pgx"), s.Config.DatabaseDSN)
	if err != nil {
		return model.User{}, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.User{}, err
	}
	defer tx.Rollback()
	var tokenHash string
	var used sql.NullTime
	var completed bool
	if err = tx.QueryRowContext(ctx, `SELECT bootstrap_token_hash, bootstrap_token_used_at, installation_completed FROM neverlauncher_installation_state WHERE singleton=TRUE FOR UPDATE`).Scan(&tokenHash, &used, &completed); err != nil {
		return model.User{}, err
	}
	if completed || used.Valid {
		return model.User{}, errors.New("bootstrap token already consumed or installation completed")
	}
	supplied := bootstrapTokenHashP0(token)
	if token == "" || subtle.ConstantTimeCompare([]byte(tokenHash), []byte(supplied)) != 1 {
		return model.User{}, errors.New("invalid bootstrap token")
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users LIMIT 1)`).Scan(&exists); err != nil {
		return model.User{}, err
	}
	if exists {
		return model.User{}, errors.New("bootstrap admin is disabled after the first user exists")
	}
	rolesRaw := `{"*":"owner"}`
	_, err = tx.ExecContext(ctx, `INSERT INTO users(id,email,display_name,role_id,status,project_roles,password_hash,password_updated_at,created_at,updated_at) VALUES($1,$2,$3,'owner','active',$4::jsonb,$5,$6,$6,$6)`, user.ID, user.Email, user.DisplayName, rolesRaw, user.PasswordHash, now)
	if err != nil {
		return model.User{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_identities(id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at)
VALUES($1,$2,'local',$2,$3,$3,$4,'{}'::jsonb,$5,$5)
ON CONFLICT(user_id,provider) DO UPDATE SET subject=EXCLUDED.subject,email=EXCLUDED.email,username=EXCLUDED.username,display_name=EXCLUDED.display_name,updated_at=EXCLUDED.updated_at`, "identity-local-"+user.ID, user.ID, user.Email, user.DisplayName, now); err != nil {
		return model.User{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE neverlauncher_installation_state SET bootstrap_token_used_at=$1, updated_at=$1 WHERE singleton=TRUE`, now); err != nil {
		return model.User{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(id,actor,action,target,ip,user_agent,created_at) VALUES($1,$2,'install.bootstrap-admin',$3,'','0.10.0-P0',$4)`, fmt.Sprintf("install-admin-%d", now.UnixNano()), firstNonEmpty(actor, "installer"), email, now); err != nil {
		return model.User{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.User{}, err
	}
	return user, nil
}
