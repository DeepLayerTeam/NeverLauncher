package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/dbmigrate"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// SQLRepository — минимальная SQL-реализация Repository для PostgreSQL-схемы NeverLauncher.
//
// Реализация intentionally narrow: она закрывает основные production-сущности API
// (projects, profiles, release_channels, release_versions, files, users, roles,
// audit_events, telemetry_events, crash_reports) и больше не делегирует PostgreSQL-режим в MemoryRepository.
// Для работы требуется зарегистрированный database/sql driver.
// По умолчанию используется имя драйвера "pgx" через github.com/jackc/pgx/v5/stdlib.
// Для нестандартного driver-name используйте NewSQLRepository.
type SQLRepository struct {
	db         *sql.DB
	initErr    error
	driverName string
	publicURL  string
}

// NewPostgresRepository создаёт SQL repository для PostgreSQL-режима.
func NewPostgresRepository(dsn string, publicURL string) Repository {
	return NewSQLRepository("pgx", dsn, publicURL)
}

// NewSQLRepository создаёт repository поверх database/sql.
// driverName намеренно вынесен наружу: production-сборка может регистрировать
// github.com/lib/pq как "postgres" или pgx stdlib как "pgx".
func NewSQLRepository(driverName, dsn string, publicURL string) Repository {
	driverName = strings.TrimSpace(driverName)
	if driverName == "" {
		driverName = "pgx"
	}
	db, err := sql.Open(driverName, dsn)
	return &SQLRepository{db: db, initErr: err, driverName: driverName, publicURL: strings.TrimRight(publicURL, "/")}
}

func (r *SQLRepository) check() error {
	if r == nil {
		return errors.New("sql repository не инициализирован")
	}
	if r.initErr != nil {
		return fmt.Errorf("postgres driver недоступен: %w", r.initErr)
	}
	if r.db == nil {
		return errors.New("postgres db handle отсутствует")
	}
	return nil
}

// Health проверяет доступность SQL backend.
// Метод используется /ready: storage может быть доступен, но backend нельзя считать готовым,
// если SQL repository не подключается к базе.
func (r *SQLRepository) Health(ctx context.Context) error {
	if err := r.check(); err != nil {
		return err
	}
	if err := r.db.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres repository недоступен через driver %q: %w", r.driverName, err)
	}
	return nil
}

func (r *SQLRepository) MigrationStatus(ctx context.Context) (dbmigrate.Status, error) {
	if err := r.check(); err != nil {
		return dbmigrate.Status{}, err
	}
	return dbmigrate.StatusOf(ctx, r.db)
}

func (r *SQLRepository) ApplyMigrations(ctx context.Context) (dbmigrate.Status, error) {
	if err := r.check(); err != nil {
		return dbmigrate.Status{}, err
	}
	return dbmigrate.Apply(ctx, r.db)
}

func (r *SQLRepository) ListProjects() []model.Project {
	if err := r.check(); err != nil {
		return nil
	}
	rows, err := r.db.Query(`SELECT id, name, description, homepage, repository, default_channel, created_at, updated_at FROM projects ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []model.Project
	for rows.Next() {
		var item model.Project
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Homepage, &item.Repository, &item.DefaultChannel, &item.CreatedAt, &item.UpdatedAt); err == nil {
			result = append(result, item)
		}
	}
	return result
}

func (r *SQLRepository) GetProject(id string) (model.Project, error) {
	if err := r.check(); err != nil {
		return model.Project{}, err
	}
	var item model.Project
	err := r.db.QueryRow(`SELECT id, name, description, homepage, repository, default_channel, created_at, updated_at FROM projects WHERE id = $1`, id).Scan(&item.ID, &item.Name, &item.Description, &item.Homepage, &item.Repository, &item.DefaultChannel, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Project{}, ErrNotFound
	}
	return item, err
}

func (r *SQLRepository) SaveProject(project model.Project) (model.Project, error) {
	if err := r.check(); err != nil {
		return model.Project{}, err
	}
	now := time.Now().UTC()
	project.ID = strings.TrimSpace(project.ID)
	project.Name = strings.TrimSpace(project.Name)
	if project.ID == "" {
		project.ID = strings.ToLower(strings.ReplaceAll(project.Name, " ", "-"))
	}
	if project.ID == "" || project.Name == "" {
		return model.Project{}, fmt.Errorf("id и name проекта обязательны")
	}
	if project.DefaultChannel == "" {
		project.DefaultChannel = "stable"
	}
	if project.CreatedAt.IsZero() {
		if existing, err := r.GetProject(project.ID); err == nil {
			project.CreatedAt = existing.CreatedAt
		} else {
			project.CreatedAt = now
		}
	}
	project.UpdatedAt = now
	_, err := r.db.Exec(`INSERT INTO projects (id, name, description, homepage, repository, default_channel, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, homepage = EXCLUDED.homepage, repository = EXCLUDED.repository, default_channel = EXCLUDED.default_channel, updated_at = EXCLUDED.updated_at`, project.ID, project.Name, project.Description, project.Homepage, project.Repository, project.DefaultChannel, project.CreatedAt, project.UpdatedAt)
	if err != nil {
		return model.Project{}, err
	}
	return r.GetProject(project.ID)
}

func (r *SQLRepository) ListProfiles(projectID string) ([]model.Profile, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(`SELECT id, project_id, name, description, loader, COALESCE(preset, ''), is_default, created_at, updated_at FROM profiles WHERE project_id = $1 ORDER BY id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Profile
	for rows.Next() {
		var item model.Profile
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.Name, &item.Description, &item.Loader, &item.Preset, &item.IsDefault, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *SQLRepository) SaveProfile(profile model.Profile) (model.Profile, error) {
	if err := r.check(); err != nil {
		return model.Profile{}, err
	}
	if _, err := r.GetProject(profile.ProjectID); err != nil {
		return model.Profile{}, err
	}
	now := time.Now().UTC()
	profile.ID = strings.TrimSpace(profile.ID)
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.ID == "" {
		profile.ID = strings.ToLower(strings.ReplaceAll(profile.Name, " ", "-"))
	}
	if profile.ID == "" || profile.ProjectID == "" || profile.Name == "" {
		return model.Profile{}, fmt.Errorf("projectId, id и name профиля обязательны")
	}
	if profile.Loader == "" {
		profile.Loader = "vanilla"
	}
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	profile.UpdatedAt = now
	_, err := r.db.Exec(`INSERT INTO profiles (id, project_id, name, description, loader, preset, is_default, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (project_id, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, loader = EXCLUDED.loader, preset = EXCLUDED.preset, is_default = EXCLUDED.is_default, updated_at = EXCLUDED.updated_at`, profile.ID, profile.ProjectID, profile.Name, profile.Description, profile.Loader, profile.Preset, profile.IsDefault, profile.CreatedAt, profile.UpdatedAt)
	if err != nil {
		return model.Profile{}, err
	}
	profiles, err := r.ListProfiles(profile.ProjectID)
	if err != nil {
		return model.Profile{}, err
	}
	for _, item := range profiles {
		if item.ID == profile.ID {
			return item, nil
		}
	}
	return profile, nil
}

func (r *SQLRepository) ListChannels(projectID string) ([]model.ReleaseChannel, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(`SELECT id, project_id, name, description, protected FROM release_channels WHERE project_id = $1 ORDER BY id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.ReleaseChannel
	for rows.Next() {
		var item model.ReleaseChannel
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.Name, &item.Description, &item.Protected); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *SQLRepository) SaveChannel(channel model.ReleaseChannel) (model.ReleaseChannel, error) {
	if err := r.check(); err != nil {
		return model.ReleaseChannel{}, err
	}
	if _, err := r.GetProject(channel.ProjectID); err != nil {
		return model.ReleaseChannel{}, err
	}
	channel.ID = strings.TrimSpace(channel.ID)
	channel.Name = strings.TrimSpace(channel.Name)
	if channel.ID == "" {
		channel.ID = strings.ToLower(strings.ReplaceAll(channel.Name, " ", "-"))
	}
	if channel.Name == "" {
		channel.Name = channel.ID
	}
	if channel.ID == "" || channel.ProjectID == "" {
		return model.ReleaseChannel{}, fmt.Errorf("projectId и id канала обязательны")
	}
	_, err := r.db.Exec(`INSERT INTO release_channels (id, project_id, name, description, protected)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (project_id, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, protected = EXCLUDED.protected`, channel.ID, channel.ProjectID, channel.Name, channel.Description, channel.Protected)
	if err != nil {
		return model.ReleaseChannel{}, err
	}
	channels, err := r.ListChannels(channel.ProjectID)
	if err != nil {
		return model.ReleaseChannel{}, err
	}
	for _, item := range channels {
		if item.ID == channel.ID {
			return item, nil
		}
	}
	return channel, nil
}

func (r *SQLRepository) ListVersions(projectID string) ([]model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(`SELECT id, project_id, profile_id, channel, version, status, manifest, published_at FROM release_versions WHERE project_id = $1 ORDER BY published_at DESC NULLS LAST, version DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.ReleaseVersion
	for rows.Next() {
		item, err := scanReleaseVersion(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *SQLRepository) ListFiles(projectID, versionID string) ([]model.FileObject, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	query := `SELECT id, project_id, version_id, path, size, sha256, url, required, executable, target_os::text FROM files WHERE project_id = $1`
	args := []any{projectID}
	if versionID != "" {
		query += ` AND version_id = $2`
		args = append(args, versionID)
	}
	query += ` ORDER BY path`
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.FileObject
	for rows.Next() {
		var item model.FileObject
		var targetOSRaw string
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.VersionID, &item.Path, &item.Size, &item.SHA256, &item.URL, &item.Required, &item.Executable, &targetOSRaw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(targetOSRaw), &item.TargetOS); err != nil {
			return nil, fmt.Errorf("files.target_os повреждён для %s: %w", item.Path, err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *SQLRepository) ListUsers() []model.User {
	if err := r.check(); err != nil {
		return nil
	}
	rows, err := r.db.Query(`SELECT id, email, display_name, role_id, status, project_roles, password_hash, password_updated_at, last_login_at, disabled_at, created_at, updated_at FROM users ORDER BY email`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []model.User
	for rows.Next() {
		item, err := scanUser(rows)
		if err == nil {
			result = append(result, item)
		}
	}
	return result
}

func (r *SQLRepository) GetUser(id string) (model.User, error) {
	if err := r.check(); err != nil {
		return model.User{}, err
	}
	row := r.db.QueryRow(`SELECT id, email, display_name, role_id, status, project_roles, password_hash, password_updated_at, last_login_at, disabled_at, created_at, updated_at FROM users WHERE id = $1`, id)
	item, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	return item, err
}

func (r *SQLRepository) GetUserByEmail(email string) (model.User, error) {
	if err := r.check(); err != nil {
		return model.User{}, err
	}
	row := r.db.QueryRow(`SELECT id, email, display_name, role_id, status, project_roles, password_hash, password_updated_at, last_login_at, disabled_at, created_at, updated_at FROM users WHERE lower(email) = lower($1)`, email)
	item, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	return item, err
}

func (r *SQLRepository) SaveUser(user model.User) (model.User, error) {
	if err := r.check(); err != nil {
		return model.User{}, err
	}
	now := time.Now().UTC()
	if user.ID == "" {
		user.ID = fmt.Sprintf("user-%d", now.UnixNano())
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if user.RoleID == "" {
		user.RoleID = "viewer"
	}
	if user.ProjectRoles == nil {
		user.ProjectRoles = map[string]string{}
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now
	projectRoles, _ := json.Marshal(user.ProjectRoles)

	tx, err := r.db.Begin()
	if err != nil {
		return model.User{}, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO users (id, email, display_name, role_id, status, project_roles, password_hash, password_updated_at, last_login_at, disabled_at, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, display_name = EXCLUDED.display_name, role_id = EXCLUDED.role_id, status = EXCLUDED.status, project_roles = EXCLUDED.project_roles, password_hash = EXCLUDED.password_hash, password_updated_at = EXCLUDED.password_updated_at, last_login_at = EXCLUDED.last_login_at, disabled_at = EXCLUDED.disabled_at, updated_at = EXCLUDED.updated_at`,
		user.ID, user.Email, user.DisplayName, user.RoleID, user.Status, string(projectRoles), user.PasswordHash, nullTime(user.PasswordUpdatedAt), nullTime(user.LastLoginAt), nullTime(user.DisabledAt), user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return model.User{}, err
	}
	if strings.TrimSpace(user.PasswordHash) != "" {
		identityID := "identity-local-" + user.ID
		_, err = tx.Exec(`INSERT INTO auth_identities(id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at)
VALUES($1,$2,'local',$2,$3,$3,$4,'{}'::jsonb,now(),now())
ON CONFLICT(user_id,provider) DO UPDATE SET subject=EXCLUDED.subject,email=EXCLUDED.email,username=EXCLUDED.username,display_name=EXCLUDED.display_name,updated_at=now()`, identityID, user.ID, user.Email, user.DisplayName)
		if err != nil {
			return model.User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, err
	}
	return r.GetUser(user.ID)
}

func (r *SQLRepository) SetUserDisabled(id string, disabled bool) (model.User, error) {
	if err := r.check(); err != nil {
		return model.User{}, err
	}
	status := "active"
	var disabledAt any = nil
	if disabled {
		status = "disabled"
		disabledAt = time.Now().UTC()
	}
	if _, err := r.db.Exec(`UPDATE users SET status = $2, disabled_at = $3, updated_at = now() WHERE id = $1`, id, status, disabledAt); err != nil {
		return model.User{}, err
	}
	return r.GetUser(id)
}

func (r *SQLRepository) SetUserPassword(id, passwordHash string) (model.User, error) {
	if err := r.check(); err != nil {
		return model.User{}, err
	}
	if _, err := r.db.Exec(`UPDATE users SET password_hash = $2, password_updated_at = now(), updated_at = now() WHERE id = $1`, id, passwordHash); err != nil {
		return model.User{}, err
	}
	return r.GetUser(id)
}

func (r *SQLRepository) TouchUserLogin(id string) (model.User, error) {
	if err := r.check(); err != nil {
		return model.User{}, err
	}
	if _, err := r.db.Exec(`UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`, id); err != nil {
		return model.User{}, err
	}
	return r.GetUser(id)
}

func (r *SQLRepository) GetAuthIdentity(provider, subject string) (model.AuthIdentity, error) {
	if err := r.check(); err != nil {
		return model.AuthIdentity{}, err
	}
	var item model.AuthIdentity
	var claimsRaw []byte
	var lastAuth sql.NullTime
	err := r.db.QueryRow(`SELECT id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at,last_authenticated_at FROM auth_identities WHERE provider=$1 AND subject=$2`, strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(subject)).Scan(&item.ID, &item.UserID, &item.Provider, &item.Subject, &item.Email, &item.Username, &item.DisplayName, &claimsRaw, &item.CreatedAt, &item.UpdatedAt, &lastAuth)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AuthIdentity{}, ErrNotFound
	}
	if err != nil {
		return model.AuthIdentity{}, err
	}
	if len(claimsRaw) > 0 {
		_ = json.Unmarshal(claimsRaw, &item.Claims)
	}
	if lastAuth.Valid {
		item.LastAuthenticatedAt = lastAuth.Time
	}
	return item, nil
}

func (r *SQLRepository) ListAuthIdentities(userID string) []model.AuthIdentity {
	if err := r.check(); err != nil {
		return nil
	}
	query := `SELECT id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at,last_authenticated_at FROM auth_identities`
	var rows *sql.Rows
	var err error
	if strings.TrimSpace(userID) == "" {
		rows, err = r.db.Query(query + ` ORDER BY provider,subject`)
	} else {
		rows, err = r.db.Query(query+` WHERE user_id=$1 ORDER BY provider,subject`, userID)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()
	var items []model.AuthIdentity
	for rows.Next() {
		var item model.AuthIdentity
		var claimsRaw []byte
		var lastAuth sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserID, &item.Provider, &item.Subject, &item.Email, &item.Username, &item.DisplayName, &claimsRaw, &item.CreatedAt, &item.UpdatedAt, &lastAuth); err != nil {
			continue
		}
		if len(claimsRaw) > 0 {
			_ = json.Unmarshal(claimsRaw, &item.Claims)
		}
		if lastAuth.Valid {
			item.LastAuthenticatedAt = lastAuth.Time
		}
		items = append(items, item)
	}
	return items
}

func (r *SQLRepository) SaveAuthIdentity(identity model.AuthIdentity) (model.AuthIdentity, error) {
	if err := r.check(); err != nil {
		return model.AuthIdentity{}, err
	}
	identity.Provider = strings.ToLower(strings.TrimSpace(identity.Provider))
	identity.Subject = strings.TrimSpace(identity.Subject)
	identity.UserID = strings.TrimSpace(identity.UserID)
	if identity.Provider == "" || identity.Subject == "" || identity.UserID == "" {
		return model.AuthIdentity{}, fmt.Errorf("userId, provider и subject identity обязательны")
	}
	if _, err := r.GetUser(identity.UserID); err != nil {
		return model.AuthIdentity{}, err
	}
	existing, lookupErr := r.GetAuthIdentity(identity.Provider, identity.Subject)
	if lookupErr == nil && existing.UserID != identity.UserID {
		return model.AuthIdentity{}, fmt.Errorf("identity %s/%s уже связана с другим пользователем", identity.Provider, identity.Subject)
	}
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return model.AuthIdentity{}, lookupErr
	}
	var currentSubject string
	err := r.db.QueryRow(`SELECT subject FROM auth_identities WHERE user_id=$1 AND provider=$2`, identity.UserID, identity.Provider).Scan(&currentSubject)
	if err == nil && currentSubject != identity.Subject {
		return model.AuthIdentity{}, fmt.Errorf("provider %s уже связан с другим subject для пользователя", identity.Provider)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.AuthIdentity{}, err
	}
	if identity.ID == "" {
		identity.ID = "identity-" + identity.Provider + "-" + identity.UserID
	}
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = time.Now().UTC()
	}
	claims, err := json.Marshal(identity.Claims)
	if err != nil {
		return model.AuthIdentity{}, err
	}
	_, err = r.db.Exec(`INSERT INTO auth_identities(id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at,last_authenticated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,now(),$10)
ON CONFLICT(user_id,provider) DO UPDATE SET subject=EXCLUDED.subject,email=EXCLUDED.email,username=EXCLUDED.username,display_name=EXCLUDED.display_name,claims=EXCLUDED.claims,updated_at=now(),last_authenticated_at=COALESCE(EXCLUDED.last_authenticated_at,auth_identities.last_authenticated_at)`, identity.ID, identity.UserID, identity.Provider, identity.Subject, identity.Email, identity.Username, identity.DisplayName, string(claims), identity.CreatedAt, nullTime(identity.LastAuthenticatedAt))
	if err != nil {
		return model.AuthIdentity{}, err
	}
	return r.GetAuthIdentity(identity.Provider, identity.Subject)
}

func (r *SQLRepository) SaveFederatedUser(ctx context.Context, user model.User, identity model.AuthIdentity) (model.User, model.AuthIdentity, error) {
	if err := r.check(); err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now().UTC()
	user.ID = strings.TrimSpace(user.ID)
	user.Email = strings.TrimSpace(user.Email)
	identity.Provider = strings.ToLower(strings.TrimSpace(identity.Provider))
	identity.Subject = strings.TrimSpace(identity.Subject)
	if user.ID == "" || user.Email == "" || identity.Provider == "" || identity.Subject == "" {
		return model.User{}, model.AuthIdentity{}, fmt.Errorf("federated user id/email and provider/subject are required")
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if user.RoleID == "" {
		user.RoleID = "player"
	}
	if user.ProjectRoles == nil {
		user.ProjectRoles = map[string]string{}
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now
	identity.UserID = user.ID
	if identity.ID == "" {
		identity.ID = "identity-" + identity.Provider + "-" + user.ID
	}
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = now
	}
	identity.UpdatedAt = now
	if identity.LastAuthenticatedAt.IsZero() {
		identity.LastAuthenticatedAt = now
	}
	projectRoles, err := json.Marshal(user.ProjectRoles)
	if err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	claims, err := json.Marshal(identity.Claims)
	if err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}

	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	defer tx.Rollback()

	// Serialize JIT provisioning on the normalized email even when no row exists yet.
	// The users.email constraint may be case-sensitive, while identity linking policy
	// deliberately treats email case-insensitively. The transaction-scoped advisory
	// lock closes the otherwise unavoidable "check-then-insert" race.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(lower($1), 0))`, user.Email); err != nil {
		return model.User{}, model.AuthIdentity{}, fmt.Errorf("lock federated canonical email: %w", err)
	}
	var emailOwner string
	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1`, user.Email).Scan(&emailOwner)
	if err == nil && emailOwner != user.ID {
		return model.User{}, model.AuthIdentity{}, fmt.Errorf("%w: canonical email is already used by another Never user", ErrConflict)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.User{}, model.AuthIdentity{}, err
	}

	// JIT provisioning is create-once. ON CONFLICT DO NOTHING also makes concurrent
	// first logins for the same deterministic canonical id idempotent.
	result, err := tx.ExecContext(ctx, `INSERT INTO users (id,email,display_name,role_id,status,project_roles,password_hash,password_updated_at,last_login_at,disabled_at,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,$6,'',NULL,NULL,NULL,$7,$8)
ON CONFLICT DO NOTHING`, user.ID, user.Email, user.DisplayName, user.RoleID, user.Status, string(projectRoles), user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return model.User{}, model.AuthIdentity{}, fmt.Errorf("save federated canonical user: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	if inserted == 0 {
		var existingEmail string
		if err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id=$1`, user.ID).Scan(&existingEmail); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return model.User{}, model.AuthIdentity{}, fmt.Errorf("%w: canonical email is already used by another Never user", ErrConflict)
			}
			return model.User{}, model.AuthIdentity{}, err
		}
		if !strings.EqualFold(strings.TrimSpace(existingEmail), user.Email) {
			return model.User{}, model.AuthIdentity{}, fmt.Errorf("%w: deterministic canonical user id already exists with another email", ErrConflict)
		}
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO auth_identities(id,user_id,provider,subject,email,username,display_name,claims,created_at,updated_at,last_authenticated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11)
ON CONFLICT(provider,subject) DO NOTHING`, identity.ID, identity.UserID, identity.Provider, identity.Subject, identity.Email, identity.Username, identity.DisplayName, string(claims), identity.CreatedAt, identity.UpdatedAt, identity.LastAuthenticatedAt)
	if err != nil {
		return model.User{}, model.AuthIdentity{}, fmt.Errorf("save federated identity: %w", err)
	}
	var linkedUserID string
	if err := tx.QueryRowContext(ctx, `SELECT user_id FROM auth_identities WHERE provider=$1 AND subject=$2`, identity.Provider, identity.Subject).Scan(&linkedUserID); err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	if linkedUserID != user.ID {
		return model.User{}, model.AuthIdentity{}, fmt.Errorf("%w: external identity is already linked to another Never user", ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	canonical, err := r.GetUser(user.ID)
	if err != nil {
		return model.User{}, model.AuthIdentity{}, err
	}
	linked, err := r.GetAuthIdentity(identity.Provider, identity.Subject)
	return canonical, linked, err
}

func (r *SQLRepository) TouchAuthIdentity(id string) (model.AuthIdentity, error) {
	if err := r.check(); err != nil {
		return model.AuthIdentity{}, err
	}
	var provider, subject string
	if err := r.db.QueryRow(`UPDATE auth_identities SET last_authenticated_at=now(),updated_at=now() WHERE id=$1 RETURNING provider,subject`, id).Scan(&provider, &subject); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.AuthIdentity{}, ErrNotFound
		}
		return model.AuthIdentity{}, err
	}
	return r.GetAuthIdentity(provider, subject)
}

func (r *SQLRepository) ListRoles() []model.Role {
	fallback := []model.Role{{ID: "owner", Name: "Владелец", Permissions: []string{"*"}}, {ID: "admin", Name: "Администратор", Permissions: []string{"project:read", "project:write", "release:prepare", "release:publish", "file:write", "users:manage", "audit:read"}}, {ID: "developer", Name: "Разработчик", Permissions: []string{"project:read", "release:prepare", "file:write"}}, {ID: "viewer", Name: "Наблюдатель", Permissions: []string{"project:read"}}}
	if err := r.check(); err != nil {
		return fallback
	}
	rows, err := r.db.Query(`SELECT id, name, description, permissions FROM roles ORDER BY id`)
	if err != nil {
		return fallback
	}
	defer rows.Close()
	var result []model.Role
	for rows.Next() {
		var item model.Role
		var permissionsRaw []byte
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &permissionsRaw); err != nil {
			continue
		}
		_ = json.Unmarshal(permissionsRaw, &item.Permissions)
		result = append(result, item)
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}

func (r *SQLRepository) ListAuditEvents() []model.AuditEvent {
	if err := r.check(); err != nil {
		return nil
	}
	rows, err := r.db.Query(`SELECT id, actor, action, target, ip, user_agent, created_at FROM audit_events ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []model.AuditEvent
	for rows.Next() {
		var item model.AuditEvent
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.Target, &item.IP, &item.UserAgent, &item.CreatedAt); err == nil {
			result = append(result, item)
		}
	}
	return result
}

func (r *SQLRepository) AddAuditEvent(event model.AuditEvent) {
	if err := r.check(); err != nil {
		return
	}
	if event.ID == "" {
		event.ID = fmt.Sprintf("audit-%d", time.Now().UTC().UnixNano())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, _ = r.db.Exec(`INSERT INTO audit_events (id, actor, action, target, ip, user_agent, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, event.ID, event.Actor, event.Action, event.Target, event.IP, event.UserAgent, event.CreatedAt)
}

func (r *SQLRepository) GetManifest(projectID, profileID, channel string) (model.Manifest, error) {
	if err := r.check(); err != nil {
		return model.Manifest{}, err
	}
	row := r.db.QueryRow(`SELECT manifest FROM release_versions WHERE project_id = $1 AND profile_id = $2 AND channel = $3 ORDER BY published_at DESC LIMIT 1`, projectID, profileID, channel)
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Manifest{}, ErrNotFound
		}
		return model.Manifest{}, err
	}
	var manifest model.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return model.Manifest{}, err
	}
	return manifest, nil
}

func (r *SQLRepository) CreateVersion(projectID, profileID, channel, version string) (model.ReleaseVersion, error) {
	if profileID == "" {
		profileID = "vanilla"
	}
	if channel == "" {
		channel = "dev"
	}
	if version == "" {
		version = time.Now().UTC().Format("20060102150405")
	}
	now := time.Now().UTC()
	manifest := model.Manifest{SchemaVersion: "1.0", ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, CreatedAt: now.Format(time.RFC3339), Files: []model.ManifestFile{}}
	return r.saveRelease(model.ReleaseVersion{ID: fmt.Sprintf("%s-%s-%s", projectID, profileID, version), ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, Status: "draft", Manifest: manifest, PublishedAt: now})
}

func (r *SQLRepository) PublishVersion(projectID, profileID, channel, version string) (model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return model.ReleaseVersion{}, err
	}
	if profileID == "" {
		profileID = "vanilla"
	}
	if channel == "" {
		channel = "stable"
	}
	if version == "" {
		version = time.Now().UTC().Format("20060102150405")
	}
	now := time.Now().UTC()
	releaseID := fmt.Sprintf("%s-%s-%s", projectID, profileID, version)
	manifest := model.Manifest{SchemaVersion: "1.0", ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, CreatedAt: now.Format(time.RFC3339), Files: []model.ManifestFile{}}

	tx, err := r.db.Begin()
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	defer tx.Rollback()

	var existingRaw []byte
	var existingStatus string
	err = tx.QueryRow(`SELECT manifest, status FROM release_versions
		WHERE project_id=$1 AND profile_id=$2 AND channel=$3 AND version=$4
		FOR UPDATE`, projectID, profileID, channel, version).Scan(&existingRaw, &existingStatus)
	switch {
	case err == nil:
		if existingStatus == "published" {
			return model.ReleaseVersion{}, ErrImmutable
		}
		if len(existingRaw) > 0 {
			_ = json.Unmarshal(existingRaw, &manifest)
		}
	case errors.Is(err, sql.ErrNoRows):
		// New release: no row exists to lock yet. The conditional UPSERT below is
		// the second guard against a concurrent publisher creating the same version.
	default:
		return model.ReleaseVersion{}, err
	}

	manifest.ProjectID = projectID
	manifest.ProfileID = profileID
	manifest.Channel = channel
	manifest.Version = version
	manifest.CreatedAt = now.Format(time.RFC3339)

	rows, err := tx.Query(`SELECT id, project_id, version_id, path, size, sha256, url, required, executable, target_os::text
		FROM files WHERE project_id=$1 AND version_id=$2 ORDER BY path`, projectID, releaseID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	var files []model.FileObject
	for rows.Next() {
		var file model.FileObject
		var targetOSRaw string
		if err := rows.Scan(&file.ID, &file.ProjectID, &file.VersionID, &file.Path, &file.Size, &file.SHA256, &file.URL, &file.Required, &file.Executable, &targetOSRaw); err != nil {
			rows.Close()
			return model.ReleaseVersion{}, err
		}
		if err := json.Unmarshal([]byte(targetOSRaw), &file.TargetOS); err != nil {
			rows.Close()
			return model.ReleaseVersion{}, fmt.Errorf("files.target_os повреждён для %s: %w", file.Path, err)
		}
		files = append(files, file)
	}
	if err := rows.Close(); err != nil {
		return model.ReleaseVersion{}, err
	}
	if len(files) > 0 {
		manifest.Files = manifest.Files[:0]
		for _, file := range files {
			manifest.Files = append(manifest.Files, model.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256, URL: file.URL, Required: file.Required, Executable: file.Executable, TargetOS: append([]string(nil), file.TargetOS...)})
		}
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	res, err := tx.Exec(`INSERT INTO release_versions (id, project_id, profile_id, channel, version, status, manifest, published_at)
VALUES ($1,$2,$3,$4,$5,'published',$6,$7)
ON CONFLICT (project_id, profile_id, channel, version) DO UPDATE
SET status='published', manifest=EXCLUDED.manifest, published_at=EXCLUDED.published_at
WHERE release_versions.status <> 'published'`, releaseID, projectID, profileID, channel, version, string(manifestRaw), now)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return model.ReleaseVersion{}, ErrImmutable
	}
	if _, err := tx.Exec(`INSERT INTO release_channels (id, project_id, name, description, protected)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (project_id, id) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, protected=EXCLUDED.protected`, channel, projectID, channel, "Канал релиза", channel == "stable"); err != nil {
		return model.ReleaseVersion{}, err
	}
	if _, err := tx.Exec(`INSERT INTO audit_events (id, actor, action, target, created_at) VALUES ($1,$2,$3,$4,$5)`, fmt.Sprintf("audit-%d", now.UnixNano()), "system", "version:publish", releaseID, now); err != nil {
		return model.ReleaseVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ReleaseVersion{}, err
	}
	return model.ReleaseVersion{ID: releaseID, ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, Status: "published", Manifest: manifest, PublishedAt: now}, nil
}

func (r *SQLRepository) PublishVersionWithManifest(projectID, profileID, channel, version string, manifest model.Manifest) (model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return model.ReleaseVersion{}, err
	}
	manifest.ProjectID = projectID
	manifest.ProfileID = profileID
	manifest.Channel = channel
	manifest.Version = version
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = "1.0"
	}
	if manifest.Files == nil {
		manifest.Files = []model.ManifestFile{}
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	now := time.Now().UTC()
	releaseID := fmt.Sprintf("%s-%s-%s", projectID, profileID, version)
	tx, err := r.db.Begin()
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	defer tx.Rollback()
	var currentStatus string
	if err := tx.QueryRow(`SELECT status FROM release_versions WHERE id = $1 AND project_id = $2 AND profile_id = $3 AND channel = $4 AND version = $5 FOR UPDATE`, releaseID, projectID, profileID, channel, version).Scan(&currentStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ReleaseVersion{}, ErrNotFound
		}
		return model.ReleaseVersion{}, err
	}
	if currentStatus == "published" {
		return model.ReleaseVersion{}, ErrImmutable
	}
	if _, err := tx.Exec(`UPDATE release_versions
		SET status = 'published', manifest = $2, published_at = $3
		WHERE id = $1 AND project_id = $4`, releaseID, string(manifestRaw), now, projectID); err != nil {
		return model.ReleaseVersion{}, err
	}
	if _, err := tx.Exec(`INSERT INTO release_channels (id, project_id, name, description, protected)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (project_id, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, protected = EXCLUDED.protected`, channel, projectID, channel, "Канал релиза", channel == "stable"); err != nil {
		return model.ReleaseVersion{}, err
	}
	if _, err := tx.Exec(`INSERT INTO audit_events (id, actor, action, target, created_at) VALUES ($1,$2,$3,$4,$5)`, fmt.Sprintf("audit-%d", now.UnixNano()), "system", "version:publish", releaseID, now); err != nil {
		return model.ReleaseVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ReleaseVersion{}, err
	}
	return model.ReleaseVersion{ID: releaseID, ProjectID: projectID, ProfileID: profileID, Channel: channel, Version: version, Status: "published", Manifest: manifest, PublishedAt: now}, nil
}

func (r *SQLRepository) UpdateVersionStatus(projectID, versionID, status string) (model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return model.ReleaseVersion{}, err
	}
	status = strings.TrimSpace(status)
	if status == "" {
		return model.ReleaseVersion{}, errors.New("status обязателен")
	}
	res, err := r.db.Exec(`UPDATE release_versions SET status=$1, updated_at=now() WHERE project_id=$2 AND id=$3 AND status <> 'published'`, status, projectID, versionID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var current string
		if scanErr := r.db.QueryRow(`SELECT status FROM release_versions WHERE project_id=$1 AND id=$2`, projectID, versionID).Scan(&current); scanErr == nil && current == "published" {
			return model.ReleaseVersion{}, ErrImmutable
		}
		return model.ReleaseVersion{}, ErrNotFound
	}
	versions, err := r.ListVersions(projectID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	for _, item := range versions {
		if item.ID == versionID {
			return item, nil
		}
	}
	return model.ReleaseVersion{}, ErrNotFound
}

func (r *SQLRepository) UpdateVersionManifest(projectID, versionID string, manifest model.Manifest) (model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return model.ReleaseVersion{}, err
	}
	tx, err := r.db.Begin()
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	defer tx.Rollback()
	var found model.ReleaseVersion
	var raw []byte
	if err := tx.QueryRow(`SELECT id, project_id, profile_id, channel, version, status, manifest, published_at
		FROM release_versions WHERE project_id=$1 AND id=$2 FOR UPDATE`, projectID, versionID).
		Scan(&found.ID, &found.ProjectID, &found.ProfileID, &found.Channel, &found.Version, &found.Status, &raw, &found.PublishedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ReleaseVersion{}, ErrNotFound
		}
		return model.ReleaseVersion{}, err
	}
	if found.Status == "published" {
		return model.ReleaseVersion{}, ErrImmutable
	}
	_ = json.Unmarshal(raw, &found.Manifest)
	manifest.ProjectID, manifest.ProfileID, manifest.Channel, manifest.Version = projectID, found.ProfileID, found.Channel, found.Version
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = "1.0"
	}
	if manifest.Files == nil {
		manifest.Files = []model.ManifestFile{}
	}
	next, err := json.Marshal(manifest)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	res, err := tx.Exec(`UPDATE release_versions SET manifest=$1 WHERE id=$2 AND project_id=$3 AND status <> 'published'`, string(next), versionID, projectID)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.ReleaseVersion{}, ErrImmutable
	}
	if err := tx.Commit(); err != nil {
		return model.ReleaseVersion{}, err
	}
	found.Manifest = manifest
	return found, nil
}

func (r *SQLRepository) AddFile(file model.FileObject) (model.FileObject, error) {
	if err := r.check(); err != nil {
		return model.FileObject{}, err
	}
	tx, err := r.db.Begin()
	if err != nil {
		return model.FileObject{}, err
	}
	defer tx.Rollback()

	var releaseStatus string
	var manifestRaw []byte
	if err := tx.QueryRow(`SELECT status, manifest FROM release_versions WHERE project_id=$1 AND id=$2 FOR UPDATE`, file.ProjectID, file.VersionID).Scan(&releaseStatus, &manifestRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.FileObject{}, ErrNotFound
		}
		return model.FileObject{}, err
	}
	if releaseStatus == "published" {
		return model.FileObject{}, ErrImmutable
	}
	if file.ID == "" {
		file.ID = fmt.Sprintf("file-%d", time.Now().UTC().UnixNano())
	}
	if !file.Required {
		file.Required = true
	}
	targetOSRaw, err := json.Marshal(file.TargetOS)
	if err != nil {
		return model.FileObject{}, err
	}
	if _, err := tx.Exec(`INSERT INTO files (id, project_id, version_id, path, size, sha256, url, required, executable, target_os)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
ON CONFLICT (version_id, path) DO UPDATE SET size=EXCLUDED.size, sha256=EXCLUDED.sha256, url=EXCLUDED.url, required=EXCLUDED.required, executable=EXCLUDED.executable, target_os=EXCLUDED.target_os`, file.ID, file.ProjectID, file.VersionID, file.Path, file.Size, file.SHA256, file.URL, file.Required, file.Executable, string(targetOSRaw)); err != nil {
		return model.FileObject{}, err
	}
	var manifest model.Manifest
	_ = json.Unmarshal(manifestRaw, &manifest)
	updated := false
	for i := range manifest.Files {
		if manifest.Files[i].Path == file.Path {
			manifest.Files[i] = model.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256, URL: file.URL, Required: file.Required, Executable: file.Executable, TargetOS: append([]string(nil), file.TargetOS...)}
			updated = true
			break
		}
	}
	if !updated {
		manifest.Files = append(manifest.Files, model.ManifestFile{Path: file.Path, Size: file.Size, SHA256: file.SHA256, URL: file.URL, Required: file.Required, Executable: file.Executable, TargetOS: append([]string(nil), file.TargetOS...)})
	}
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	next, err := json.Marshal(manifest)
	if err != nil {
		return model.FileObject{}, err
	}
	res, err := tx.Exec(`UPDATE release_versions SET manifest=$1 WHERE id=$2 AND project_id=$3 AND status <> 'published'`, string(next), file.VersionID, file.ProjectID)
	if err != nil {
		return model.FileObject{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return model.FileObject{}, ErrImmutable
	}
	if err := tx.Commit(); err != nil {
		return model.FileObject{}, err
	}
	return file, nil
}

func (r *SQLRepository) ExportProject(projectID string) (map[string]any, error) {
	project, err := r.GetProject(projectID)
	if err != nil {
		return nil, err
	}
	profiles, _ := r.ListProfiles(projectID)
	channels, _ := r.ListChannels(projectID)
	versions, _ := r.ListVersions(projectID)
	files, _ := r.ListFiles(projectID, "")
	return map[string]any{"schemaVersion": "1.0", "exportedAt": time.Now().UTC(), "project": project, "profiles": profiles, "channels": channels, "versions": versions, "files": files}, nil
}

func (r *SQLRepository) ImportProject(payload map[string]any) error {
	if err := r.check(); err != nil {
		return err
	}
	project, ok := payload["project"].(map[string]any)
	if !ok {
		return errors.New("поле project обязательно для импорта")
	}
	id, _ := project["id"].(string)
	name, _ := project["name"].(string)
	if id == "" || name == "" {
		return errors.New("импортируемый проект должен содержать id и name")
	}
	now := time.Now().UTC()
	_, err := r.db.Exec(`INSERT INTO projects (id, name, description, homepage, repository, default_channel, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, updated_at = EXCLUDED.updated_at`, id, name, fmt.Sprint(project["description"]), fmt.Sprint(project["homepage"]), fmt.Sprint(project["repository"]), "stable", now, now)
	return err
}

func (r *SQLRepository) AddTelemetryEvent(event model.TelemetryEvent) {
	if err := r.check(); err != nil {
		return
	}
	if event.ID == "" {
		event.ID = fmt.Sprintf("telemetry-%d", time.Now().UTC().UnixNano())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, _ = r.db.Exec(`INSERT INTO telemetry_events (id, project_id, profile_id, launcher_version, profile_version, event, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, event.ID, event.ProjectID, event.ProfileID, event.LauncherVersion, event.ProfileVersion, event.Event, event.Status, event.CreatedAt)
}

func (r *SQLRepository) AddCrashReport(report model.CrashReport) {
	if err := r.check(); err != nil {
		return
	}
	if report.ID == "" {
		report.ID = fmt.Sprintf("crash-%d", time.Now().UTC().UnixNano())
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now().UTC()
	}
	_, _ = r.db.Exec(`INSERT INTO crash_reports (id, project_id, profile_id, launcher_version, profile_version, message, log, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, report.ID, report.ProjectID, report.ProfileID, report.LauncherVersion, report.ProfileVersion, report.Message, report.Log, report.CreatedAt)
}

func (r *SQLRepository) ListTelemetryEvents() []model.TelemetryEvent {
	if err := r.check(); err != nil {
		return nil
	}
	rows, err := r.db.Query(`SELECT id, project_id, profile_id, launcher_version, profile_version, event, status, created_at FROM telemetry_events ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []model.TelemetryEvent
	for rows.Next() {
		var item model.TelemetryEvent
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.ProfileID, &item.LauncherVersion, &item.ProfileVersion, &item.Event, &item.Status, &item.CreatedAt); err == nil {
			result = append(result, item)
		}
	}
	return result
}

func (r *SQLRepository) ListCrashReports() []model.CrashReport {
	if err := r.check(); err != nil {
		return nil
	}
	rows, err := r.db.Query(`SELECT id, project_id, profile_id, launcher_version, profile_version, message, log, created_at FROM crash_reports ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []model.CrashReport
	for rows.Next() {
		var item model.CrashReport
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.ProfileID, &item.LauncherVersion, &item.ProfileVersion, &item.Message, &item.Log, &item.CreatedAt); err == nil {
			result = append(result, item)
		}
	}
	return result
}

func (r *SQLRepository) saveRelease(release model.ReleaseVersion) (model.ReleaseVersion, error) {
	if err := r.check(); err != nil {
		return model.ReleaseVersion{}, err
	}
	manifestRaw, err := json.Marshal(release.Manifest)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	_, err = r.db.Exec(`INSERT INTO release_versions (id, project_id, profile_id, channel, version, status, manifest, published_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (project_id, profile_id, channel, version) DO UPDATE SET status = EXCLUDED.status, manifest = EXCLUDED.manifest, published_at = EXCLUDED.published_at`, release.ID, release.ProjectID, release.ProfileID, release.Channel, release.Version, release.Status, string(manifestRaw), release.PublishedAt)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	return release, nil
}

func scanReleaseVersion(scanner interface{ Scan(dest ...any) error }) (model.ReleaseVersion, error) {
	var item model.ReleaseVersion
	var raw []byte
	if err := scanner.Scan(&item.ID, &item.ProjectID, &item.ProfileID, &item.Channel, &item.Version, &item.Status, &raw, &item.PublishedAt); err != nil {
		return model.ReleaseVersion{}, err
	}
	if item.Status == "" {
		item.Status = "published"
	}
	_ = json.Unmarshal(raw, &item.Manifest)
	return item, nil
}

func scanUser(scanner interface{ Scan(dest ...any) error }) (model.User, error) {
	var item model.User
	var projectRolesRaw []byte
	var passwordUpdatedAt, lastLoginAt, disabledAt sql.NullTime
	if err := scanner.Scan(&item.ID, &item.Email, &item.DisplayName, &item.RoleID, &item.Status, &projectRolesRaw, &item.PasswordHash, &passwordUpdatedAt, &lastLoginAt, &disabledAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return model.User{}, err
	}
	if item.ProjectRoles == nil {
		item.ProjectRoles = map[string]string{}
	}
	_ = json.Unmarshal(projectRolesRaw, &item.ProjectRoles)
	if passwordUpdatedAt.Valid {
		item.PasswordUpdatedAt = passwordUpdatedAt.Time
	}
	if lastLoginAt.Valid {
		item.LastLoginAt = lastLoginAt.Time
	}
	if disabledAt.Valid {
		item.DisabledAt = disabledAt.Time
	}
	return item, nil
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

// ProductionPostgresTables возвращает список таблиц, зафиксированных production-контрактом.
func ProductionPostgresTables() []string {
	items := []string{"projects", "profiles", "release_channels", "release_versions", "files", "storage_objects", "users", "roles", "audit_events", "admin_sessions", "project_user_roles", "telemetry_events", "crash_reports", "schema_migrations"}
	sort.Strings(items)
	return items
}

func (r *SQLRepository) GetProviderCredential(userID, provider string) (model.ProviderCredential, error) {
	if err := r.check(); err != nil {
		return model.ProviderCredential{}, err
	}
	userID = strings.TrimSpace(userID)
	provider = strings.ToLower(strings.TrimSpace(provider))
	var item model.ProviderCredential
	var refreshed sql.NullTime
	err := r.db.QueryRow(`SELECT id,user_id,identity_id,provider,subject,encrypted_refresh_token,created_at,updated_at,last_refreshed_at FROM provider_credentials WHERE user_id=$1 AND provider=$2`, userID, provider).Scan(&item.ID, &item.UserID, &item.IdentityID, &item.Provider, &item.Subject, &item.EncryptedRefreshToken, &item.CreatedAt, &item.UpdatedAt, &refreshed)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ProviderCredential{}, ErrNotFound
	}
	if err != nil {
		return model.ProviderCredential{}, err
	}
	if refreshed.Valid {
		item.LastRefreshedAt = refreshed.Time
	}
	return item, nil
}

func (r *SQLRepository) SaveProviderCredential(item model.ProviderCredential) (model.ProviderCredential, error) {
	if err := r.check(); err != nil {
		return model.ProviderCredential{}, err
	}
	item.UserID = strings.TrimSpace(item.UserID)
	item.IdentityID = strings.TrimSpace(item.IdentityID)
	item.Provider = strings.ToLower(strings.TrimSpace(item.Provider))
	item.Subject = strings.TrimSpace(item.Subject)
	item.EncryptedRefreshToken = strings.TrimSpace(item.EncryptedRefreshToken)
	if item.UserID == "" || item.IdentityID == "" || item.Provider == "" || item.Subject == "" || item.EncryptedRefreshToken == "" {
		return model.ProviderCredential{}, fmt.Errorf("provider credential fields are required")
	}
	var linkedUserID string
	if err := r.db.QueryRow(`SELECT user_id FROM auth_identities WHERE id=$1 AND provider=$2 AND subject=$3`, item.IdentityID, item.Provider, item.Subject).Scan(&linkedUserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ProviderCredential{}, fmt.Errorf("provider credential identity mismatch")
		}
		return model.ProviderCredential{}, err
	}
	if linkedUserID != item.UserID {
		return model.ProviderCredential{}, fmt.Errorf("provider credential identity belongs to another user")
	}
	if item.ID == "" {
		item.ID = "provider-credential-" + item.Provider + "-" + item.UserID
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.Exec(`INSERT INTO provider_credentials(id,user_id,identity_id,provider,subject,encrypted_refresh_token,created_at,updated_at,last_refreshed_at)
VALUES($1,$2,$3,$4,$5,$6,$7,now(),$8)
ON CONFLICT(user_id,provider) DO UPDATE SET identity_id=EXCLUDED.identity_id,subject=EXCLUDED.subject,encrypted_refresh_token=EXCLUDED.encrypted_refresh_token,updated_at=now(),last_refreshed_at=EXCLUDED.last_refreshed_at`, item.ID, item.UserID, item.IdentityID, item.Provider, item.Subject, item.EncryptedRefreshToken, item.CreatedAt, nullTime(item.LastRefreshedAt))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return model.ProviderCredential{}, fmt.Errorf("%w: provider credential identity already belongs to another user", ErrConflict)
		}
		return model.ProviderCredential{}, err
	}
	return r.GetProviderCredential(item.UserID, item.Provider)
}

func (r *SQLRepository) DeleteProviderCredential(userID, provider string) error {
	if err := r.check(); err != nil {
		return err
	}
	result, err := r.db.Exec(`DELETE FROM provider_credentials WHERE user_id=$1 AND provider=$2`, strings.TrimSpace(userID), strings.ToLower(strings.TrimSpace(provider)))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *SQLRepository) GetMinecraftProfileByUser(userID string) (model.MinecraftProfile, error) {
	if err := r.check(); err != nil {
		return model.MinecraftProfile{}, err
	}
	var item model.MinecraftProfile
	err := r.db.QueryRow(`SELECT user_id, uuid, name, created_at, updated_at FROM minecraft_profiles WHERE user_id=$1`, strings.TrimSpace(userID)).Scan(&item.UserID, &item.UUID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MinecraftProfile{}, ErrNotFound
	}
	return item, err
}
func (r *SQLRepository) GetMinecraftProfileByUUID(uuid string) (model.MinecraftProfile, error) {
	if err := r.check(); err != nil {
		return model.MinecraftProfile{}, err
	}
	var item model.MinecraftProfile
	err := r.db.QueryRow(`SELECT user_id, uuid, name, created_at, updated_at FROM minecraft_profiles WHERE lower(uuid)=lower($1)`, strings.TrimSpace(uuid)).Scan(&item.UserID, &item.UUID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MinecraftProfile{}, ErrNotFound
	}
	return item, err
}
func (r *SQLRepository) GetMinecraftProfileByName(name string) (model.MinecraftProfile, error) {
	if err := r.check(); err != nil {
		return model.MinecraftProfile{}, err
	}
	var item model.MinecraftProfile
	err := r.db.QueryRow(`SELECT user_id, uuid, name, created_at, updated_at FROM minecraft_profiles WHERE lower(name)=lower($1)`, strings.TrimSpace(name)).Scan(&item.UserID, &item.UUID, &item.Name, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MinecraftProfile{}, ErrNotFound
	}
	return item, err
}
func (r *SQLRepository) SaveMinecraftProfile(item model.MinecraftProfile) (model.MinecraftProfile, error) {
	if err := r.check(); err != nil {
		return model.MinecraftProfile{}, err
	}
	item.UserID = strings.TrimSpace(item.UserID)
	item.UUID = strings.ToLower(strings.TrimSpace(item.UUID))
	item.Name = strings.TrimSpace(item.Name)
	if item.UserID == "" || item.UUID == "" || item.Name == "" {
		return model.MinecraftProfile{}, fmt.Errorf("minecraft profile fields are required")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	_, err := r.db.Exec(`INSERT INTO minecraft_profiles(user_id,uuid,name,created_at,updated_at) VALUES($1,$2,$3,$4,$5)
ON CONFLICT (user_id) DO UPDATE SET uuid=EXCLUDED.uuid,name=EXCLUDED.name,updated_at=EXCLUDED.updated_at`, item.UserID, item.UUID, item.Name, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		return model.MinecraftProfile{}, err
	}
	return r.GetMinecraftProfileByUser(item.UserID)
}
func (r *SQLRepository) SaveMinecraftSession(item model.MinecraftSession) (model.MinecraftSession, error) {
	if err := r.check(); err != nil {
		return model.MinecraftSession{}, err
	}
	if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.UserID) == "" || strings.TrimSpace(item.NeverSessionID) == "" || strings.TrimSpace(item.ProfileUUID) == "" || strings.TrimSpace(item.AccessTokenHash) == "" {
		return model.MinecraftSession{}, fmt.Errorf("minecraft session fields are required")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.LastSeenAt.IsZero() {
		item.LastSeenAt = now
	}
	if item.Status == "" {
		item.Status = "active"
	}
	_, err := r.db.Exec(`INSERT INTO minecraft_sessions(id,user_id,never_session_id,profile_uuid,client_token,access_token_hash,status,created_at,last_seen_at,expires_at,revoked_at,revoked_reason)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (id) DO UPDATE SET client_token=EXCLUDED.client_token,status=EXCLUDED.status,last_seen_at=EXCLUDED.last_seen_at,expires_at=EXCLUDED.expires_at,revoked_at=EXCLUDED.revoked_at,revoked_reason=EXCLUDED.revoked_reason`, item.ID, item.UserID, item.NeverSessionID, item.ProfileUUID, item.ClientToken, item.AccessTokenHash, item.Status, item.CreatedAt, item.LastSeenAt, item.ExpiresAt, nullTime(item.RevokedAt), item.RevokedReason)
	if err != nil {
		return model.MinecraftSession{}, err
	}
	return r.getMinecraftSessionByID(item.ID)
}
func (r *SQLRepository) getMinecraftSessionByID(id string) (model.MinecraftSession, error) {
	var item model.MinecraftSession
	var revoked sql.NullTime
	err := r.db.QueryRow(`SELECT id,user_id,never_session_id,profile_uuid,client_token,access_token_hash,status,created_at,last_seen_at,expires_at,revoked_at,revoked_reason FROM minecraft_sessions WHERE id=$1`, id).Scan(&item.ID, &item.UserID, &item.NeverSessionID, &item.ProfileUUID, &item.ClientToken, &item.AccessTokenHash, &item.Status, &item.CreatedAt, &item.LastSeenAt, &item.ExpiresAt, &revoked, &item.RevokedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MinecraftSession{}, ErrNotFound
	}
	if revoked.Valid {
		item.RevokedAt = revoked.Time
	}
	return item, err
}
func (r *SQLRepository) GetMinecraftSessionByTokenHash(hash string) (model.MinecraftSession, error) {
	if err := r.check(); err != nil {
		return model.MinecraftSession{}, err
	}
	var item model.MinecraftSession
	var revoked sql.NullTime
	err := r.db.QueryRow(`SELECT id,user_id,never_session_id,profile_uuid,client_token,access_token_hash,status,created_at,last_seen_at,expires_at,revoked_at,revoked_reason FROM minecraft_sessions WHERE access_token_hash=$1`, strings.TrimSpace(hash)).Scan(&item.ID, &item.UserID, &item.NeverSessionID, &item.ProfileUUID, &item.ClientToken, &item.AccessTokenHash, &item.Status, &item.CreatedAt, &item.LastSeenAt, &item.ExpiresAt, &revoked, &item.RevokedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MinecraftSession{}, ErrNotFound
	}
	if revoked.Valid {
		item.RevokedAt = revoked.Time
	}
	return item, err
}
func (r *SQLRepository) TouchMinecraftSession(id string) (model.MinecraftSession, error) {
	if err := r.check(); err != nil {
		return model.MinecraftSession{}, err
	}
	res, err := r.db.Exec(`UPDATE minecraft_sessions SET last_seen_at=now() WHERE id=$1 AND status='active'`, strings.TrimSpace(id))
	if err != nil {
		return model.MinecraftSession{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.MinecraftSession{}, ErrNotFound
	}
	return r.getMinecraftSessionByID(id)
}
func (r *SQLRepository) RevokeMinecraftSession(id, reason string) error {
	if err := r.check(); err != nil {
		return err
	}
	res, err := r.db.Exec(`UPDATE minecraft_sessions SET status='revoked',revoked_at=COALESCE(revoked_at,now()),revoked_reason=CASE WHEN revoked_reason='' THEN $2 ELSE revoked_reason END WHERE id=$1 AND status='active'`, strings.TrimSpace(id), strings.TrimSpace(reason))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}
func (r *SQLRepository) RevokeMinecraftSessionsByNeverSession(neverSessionID, reason string) int {
	if err := r.check(); err != nil {
		return 0
	}
	res, err := r.db.Exec(`UPDATE minecraft_sessions SET status='revoked',revoked_at=now(),revoked_reason=$2 WHERE never_session_id=$1 AND status='active'`, strings.TrimSpace(neverSessionID), strings.TrimSpace(reason))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}
func (r *SQLRepository) RevokeMinecraftSessionsByUser(userID, reason string) int {
	if err := r.check(); err != nil {
		return 0
	}
	res, err := r.db.Exec(`UPDATE minecraft_sessions SET status='revoked',revoked_at=now(),revoked_reason=$2 WHERE user_id=$1 AND status='active'`, strings.TrimSpace(userID), strings.TrimSpace(reason))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

func (r *SQLRepository) GetMinecraftSession(id string) (model.MinecraftSession, error) {
	if err := r.check(); err != nil {
		return model.MinecraftSession{}, err
	}
	return r.getMinecraftSessionByID(strings.TrimSpace(id))
}
func (r *SQLRepository) SaveMinecraftJoin(item model.MinecraftJoin) error {
	if err := r.check(); err != nil {
		return err
	}
	item.Username = strings.TrimSpace(item.Username)
	item.UsernameNormalized = strings.ToLower(item.Username)
	item.ProfileUUID = strings.ToLower(strings.TrimSpace(item.ProfileUUID))
	item.ServerID = strings.TrimSpace(item.ServerID)
	if item.Username == "" || item.UserID == "" || item.ProfileUUID == "" || item.MinecraftSessionID == "" || item.ServerID == "" {
		return fmt.Errorf("minecraft join fields are required")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.ExpiresAt.IsZero() {
		item.ExpiresAt = now.Add(2 * time.Minute)
	}
	_, err := r.db.Exec(`INSERT INTO minecraft_joins(username,username_normalized,profile_uuid,user_id,minecraft_session_id,server_id,ip,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (username_normalized,server_id) DO UPDATE SET username=EXCLUDED.username,profile_uuid=EXCLUDED.profile_uuid,user_id=EXCLUDED.user_id,minecraft_session_id=EXCLUDED.minecraft_session_id,ip=EXCLUDED.ip,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at`, item.Username, item.UsernameNormalized, item.ProfileUUID, item.UserID, item.MinecraftSessionID, item.ServerID, item.IP, item.CreatedAt, item.ExpiresAt)
	return err
}
func (r *SQLRepository) GetMinecraftJoin(username, serverID string) (model.MinecraftJoin, error) {
	if err := r.check(); err != nil {
		return model.MinecraftJoin{}, err
	}
	var item model.MinecraftJoin
	err := r.db.QueryRow(`SELECT username,username_normalized,profile_uuid,user_id,minecraft_session_id,server_id,ip,created_at,expires_at FROM minecraft_joins WHERE username_normalized=lower($1) AND server_id=$2 AND expires_at>now()`, strings.TrimSpace(username), strings.TrimSpace(serverID)).Scan(&item.Username, &item.UsernameNormalized, &item.ProfileUUID, &item.UserID, &item.MinecraftSessionID, &item.ServerID, &item.IP, &item.CreatedAt, &item.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.MinecraftJoin{}, ErrNotFound
	}
	return item, err
}
