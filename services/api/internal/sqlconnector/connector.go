package sqlconnector

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"gitflic.ru/skif4er/neverlauncher/services/api/pkg/authconnector"
)

type Connector struct {
	cfg            RuntimeConfig
	db             *sql.DB
	stmtByID       *sql.Stmt
	stmtBySub      *sql.Stmt
	identifierArgs int
	closeOnce      sync.Once
}

type rowIdentity struct {
	subject       string
	username      string
	email         string
	passwordHash  string
	status        string
	displayName   string
	groupsRaw     string
	rolesRaw      string
	minecraftUUID string
}

func New(ctx context.Context, input Config) (*Connector, error) {
	cfg, err := Normalize(input)
	if err != nil {
		return nil, err
	}
	db, err := openDatabase(cfg)
	if err != nil {
		return nil, fmt.Errorf("SQL connector %q open database: %w", cfg.ID, err)
	}
	connector, err := newWithDB(ctx, cfg, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeoutDuration)
	defer cancel()
	if err := connector.Health(pingCtx); err != nil {
		_ = connector.Close()
		return nil, fmt.Errorf("SQL connector %q health check: %w", cfg.ID, err)
	}
	return connector, nil
}

func newWithDB(ctx context.Context, cfg RuntimeConfig, db *sql.DB) (*Connector, error) {
	if db == nil {
		return nil, errors.New("SQL database handle is nil")
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetimeDuration)
	queryByID, queryBySub, identifierArgs, err := buildQueries(cfg)
	if err != nil {
		return nil, err
	}
	prepareCtx, cancel := context.WithTimeout(ctx, cfg.QueryTimeoutDuration)
	defer cancel()
	stmtByID, err := db.PrepareContext(prepareCtx, queryByID)
	if err != nil {
		return nil, fmt.Errorf("SQL connector %q prepare identifier lookup: %w", cfg.ID, err)
	}
	stmtBySub, err := db.PrepareContext(prepareCtx, queryBySub)
	if err != nil {
		_ = stmtByID.Close()
		return nil, fmt.Errorf("SQL connector %q prepare subject lookup: %w", cfg.ID, err)
	}
	return &Connector{cfg: cfg, db: db, stmtByID: stmtByID, stmtBySub: stmtBySub, identifierArgs: identifierArgs}, nil
}

func (c *Connector) Metadata() authconnector.Metadata {
	capabilities := []authconnector.Capability{authconnector.CapabilityPasswordAuth, authconnector.CapabilityUserLookup}
	if c.cfg.Columns.Email != "" {
		capabilities = append(capabilities, authconnector.CapabilityEmail)
	}
	if c.cfg.Columns.DisplayName != "" || c.cfg.Columns.MinecraftUUID != "" {
		capabilities = append(capabilities, authconnector.CapabilityProfile)
	}
	if c.cfg.Columns.Groups != "" {
		capabilities = append(capabilities, authconnector.CapabilityGroups)
	}
	if c.cfg.Columns.Roles != "" {
		capabilities = append(capabilities, authconnector.CapabilityRoles)
	}
	if c.cfg.Columns.MinecraftUUID != "" {
		capabilities = append(capabilities, authconnector.CapabilityMinecraftProfile)
	}
	return authconnector.Metadata{ID: c.cfg.ID, DisplayName: c.cfg.DisplayName, Version: defaultProviderVersion, Capabilities: capabilities}
}

func (c *Connector) Health(ctx context.Context) error {
	if c == nil || c.db == nil {
		return errors.New("SQL connector database is unavailable")
	}
	healthCtx, cancel := context.WithTimeout(ctx, c.cfg.ConnectTimeoutDuration)
	defer cancel()
	if err := c.db.PingContext(healthCtx); err != nil {
		return authconnector.WrapError(authconnector.ErrUnavailable, "SQL provider database is unavailable", err)
	}
	return nil
}

func (c *Connector) AuthenticatePassword(ctx context.Context, request authconnector.PasswordRequest) (authconnector.Authentication, error) {
	identifier := strings.TrimSpace(request.Identifier)
	if identifier == "" || request.Secret == "" || len(identifier) > 512 || len(request.Secret) > 4096 {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	args := make([]any, c.identifierArgs)
	for i := range args {
		args[i] = identifier
	}
	identity, err := c.lookup(ctx, c.stmtByID, args...)
	if err != nil {
		if authconnector.CodeOf(err) == authconnector.ErrInvalidCredentials {
			consumePasswordWork(request.Secret, c.cfg.Password)
		}
		return authconnector.Authentication{}, err
	}
	active, err := c.isActive(identity.status)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrMisconfigured, "SQL identity status is invalid", err)
	}
	if !active {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "SQL identity is disabled")
	}
	valid, err := verifyPassword(request.Secret, identity.passwordHash, c.cfg.Password)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrMisconfigured, "SQL password hash cannot be verified", err)
	}
	if !valid {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	mapped, err := c.mapIdentity(identity)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrMisconfigured, "SQL identity mapping failed", err)
	}
	return authconnector.Authentication{Identity: mapped, AuthMethods: []string{"password"}}, nil
}

func (c *Connector) ResolveIdentity(ctx context.Context, request authconnector.ResolveRequest) (authconnector.Identity, error) {
	subject := strings.TrimSpace(request.Subject)
	if subject == "" {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "SQL identity subject is required")
	}
	row, err := c.lookup(ctx, c.stmtBySub, subject)
	if err != nil {
		if authconnector.CodeOf(err) == authconnector.ErrInvalidCredentials {
			return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "SQL identity not found")
		}
		return authconnector.Identity{}, err
	}
	active, err := c.isActive(row.status)
	if err != nil {
		return authconnector.Identity{}, authconnector.WrapError(authconnector.ErrMisconfigured, "SQL identity status is invalid", err)
	}
	if !active {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityDisabled, "SQL identity is disabled")
	}
	return c.mapIdentity(row)
}

func (c *Connector) ResolveProfile(ctx context.Context, request authconnector.ResolveRequest) (authconnector.Profile, error) {
	identity, err := c.ResolveIdentity(ctx, request)
	if err != nil {
		return authconnector.Profile{}, err
	}
	minecraftUUID, _ := identity.Claims["minecraftUuid"].(string)
	return authconnector.Profile{Subject: identity.Subject, DisplayName: identity.DisplayName, MinecraftUUID: minecraftUUID}, nil
}

func (c *Connector) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	var firstErr error
	c.closeOnce.Do(func() {
		if c.stmtByID != nil {
			if err := c.stmtByID.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.stmtBySub != nil {
			if err := c.stmtBySub.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := c.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}

func (c *Connector) ProvisioningMode() string { return c.cfg.Provisioning.Mode }
func (c *Connector) DefaultRole() string      { return c.cfg.Provisioning.DefaultRole }

func (c *Connector) lookup(parent context.Context, stmt *sql.Stmt, args ...any) (rowIdentity, error) {
	queryCtx, cancel := context.WithTimeout(parent, c.cfg.QueryTimeoutDuration)
	defer cancel()
	tx, err := c.db.BeginTx(queryCtx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return rowIdentity{}, authconnector.WrapError(authconnector.ErrUnavailable, "SQL provider read-only transaction failed", err)
	}
	defer tx.Rollback()
	if stmt == nil {
		return rowIdentity{}, authconnector.NewError(authconnector.ErrMisconfigured, "SQL provider statement is unavailable")
	}
	rows, err := tx.StmtContext(queryCtx, stmt).QueryContext(queryCtx, args...)
	if err != nil {
		return rowIdentity{}, authconnector.WrapError(authconnector.ErrUnavailable, "SQL provider query failed", err)
	}
	defer rows.Close()
	var found []rowIdentity
	for rows.Next() {
		var values [9]sql.NullString
		if err := rows.Scan(&values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7], &values[8]); err != nil {
			return rowIdentity{}, authconnector.WrapError(authconnector.ErrMisconfigured, "SQL provider row cannot be scanned", err)
		}
		found = append(found, rowIdentity{subject: values[0].String, username: values[1].String, email: values[2].String, passwordHash: values[3].String, status: values[4].String, displayName: values[5].String, groupsRaw: values[6].String, rolesRaw: values[7].String, minecraftUUID: values[8].String})
		if len(found) > 1 {
			return rowIdentity{}, authconnector.NewError(authconnector.ErrConflict, "SQL identifier resolves to multiple identities")
		}
	}
	if err := rows.Err(); err != nil {
		return rowIdentity{}, authconnector.WrapError(authconnector.ErrUnavailable, "SQL provider query failed", err)
	}
	if len(found) == 0 {
		// Deliberately use the same public error as a wrong password to avoid account enumeration.
		return rowIdentity{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "invalid credentials")
	}
	if strings.TrimSpace(found[0].subject) == "" || strings.TrimSpace(found[0].passwordHash) == "" {
		return rowIdentity{}, authconnector.NewError(authconnector.ErrMisconfigured, "SQL identity has empty subject or password hash")
	}
	if err := tx.Commit(); err != nil {
		return rowIdentity{}, authconnector.WrapError(authconnector.ErrUnavailable, "SQL provider read-only transaction commit failed", err)
	}
	return found[0], nil
}

func (c *Connector) mapIdentity(row rowIdentity) (authconnector.Identity, error) {
	groups, err := parseStringList(row.groupsRaw)
	if err != nil {
		return authconnector.Identity{}, fmt.Errorf("groups: %w", err)
	}
	roles, err := parseStringList(row.rolesRaw)
	if err != nil {
		return authconnector.Identity{}, fmt.Errorf("roles: %w", err)
	}
	claims := map[string]any{"sqlDriver": c.cfg.Driver}
	if row.minecraftUUID != "" {
		claims["minecraftUuid"] = strings.TrimSpace(row.minecraftUUID)
	}
	if len(groups) > 0 {
		claims["groups"] = append([]string(nil), groups...)
	}
	if len(roles) > 0 {
		claims["roles"] = append([]string(nil), roles...)
	}
	displayName := strings.TrimSpace(row.displayName)
	if displayName == "" {
		displayName = firstNonEmpty(strings.TrimSpace(row.username), strings.TrimSpace(row.email), strings.TrimSpace(row.subject))
	}
	return authconnector.Identity{Subject: strings.TrimSpace(row.subject), Email: strings.TrimSpace(row.email), Username: strings.TrimSpace(row.username), DisplayName: displayName, Groups: groups, Roles: roles, Claims: claims}, nil
}

func (c *Connector) isActive(status string) (bool, error) {
	if c.cfg.Columns.Status == "" {
		return true, nil
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return false, nil
	}
	for _, allowed := range c.cfg.ActiveStatusValues {
		if status == allowed {
			return true, nil
		}
	}
	return false, nil
}

func buildQueries(cfg RuntimeConfig) (string, string, int, error) {
	quote := func(identifier string) string {
		if identifier == "" {
			return ""
		}
		marker := `"`
		if cfg.Driver == "mysql" || cfg.Driver == "mariadb" {
			marker = "`"
		}
		parts := strings.Split(identifier, ".")
		for i := range parts {
			parts[i] = marker + parts[i] + marker
		}
		return strings.Join(parts, ".")
	}
	literal := func(column string) string {
		if column == "" {
			return "''"
		}
		return "CAST(" + quote(column) + " AS CHAR)"
	}
	if cfg.Driver == "postgresql" {
		literal = func(column string) string {
			if column == "" {
				return "''"
			}
			return "CAST(" + quote(column) + " AS TEXT)"
		}
	}
	selectList := strings.Join([]string{
		literal(cfg.Columns.ID), literal(cfg.Columns.Username), literal(cfg.Columns.Email), literal(cfg.Columns.Password), literal(cfg.Columns.Status), literal(cfg.Columns.DisplayName), literal(cfg.Columns.Groups), literal(cfg.Columns.Roles), literal(cfg.Columns.MinecraftUUID),
	}, ", ")
	placeholder := "?"
	if cfg.Driver == "postgresql" {
		placeholder = "$1"
	}
	loginConditions := make([]string, 0, 2)
	if cfg.Columns.Username != "" {
		loginConditions = append(loginConditions, "LOWER("+literal(cfg.Columns.Username)+") = LOWER("+placeholder+")")
	}
	if cfg.Columns.Email != "" {
		loginConditions = append(loginConditions, "LOWER("+literal(cfg.Columns.Email)+") = LOWER("+placeholder+")")
	}
	if len(loginConditions) == 0 {
		return "", "", 0, errors.New("SQL connector has no login identifier columns")
	}
	byIdentifier := "SELECT " + selectList + " FROM " + quote(cfg.Table) + " WHERE (" + strings.Join(loginConditions, " OR ") + ") LIMIT 2"
	bySubject := "SELECT " + selectList + " FROM " + quote(cfg.Table) + " WHERE " + literal(cfg.Columns.ID) + " = " + placeholder + " LIMIT 2"
	identifierArgs := 1
	if cfg.Driver != "postgresql" {
		identifierArgs = len(loginConditions)
	}
	return byIdentifier, bySubject, identifierArgs, nil
}

func parseStringList(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "[") {
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, err
		}
		return normalizeList(values), nil
	}
	if strings.HasPrefix(raw, "{") {
		values, err := parsePostgresArray(raw)
		if err != nil {
			return nil, err
		}
		return normalizeList(values), nil
	}
	return normalizeList(strings.Split(raw, ",")), nil
}

// parsePostgresArray handles the one-dimensional text-array representation returned
// by CAST(text[] AS TEXT). It deliberately rejects nested arrays and malformed quoted
// elements instead of silently producing wrong role/group names.
func parsePostgresArray(raw string) ([]string, error) {
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return nil, errors.New("invalid PostgreSQL array")
	}
	body := raw[1 : len(raw)-1]
	if body == "" {
		return nil, nil
	}
	values := make([]string, 0, 4)
	var current strings.Builder
	inQuotes := false
	escaped := false
	quotedElement := false
	flush := func() {
		value := current.String()
		if !quotedElement && strings.EqualFold(strings.TrimSpace(value), "NULL") {
			value = ""
		}
		values = append(values, value)
		current.Reset()
		quotedElement = false
	}
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			quotedElement = true
			continue
		}
		if ch == ',' && !inQuotes {
			flush()
			continue
		}
		if (ch == '{' || ch == '}') && !inQuotes {
			return nil, errors.New("nested PostgreSQL arrays are not supported")
		}
		current.WriteByte(ch)
	}
	if escaped || inQuotes {
		return nil, errors.New("malformed PostgreSQL array quoting")
	}
	flush()
	return values, nil
}

func normalizeList(input []string) []string {
	output := make([]string, 0, len(input))
	seen := map[string]struct{}{}
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		output = append(output, item)
	}
	return output
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var _ authconnector.PasswordAuthenticator = (*Connector)(nil)
var _ authconnector.IdentityResolver = (*Connector)(nil)
var _ authconnector.ProfileResolver = (*Connector)(nil)
var _ authconnector.Connector = (*Connector)(nil)
