package fileauthlive

// Живой провайдер аутентификации Gravit FileAuthSystem только на чтение. Источник
// аккаунтов остаётся авторитетным; Never сохраняет только собственную привязку
// идентичности и сессии. Sessions.json, внешние полномочия и внешние refresh-токены
// намеренно никогда не читаются и не импортируются.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gitflic.ru/skif4er/launcher/services/api/internal/fileauth"
	"gitflic.ru/skif4er/launcher/services/api/pkg/authconnector"
)

const maxLiveConfigBytes = 64 << 10

var liveUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)
var providerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

type LiveProvisioning struct {
	Mode        string `json:"mode,omitempty"`
	DefaultRole string `json:"defaultRole,omitempty"`
}

type LiveConfig struct {
	ID             string           `json:"id"`
	DisplayName    string           `json:"displayName,omitempty"`
	DatabasePath   string           `json:"databasePath"`
	PasswordFormat string           `json:"passwordFormat"`
	Provisioning   LiveProvisioning `json:"provisioning,omitempty"`
}

// LoadLiveConfigs отклоняет неоднозначную и повреждённую конфигурацию при запуске.
func LoadLiveConfigs(jsonValue, filePath string) ([]LiveConfig, error) {
	if strings.TrimSpace(jsonValue) != "" && strings.TrimSpace(filePath) != "" {
		return nil, errors.New("configure only one live FileAuth providers source")
	}
	raw := []byte(strings.TrimSpace(jsonValue))
	if strings.TrimSpace(filePath) != "" {
		data, err := os.ReadFile(strings.TrimSpace(filePath))
		if err != nil {
			return nil, fmt.Errorf("read live FileAuth provider configuration: %w", err)
		}
		raw = data
	}
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxLiveConfigBytes {
		return nil, errors.New("live FileAuth provider configuration exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var configs []LiveConfig
	if err := decoder.Decode(&configs); err != nil {
		return nil, fmt.Errorf("decode live FileAuth provider configuration: %w", err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing data in live FileAuth provider configuration")
	}
	if len(configs) > 16 {
		return nil, errors.New("Слишком много активных провайдеров FileAuth")
	}
	seen := map[string]bool{}
	for i := range configs {
		cfg, err := normalizeLiveConfig(configs[i])
		if err != nil {
			return nil, err
		}
		if seen[cfg.ID] {
			return nil, fmt.Errorf("Обнаружен дубликат: идентификатор действующего провайдера FileAuth %q", cfg.ID)
		}
		seen[cfg.ID] = true
		configs[i] = cfg
	}
	return configs, nil
}

func normalizeLiveConfig(in LiveConfig) (LiveConfig, error) {
	in.ID = strings.ToLower(strings.TrimSpace(in.ID))
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.PasswordFormat = strings.ToLower(strings.TrimSpace(in.PasswordFormat))
	in.DatabasePath = strings.TrimSpace(in.DatabasePath)
	in.Provisioning.Mode = strings.ToLower(strings.TrimSpace(in.Provisioning.Mode))
	in.Provisioning.DefaultRole = strings.TrimSpace(in.Provisioning.DefaultRole)
	if !providerIDPattern.MatchString(in.ID) || in.ID == "local" {
		return in, errors.New("Некорректное значение: идентификатор действующего провайдера FileAuth")
	}
	if !fileauth.SupportedFormat(in.PasswordFormat) {
		return in, fmt.Errorf("live FileAuth provider %q: unsupported explicit password format", in.ID)
	}
	if in.DatabasePath == "" || !filepath.IsAbs(in.DatabasePath) || !strings.EqualFold(filepath.Base(in.DatabasePath), "Database.json") {
		return in, fmt.Errorf("Требуется: «live FileAuth provider %q: absolute Database.json path»", in.ID)
	}
	if in.DisplayName == "" {
		in.DisplayName = in.ID
	}
	if len(in.DisplayName) > 120 {
		return in, errors.New("FileAuth displayName too long")
	}
	if in.Provisioning.Mode == "" {
		in.Provisioning.Mode = "explicit-only"
	}
	if in.Provisioning.Mode != "explicit-only" && in.Provisioning.Mode != "jit" {
		return in, errors.New("Некорректное значение: «live FileAuth provisioning mode»")
	}
	if in.Provisioning.DefaultRole == "" {
		in.Provisioning.DefaultRole = "player"
	}
	return in, nil
}

type liveSnapshot struct {
	digest [32]byte
	byName map[string]fileauth.Account
	byUUID map[string]fileauth.Account
}

type LiveConnector struct {
	verify   func(password, encoded string) bool
	cfg      LiveConfig
	mu       sync.RWMutex
	snapshot *liveSnapshot
}

// NewLiveConnector проверяет настоящий источник при регистрации, а не принимает
// номинально настроенного, но непригодного провайдера.
func NewLiveConnector(ctx context.Context, input LiveConfig, verifier func(password, encoded string) bool) (*LiveConnector, error) {
	if verifier == nil {
		return nil, errors.New("Требуется: «live FileAuth password verifier»")
	}
	cfg, err := normalizeLiveConfig(input)
	if err != nil {
		return nil, err
	}
	c := &LiveConnector{cfg: cfg, verify: verifier}
	if _, err := c.current(ctx); err != nil {
		return nil, fmt.Errorf("live FileAuth provider %q: %w", cfg.ID, err)
	}
	return c, nil
}

func (c *LiveConnector) Metadata() authconnector.Metadata {
	return authconnector.Metadata{ID: c.cfg.ID, DisplayName: c.cfg.DisplayName, Version: "1.0.0", Capabilities: []authconnector.Capability{
		authconnector.CapabilityPasswordAuth, authconnector.CapabilityUserLookup, authconnector.CapabilityProfile, authconnector.CapabilityEmail, authconnector.CapabilityMinecraftProfile,
	}}
}
func (c *LiveConnector) ProvisioningMode() string { return c.cfg.Provisioning.Mode }
func (c *LiveConnector) DefaultRole() string      { return c.cfg.Provisioning.DefaultRole }
func (c *LiveConnector) Close() error             { return nil }

func (c *LiveConnector) Health(ctx context.Context) error {
	_, err := c.current(ctx)
	if err != nil {
		return authconnector.WrapError(authconnector.ErrUnavailable, "live FileAuth source unavailable", err)
	}
	return nil
}

func (c *LiveConnector) current(ctx context.Context) (*liveSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Никогда не доверяйте кэшированному снимку, если файловая система стала
	// нечитаемой, исчезла или изменилась. Читайте и хешируйте при каждом запросе,
	// чтобы замена с теми же размером и mtime не обходила инвалидацию.
	before, err := os.Lstat(c.cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0007 != 0 {
		return nil, errors.New("Файл Database.json системы FileAuth: требуется «a regular file without world permissions»")
	}
	f, err := os.Open(c.cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) || opened.Size() > fileauth.MaxDatabaseBytes || !opened.Mode().IsRegular() {
		return nil, errors.New("Превышен допустимый размер: «FileAuth Database.json changed during open or»")
	}
	data, err := io.ReadAll(io.LimitReader(f, fileauth.MaxDatabaseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > fileauth.MaxDatabaseBytes {
		return nil, errors.New("FileAuth Database.json exceeds size limit")
	}
	after, err := os.Lstat(c.cfg.DatabasePath)
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || int64(len(data)) != opened.Size() {
		return nil, errors.New("FileAuth Database.json replaced or modified during read")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	c.mu.RLock()
	cached := c.snapshot
	c.mu.RUnlock()
	if cached != nil && cached.digest == digest {
		return cached, nil
	}
	accounts, err := fileauth.Parse(bytes.NewReader(data), c.cfg.PasswordFormat)
	if err != nil {
		return nil, err
	}
	next := &liveSnapshot{digest: digest, byName: make(map[string]fileauth.Account, len(accounts)), byUUID: make(map[string]fileauth.Account, len(accounts))}
	for _, a := range accounts {
		next.byName[strings.ToLower(a.Username)] = a
		next.byUUID[a.UUID] = a
	}
	c.mu.Lock()
	// Читатели всегда видят полный неизменяемый снимок.
	if c.snapshot != nil && c.snapshot.digest == digest {
		next = c.snapshot
	} else {
		c.snapshot = next
	}
	c.mu.Unlock()
	return next, nil
}

func liveIdentity(a fileauth.Account) authconnector.Identity {
	return authconnector.Identity{Subject: a.UUID, Username: a.Username, Email: a.Email, DisplayName: a.Username,
		Claims: map[string]any{"minecraftUuid": a.UUID}}
}

func (c *LiveConnector) AuthenticatePassword(ctx context.Context, req authconnector.PasswordRequest) (authconnector.Authentication, error) {
	if len(req.Secret) == 0 || len(req.Secret) > 4096 || !liveUsernamePattern.MatchString(req.Identifier) {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "Неверные учётные данные")
	}
	current, err := c.current(ctx)
	if err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrUnavailable, "live FileAuth source unavailable", err)
	}
	a, exists := current.byName[strings.ToLower(req.Identifier)]
	// Используйте явно настроенный и проверенный верификатор; никогда не
	// переходите на другой алгоритм или существующий аккаунт Never.
	if !exists || !c.verify(req.Secret, a.PasswordHash) {
		return authconnector.Authentication{}, authconnector.NewError(authconnector.ErrInvalidCredentials, "Неверные учётные данные")
	}
	// Проверка пароля, особенно PHPass/Argon2id, может быть дорогой. Источник могли
	// отозвать или заменить во время верификации. Не авторизуйте устаревший снимок,
	// даже если при чтении он был действительным.
	latest, checkErr := c.current(ctx)
	if checkErr != nil || latest.digest != current.digest {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrUnavailable, "live FileAuth source changed during verification", checkErr)
	}
	if err := ctx.Err(); err != nil {
		return authconnector.Authentication{}, authconnector.WrapError(authconnector.ErrUnavailable, "FileAuth login canceled", err)
	}
	return authconnector.Authentication{Identity: liveIdentity(a), AuthMethods: []string{"password"}}, nil
}

func (c *LiveConnector) ResolveIdentity(ctx context.Context, req authconnector.ResolveRequest) (authconnector.Identity, error) {
	current, err := c.current(ctx)
	if err != nil {
		return authconnector.Identity{}, authconnector.WrapError(authconnector.ErrUnavailable, "live FileAuth source unavailable", err)
	}
	a, exists := current.byUUID[strings.ToLower(req.Subject)]
	if !exists {
		return authconnector.Identity{}, authconnector.NewError(authconnector.ErrIdentityNotFound, "FileAuth identity not found")
	}
	return liveIdentity(a), nil
}

func (c *LiveConnector) ResolveProfile(ctx context.Context, req authconnector.ResolveRequest) (authconnector.Profile, error) {
	id, err := c.ResolveIdentity(ctx, req)
	if err != nil {
		return authconnector.Profile{}, err
	}
	return authconnector.Profile{Subject: id.Subject, DisplayName: id.DisplayName, MinecraftUUID: id.Subject}, nil
}
