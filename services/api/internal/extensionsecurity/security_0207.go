package extensionsecurity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const KeyVersion = "v1"

var catalog0207 = map[string]string{
	"project:read":      "projects.read",
	"project:write":     "projects.write",
	"release:read":      "releases.read",
	"release:prepare":   "releases.write",
	"release:publish":   "releases.publish",
	"storage:read":      "storage.read",
	"storage:write":     "storage.write",
	"telemetry:read":    "telemetry.read",
	"telemetry:write":   "telemetry.write",
	"ui:contribute":     "ui.contribute",
	"http:outbound":     "http.outbound",
	"events:subscribe":  "events.subscribe",
	"events:sync":       "events.sync",
	"secrets:read":      "secrets.read",
	"serverbridge:read": "serverbridge.read",
	"audit:read":        "audit.read",
}

type Manager struct {
	repo repository.Repository
	key  []byte
}

func ParseKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("extension secrets key must be 32-byte hex or base64")
}
func New(repo repository.Repository, key []byte) (*Manager, error) {
	if repo == nil {
		return nil, errors.New("extension security repository is required")
	}
	if len(key) != 0 && len(key) != 32 {
		return nil, errors.New("extension secrets key must be 32 bytes")
	}
	return &Manager{repo: repo, key: append([]byte(nil), key...)}, nil
}
func Catalog() map[string]string {
	out := map[string]string{}
	for k, v := range catalog0207 {
		out[k] = v
	}
	return out
}
func IsKnownPermission(p string) bool {
	_, ok := catalog0207[strings.ToLower(strings.TrimSpace(p))]
	return ok
}

func setOf(items []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, v := range items {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			m[v] = struct{}{}
		}
	}
	return m
}
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func diff(a, b map[string]struct{}) []string {
	out := map[string]struct{}{}
	for k := range a {
		if _, ok := b[k]; !ok {
			out[k] = struct{}{}
		}
	}
	return sortedKeys(out)
}
func intersect(a, b map[string]struct{}) []string {
	out := map[string]struct{}{}
	for k := range a {
		if _, ok := b[k]; ok {
			out[k] = struct{}{}
		}
	}
	return sortedKeys(out)
}

func (m *Manager) Requested(ctx context.Context, extensionID, version string) ([]string, error) {
	items, err := m.repo.ListExtensionPermissions(ctx, extensionID, version)
	if err != nil {
		return nil, err
	}
	sort.Strings(items)
	return items, nil
}
func (m *Manager) Grants(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionPermissionGrant, error) {
	return m.repo.ListExtensionPermissionGrants(ctx, extensionID, scope, scopeID)
}
func applicableGrants(grants []model.ExtensionPermissionGrant, installScope, installScopeID, projectID string) map[string]struct{} {
	out := map[string]struct{}{}
	projectID = strings.TrimSpace(projectID)
	for _, g := range grants {
		if g.Scope == "global" {
			out[g.Permission] = struct{}{}
			continue
		}
		if installScope == "project" && g.ScopeID == installScopeID {
			out[g.Permission] = struct{}{}
			continue
		}
		if installScope == "global" && projectID != "" && g.ScopeID == projectID {
			out[g.Permission] = struct{}{}
		}
	}
	return out
}
func (m *Manager) Allowed(ctx context.Context, extensionID, version, installScope, installScopeID, permission, projectID string) (bool, error) {
	requested, err := m.Requested(ctx, extensionID, version)
	if err != nil {
		return false, err
	}
	if _, ok := setOf(requested)[strings.ToLower(strings.TrimSpace(permission))]; !ok {
		return false, nil
	}
	grants, err := m.repo.ListExtensionPermissionGrants(ctx, extensionID, "", "")
	if err != nil {
		return false, err
	}
	_, ok := applicableGrants(grants, installScope, installScopeID, projectID)[strings.ToLower(strings.TrimSpace(permission))]
	return ok, nil
}
func (m *Manager) Effective(ctx context.Context, extensionID, version, scope, scopeID, projectID string) ([]string, error) {
	req, err := m.Requested(ctx, extensionID, version)
	if err != nil {
		return nil, err
	}
	grants, err := m.repo.ListExtensionPermissionGrants(ctx, extensionID, "", "")
	if err != nil {
		return nil, err
	}
	return intersect(setOf(req), applicableGrants(grants, scope, scopeID, projectID)), nil
}
func (m *Manager) PermissionDiff(ctx context.Context, extensionID, fromVersion, toVersion, scope, scopeID string) (model.ExtensionPermissionDiff, error) {
	to, err := m.Requested(ctx, extensionID, toVersion)
	if err != nil {
		return model.ExtensionPermissionDiff{}, err
	}
	from := []string{}
	if strings.TrimSpace(fromVersion) != "" {
		from, err = m.Requested(ctx, extensionID, fromVersion)
		if err != nil {
			return model.ExtensionPermissionDiff{}, err
		}
	}
	grants, err := m.repo.ListExtensionPermissionGrants(ctx, extensionID, "", "")
	if err != nil {
		return model.ExtensionPermissionDiff{}, err
	}
	grantSet := applicableGrants(grants, scope, scopeID, scopeID)
	toSet, fromSet := setOf(to), setOf(from)
	added := diff(toSet, fromSet)
	addedSet := setOf(added)
	return model.ExtensionPermissionDiff{ExtensionID: extensionID, FromVersion: fromVersion, ToVersion: toVersion, Scope: scope, ScopeID: scopeID, Requested: sortedKeys(toSet), Granted: sortedKeys(grantSet), Effective: intersect(toSet, grantSet), Missing: diff(toSet, grantSet), Added: added, Removed: diff(fromSet, toSet), AddedNotGranted: diff(addedSet, grantSet)}, nil
}
func (m *Manager) Grant(ctx context.Context, extensionID, version, scope, scopeID, permission, actor, reason string) (model.ExtensionPermissionGrant, error) {
	var err error
	scope, scopeID, err = normalizeScope0207(scope, scopeID)
	if err != nil {
		return model.ExtensionPermissionGrant{}, err
	}
	if scope == "project" {
		if _, err := m.repo.GetProject(scopeID); err != nil {
			return model.ExtensionPermissionGrant{}, err
		}
	}
	permission = strings.ToLower(strings.TrimSpace(permission))
	if !IsKnownPermission(permission) {
		return model.ExtensionPermissionGrant{}, fmt.Errorf("unknown permission %q", permission)
	}
	requested, err := m.Requested(ctx, extensionID, version)
	if err != nil {
		return model.ExtensionPermissionGrant{}, err
	}
	if _, ok := setOf(requested)[permission]; !ok {
		return model.ExtensionPermissionGrant{}, fmt.Errorf("permission %s is not requested by %s@%s", permission, extensionID, version)
	}
	return m.repo.GrantExtensionPermission(ctx, model.ExtensionPermissionGrant{ExtensionID: extensionID, Scope: scope, ScopeID: scopeID, Permission: permission, GrantedBy: actor, Reason: reason})
}
func (m *Manager) Revoke(ctx context.Context, extensionID, scope, scopeID, permission string) error {
	return m.repo.RevokeExtensionPermission(ctx, extensionID, scope, scopeID, permission)
}

func normalizeScope0207(scope, scopeID string) (string, string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	scopeID = strings.TrimSpace(scopeID)
	if scope == "" {
		scope = "global"
	}
	if scope != "global" && scope != "project" {
		return "", "", errors.New("scope must be global or project")
	}
	if scope == "global" {
		scopeID = ""
	} else if scopeID == "" {
		return "", "", errors.New("project scope requires scopeId")
	}
	return scope, scopeID, nil
}

func secretAAD(extensionID, scope, scopeID, name string) []byte {
	return []byte(strings.Join([]string{"neverlauncher-extension-secret-v1", extensionID, scope, scopeID, name}, "\x00"))
}
func (m *Manager) SetSecret(ctx context.Context, extensionID, scope, scopeID, name string, plaintext []byte, actor string) (model.ExtensionSecretMetadata, error) {
	var err error
	scope, scopeID, err = normalizeScope0207(scope, scopeID)
	if err != nil {
		return model.ExtensionSecretMetadata{}, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	name = strings.TrimSpace(name)
	if scope == "project" {
		if _, err := m.repo.GetProject(scopeID); err != nil {
			return model.ExtensionSecretMetadata{}, err
		}
	}
	if len(m.key) != 32 {
		return model.ExtensionSecretMetadata{}, errors.New("extension secrets broker is not configured")
	}
	if len(plaintext) == 0 || len(plaintext) > 1<<20 {
		return model.ExtensionSecretMetadata{}, errors.New("secret value must contain 1..1048576 bytes")
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return model.ExtensionSecretMetadata{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return model.ExtensionSecretMetadata{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return model.ExtensionSecretMetadata{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, secretAAD(extensionID, scope, scopeID, name))
	s, err := m.repo.PutExtensionSecret(ctx, model.ExtensionSecret{ExtensionID: extensionID, Scope: scope, ScopeID: scopeID, Name: name, Ciphertext: ciphertext, Nonce: nonce, KeyVersion: KeyVersion, UpdatedBy: actor})
	if err != nil {
		return model.ExtensionSecretMetadata{}, err
	}
	return model.ExtensionSecretMetadata{ExtensionID: s.ExtensionID, Scope: s.Scope, ScopeID: s.ScopeID, Name: s.Name, KeyVersion: s.KeyVersion, UpdatedBy: s.UpdatedBy, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}, nil
}
func (m *Manager) GetSecret(ctx context.Context, extensionID, scope, scopeID, name string) ([]byte, error) {
	var err error
	scope, scopeID, err = normalizeScope0207(scope, scopeID)
	if err != nil {
		return nil, err
	}
	extensionID = strings.ToLower(strings.TrimSpace(extensionID))
	name = strings.TrimSpace(name)
	if len(m.key) != 32 {
		return nil, errors.New("extension secrets broker is not configured")
	}
	s, err := m.repo.GetExtensionSecret(ctx, extensionID, scope, scopeID, name)
	if err != nil {
		return nil, err
	}
	if s.KeyVersion != KeyVersion {
		return nil, fmt.Errorf("unsupported extension secret key version %q", s.KeyVersion)
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, s.Nonce, s.Ciphertext, secretAAD(s.ExtensionID, s.Scope, s.ScopeID, s.Name))
	if err != nil {
		return nil, errors.New("extension secret authentication failed")
	}
	return plain, nil
}
func (m *Manager) ListSecrets(ctx context.Context, extensionID, scope, scopeID string) ([]model.ExtensionSecretMetadata, error) {
	return m.repo.ListExtensionSecrets(ctx, extensionID, scope, scopeID)
}
func (m *Manager) DeleteSecret(ctx context.Context, extensionID, scope, scopeID, name string) error {
	return m.repo.DeleteExtensionSecret(ctx, extensionID, scope, scopeID, name)
}

func FingerprintSecretValue(v []byte) string {
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:8])
}
