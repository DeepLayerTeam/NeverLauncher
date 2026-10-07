package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type ActorKind string

const (
	ActorUser ActorKind = "user"
)

type ScopeKind string

const (
	ScopeGlobal  ScopeKind = "global"
	ScopeProject ScopeKind = "project"
)

type Actor struct {
	Kind ActorKind
	ID   string
}

type Scope struct {
	Kind      ScopeKind
	ProjectID string
}

type Resource struct {
	Kind      string
	ID        string
	ProjectID string
}

type Decision struct {
	Allowed        bool   `json:"allowed"`
	ReasonCode     string `json:"reasonCode"`
	EffectiveRole  string `json:"effectiveRole,omitempty"`
	Scope          string `json:"scope"`
	ProjectID      string `json:"projectId,omitempty"`
	PolicyRevision string `json:"policyRevision"`
}

type Repository interface {
	GetUser(id string) (model.User, error)
	ListRoles() []model.Role
}

type Service struct {
	repo Repository
}

func New(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Authorize(_ context.Context, actor Actor, action string, scope Scope, resource Resource) Decision {
	action = strings.TrimSpace(action)
	projectID := strings.TrimSpace(scope.ProjectID)
	resourceProjectID := strings.TrimSpace(resource.ProjectID)
	decision := Decision{Allowed: false, ReasonCode: "deny", Scope: string(scope.Kind), ProjectID: projectID}
	if scope.Kind == ScopeProject {
		if projectID == "" {
			decision.ReasonCode = "project-scope-required"
			return decision
		}
		if resourceProjectID != "" && resourceProjectID != projectID {
			decision.ReasonCode = "resource-scope-mismatch"
			return decision
		}
	} else if scope.Kind != ScopeGlobal {
		decision.ReasonCode = "invalid-scope"
		return decision
	}
	if s == nil || s.repo == nil || actor.Kind != ActorUser || strings.TrimSpace(actor.ID) == "" || action == "" {
		decision.ReasonCode = "invalid-request"
		return decision
	}

	user, err := s.repo.GetUser(strings.TrimSpace(actor.ID))
	if err != nil {
		decision.ReasonCode = "actor-not-found"
		return decision
	}
	if !strings.EqualFold(strings.TrimSpace(user.Status), "active") {
		decision.ReasonCode = "actor-inactive"
		return decision
	}

	roles := roleIndex(s.repo.ListRoles())
	decision.PolicyRevision = policyRevision(user, roles)

	if roleAllows(roles[user.RoleID], action) {
		decision.Allowed = true
		decision.ReasonCode = "global-role"
		decision.EffectiveRole = user.RoleID
		return decision
	}

	if scope.Kind != ScopeProject || projectID == "" {
		decision.ReasonCode = "global-role-required"
		return decision
	}
	if !IsProjectAction(action) {
		decision.ReasonCode = "global-action-required"
		return decision
	}

	// Wildcard memberships from historical users.project_roles are intentionally
	// ignored. Instance-wide access must come from the user's global RoleID.
	roleID := strings.TrimSpace(user.ProjectRoles[projectID])
	if roleID == "" {
		decision.ReasonCode = "project-membership-required"
		return decision
	}
	if roleAllows(roles[roleID], action) {
		decision.Allowed = true
		decision.ReasonCode = "project-role"
		decision.EffectiveRole = roleID
		return decision
	}
	decision.ReasonCode = "project-role-insufficient"
	decision.EffectiveRole = roleID
	return decision
}

// IsProjectAction is the hard boundary between instance-wide privileges and
// project-scoped privileges. Adding a global administrative permission here
// is a security-sensitive change and is covered by the 0.21.1 frozen gate.
func IsProjectAction(action string) bool {
	switch strings.TrimSpace(action) {
	case "project:read", "project:write",
		"release:prepare", "release:publish", "file:write",
		"audit:read", "diagnostics:read",
		"serverbridge:control", "serverbridge:console",
		"profile:download", "profile:launch":
		return true
	default:
		return false
	}
}

func roleIndex(roles []model.Role) map[string]model.Role {
	result := make(map[string]model.Role, len(roles))
	for _, role := range roles {
		role.ID = strings.TrimSpace(role.ID)
		if role.ID != "" {
			result[role.ID] = role
		}
	}
	return result
}

func roleAllows(role model.Role, action string) bool {
	for _, permission := range role.Permissions {
		permission = strings.TrimSpace(permission)
		if permission == "*" || permission == action {
			return true
		}
	}
	return false
}

func policyRevision(user model.User, roles map[string]model.Role) string {
	h := sha256.New()
	_, _ = h.Write([]byte(strings.TrimSpace(user.ID)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(user.RoleID)))
	if role, ok := roles[user.RoleID]; ok {
		for _, p := range role.Permissions {
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(strings.TrimSpace(p)))
		}
	}
	keys := make([]string, 0, len(user.ProjectRoles))
	for projectID := range user.ProjectRoles {
		if projectID != "*" {
			keys = append(keys, projectID)
		}
	}
	// Small insertion sort keeps this package dependency-free and deterministic.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, projectID := range keys {
		roleID := user.ProjectRoles[projectID]
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(projectID))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(roleID))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
