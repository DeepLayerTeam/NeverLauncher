package authorization

import (
	"context"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

type fakeRepo struct {
	user  model.User
	roles []model.Role
}

func (f fakeRepo) GetUser(id string) (model.User, error) { return f.user, nil }
func (f fakeRepo) ListRoles() []model.Role               { return f.roles }

func TestProjectRoleNeverBecomesGlobal(t *testing.T) {
	svc := New(fakeRepo{
		user: model.User{ID: "u1", RoleID: "player", Status: "active", ProjectRoles: map[string]string{"p1": "admin"}},
		roles: []model.Role{
			{ID: "player", Permissions: []string{"launcher:login"}},
			{ID: "admin", Permissions: []string{"project:read", "project:write"}},
		},
	})
	actor := Actor{Kind: ActorUser, ID: "u1"}
	if got := svc.Authorize(context.Background(), actor, "project:write", Scope{Kind: ScopeGlobal}, Resource{Kind: "project"}); got.Allowed {
		t.Fatalf("project role unexpectedly granted global permission: %+v", got)
	}
	if got := svc.Authorize(context.Background(), actor, "project:write", Scope{Kind: ScopeProject, ProjectID: "p1"}, Resource{Kind: "project", ID: "p1", ProjectID: "p1"}); !got.Allowed {
		t.Fatalf("project role should grant p1 permission: %+v", got)
	}
	if got := svc.Authorize(context.Background(), actor, "project:write", Scope{Kind: ScopeProject, ProjectID: "p2"}, Resource{Kind: "project", ID: "p2", ProjectID: "p2"}); got.Allowed {
		t.Fatalf("project role leaked across projects: %+v", got)
	}
}

func TestWildcardMembershipDoesNotGrantInstanceAccess(t *testing.T) {
	svc := New(fakeRepo{
		user:  model.User{ID: "u1", RoleID: "player", Status: "active", ProjectRoles: map[string]string{"*": "owner"}},
		roles: []model.Role{{ID: "player", Permissions: []string{"launcher:login"}}, {ID: "owner", Permissions: []string{"*"}}},
	})
	got := svc.Authorize(context.Background(), Actor{Kind: ActorUser, ID: "u1"}, "project:write", Scope{Kind: ScopeProject, ProjectID: "p1"}, Resource{Kind: "project", ID: "p1", ProjectID: "p1"})
	if got.Allowed {
		t.Fatalf("legacy wildcard membership must not grant project access: %+v", got)
	}
}

func TestResourceCannotEscapeProjectScope(t *testing.T) {
	svc := New(fakeRepo{
		user:  model.User{ID: "u1", RoleID: "player", Status: "active", ProjectRoles: map[string]string{"p1": "owner"}},
		roles: []model.Role{{ID: "player", Permissions: []string{"launcher:login"}}, {ID: "owner", Permissions: []string{"*"}}},
	})
	got := svc.Authorize(context.Background(), Actor{Kind: ActorUser, ID: "u1"}, "project:write", Scope{Kind: ScopeProject, ProjectID: "p1"}, Resource{Kind: "profile", ID: "x", ProjectID: "p2"})
	if got.Allowed || got.ReasonCode != "resource-scope-mismatch" {
		t.Fatalf("mismatched resource escaped project scope: %+v", got)
	}
}

func TestProjectRoleCannotGrantInstanceWideAction(t *testing.T) {
	svc := New(fakeRepo{
		user: model.User{ID: "u1", RoleID: "player", Status: "active", ProjectRoles: map[string]string{"p1": "owner"}},
		roles: []model.Role{
			{ID: "player", Permissions: []string{"launcher:login"}},
			{ID: "owner", Permissions: []string{"*"}},
		},
	})
	got := svc.Authorize(context.Background(), Actor{Kind: ActorUser, ID: "u1"}, "users:manage", Scope{Kind: ScopeProject, ProjectID: "p1"}, Resource{Kind: "user", ID: "u2", ProjectID: "p1"})
	if got.Allowed || got.ReasonCode != "global-action-required" {
		t.Fatalf("project role granted an instance-wide action: %+v", got)
	}
}
