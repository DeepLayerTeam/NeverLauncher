package authorization

import (
	"context"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

func TestControlDomains0281ClosedDispatchTable(t *testing.T) {
	commands := map[string]string{
		"message.broadcast": GameBroadcast,
		"player.kick":       GameModerate,
		"whitelist.add":     GameModerate, "whitelist.remove": GameModerate,
		"whitelist.enable": GameModerate, "whitelist.disable": GameModerate,
		"ban.add": GameModerate, "ban.remove": GameModerate,
		"server.save": GameSave, "server.maintenance": GameTraffic,
		"server.drain": GameTraffic, "server.shutdown": GameShutdown,
		"server.console": GameConsole,
	}
	for kind, want := range commands {
		got, ok := GameCommandPermission(kind)
		if !ok || got != want || !IsProjectAction(got) {
			t.Fatalf("%s: permission %q, known %t", kind, got, ok)
		}
		domain, ok := ControlActionDomain(got)
		if !ok || domain != DomainGame {
			t.Fatalf("%s escaped Game domain: %q", kind, domain)
		}
	}
	for _, kind := range []string{"", "server.shell", "host.exec", "host.restart", "backend.restart", "server.restart", "MESSAGE.BROADCAST", "message.broadcast;host.exec"} {
		if permission, ok := GameCommandPermission(kind); ok || permission != "" {
			t.Fatalf("unsafe command %q accepted as %q", kind, permission)
		}
	}
	for _, action := range []string{BackendControl, HostProcess, HostExec} {
		if !IsControlAction(action) || IsProjectAction(action) {
			t.Fatalf("host/backend action %q is project scoped", action)
		}
	}
}

func TestControlDomains0281BroadcastOnlyNeverEscalates(t *testing.T) {
	svc := New(fakeRepo{
		user: model.User{ID: "user", RoleID: "player", Status: "active", ProjectRoles: map[string]string{"alpha": "broadcaster"}},
		roles: []model.Role{
			{ID: "player", Permissions: []string{"launcher:login"}},
			{ID: "broadcaster", Permissions: []string{"project:read", GameBroadcast}},
			{ID: "owner", Permissions: []string{"*"}},
		},
	})
	ctx := context.Background()
	actor := Actor{Kind: ActorUser, ID: "user"}
	authorize := func(action, project string) Decision {
		return svc.Authorize(ctx, actor, action,
			Scope{Kind: ScopeProject, ProjectID: project}, Resource{Kind: "server", ID: "game-1", ProjectID: project})
	}
	if got := authorize(GameBroadcast, "alpha"); !got.Allowed {
		t.Fatalf("project broadcaster denied: %+v", got)
	}
	for _, action := range []string{GameModerate, GameSave, GameTraffic, GameShutdown, GameConsole, BackendControl, HostProcess, HostExec, "serverbridge:console", "serverbridge:control"} {
		if got := authorize(action, "alpha"); got.Allowed {
			t.Fatalf("broadcast granted %q: %+v", action, got)
		}
	}
	if got := authorize(GameBroadcast, "beta"); got.Allowed {
		t.Fatalf("cross-project authority: %+v", got)
	}
	if got := svc.Authorize(ctx, actor, HostExec, Scope{Kind: ScopeGlobal}, Resource{Kind: "host"}); got.Allowed {
		t.Fatalf("project broadcaster got global shell access: %+v", got)
	}
}

func TestControlDomains0281LegacyControlIsNotImplicitPrivilege(t *testing.T) {
	svc := New(fakeRepo{
		user:  model.User{ID: "user", RoleID: "legacy", Status: "active", ProjectRoles: map[string]string{"alpha": "legacy"}},
		roles: []model.Role{{ID: "legacy", Permissions: []string{"serverbridge:control", "serverbridge:console"}}},
	})
	actor := Actor{Kind: ActorUser, ID: "user"}
	for _, action := range []string{GameBroadcast, GameModerate, GameSave, GameTraffic, GameShutdown, GameConsole, BackendControl, HostProcess, HostExec} {
		got := svc.Authorize(context.Background(), actor, action, Scope{Kind: ScopeProject, ProjectID: "alpha"}, Resource{Kind: "server", ProjectID: "alpha"})
		if got.Allowed {
			t.Fatalf("legacy permission implicitly escalated to %s", action)
		}
	}
}

func TestControlDomains0281InstanceRightsRequireGlobalScope(t *testing.T) {
	svc := New(fakeRepo{
		user:  model.User{ID: "owner", RoleID: "owner", Status: "active", ProjectRoles: map[string]string{"alpha": "owner"}},
		roles: []model.Role{{ID: "owner", Permissions: []string{"*"}}},
	})
	actor := Actor{Kind: ActorUser, ID: "owner"}
	for _, action := range []string{BackendControl, HostProcess, HostExec} {
		denied := svc.Authorize(context.Background(), actor, action, Scope{Kind: ScopeProject, ProjectID: "alpha"}, Resource{Kind: "host", ProjectID: "alpha"})
		if denied.Allowed || denied.ReasonCode != "instance-scope-required" {
			t.Fatalf("%s unexpectedly permitted in project scope: %+v", action, denied)
		}
		allowed := svc.Authorize(context.Background(), actor, action, Scope{Kind: ScopeGlobal}, Resource{Kind: "host"})
		if !allowed.Allowed {
			t.Fatalf("owner's global right denied: %+v", allowed)
		}
	}
}
