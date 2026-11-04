package authorization

// ControlDomain names the privilege boundary for an operational command.
// Game commands are project-scoped. Backend and host actions are instance-scoped
// and must NEVER be authorized with project memberships or a game permission.
type ControlDomain string

const (
	DomainGame    ControlDomain = "game-server"
	DomainBackend ControlDomain = "backend"
	DomainHost    ControlDomain = "host-process"
)

const (
	GameBroadcast  = "gameserver:broadcast"
	GameModerate   = "gameserver:moderate"
	GameSave       = "gameserver:save"
	GameTraffic    = "gameserver:traffic"
	GameShutdown   = "gameserver:shutdown"
	GameConsole    = "gameserver:console"
	BackendControl = "backend:control"
	HostProcess    = "host:process"
	HostExec       = "host:exec"
)

// GameCommandPermission is a closed dispatch table. Unknown commands, including
// backend/host/shell commands, have NO authority in ServerBridge control API.
func GameCommandPermission(kind string) (string, bool) {
	switch kind {
	case "message.broadcast":
		return GameBroadcast, true
	case "player.kick", "ban.add", "ban.remove", "whitelist.add", "whitelist.remove", "whitelist.enable", "whitelist.disable":
		return GameModerate, true
	case "server.save":
		return GameSave, true
	case "server.maintenance", "server.drain":
		return GameTraffic, true
	case "server.shutdown":
		return GameShutdown, true
	case "server.console":
		return GameConsole, true
	default:
		return "", false
	}
}

func IsControlAction(action string) bool {
	switch action {
	case GameBroadcast, GameModerate, GameSave, GameTraffic, GameShutdown, GameConsole, BackendControl, HostProcess, HostExec:
		return true
	default:
		return false
	}
}

func ControlActionDomain(action string) (ControlDomain, bool) {
	switch action {
	case GameBroadcast, GameModerate, GameSave, GameTraffic, GameShutdown, GameConsole:
		return DomainGame, true
	case BackendControl:
		return DomainBackend, true
	case HostProcess, HostExec:
		return DomainHost, true
	default:
		return "", false
	}
}
