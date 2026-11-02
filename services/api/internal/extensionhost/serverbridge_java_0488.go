package extensionhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/authorization"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Java extensions use the existing durable ServerBridge v3 repository. There is
// deliberately no direct node token, raw console, shell or alternate transport.
type javaBridgeRepository0488 interface {
	ListServerBridgeNodes(context.Context) ([]model.ServerBridgeNode, error)
	GetServerBridgeNode(context.Context, string) (model.ServerBridgeNode, error)
	GetActiveServerBridgeJoinTicket(context.Context, string, string, time.Time) (model.ServerBridgeJoinTicket, error)
	CreateServerBridgeControlCommand(context.Context, model.ServerBridgeControlCommand, time.Time) (model.ServerBridgeControlCommand, bool, error)
	GetServerBridgeControlCommand(context.Context, string, string) (model.ServerBridgeControlCommand, error)
}

// Closed command list, with the actual ServerBridge adapter capability required
// to execute the operation. Destructive shutdown and console are NOT exposed to
// the Java broker; the administrator-only ServerBridge control API retains them.
var bridgeJavaControls0488 = map[string]string{
	"message.broadcast": "adapter.control.broadcast",
	"player.kick":       "adapter.control.kick",
	"whitelist.add":     "adapter.control.whitelist", "whitelist.remove": "adapter.control.whitelist",
	"whitelist.enable": "adapter.control.whitelist", "whitelist.disable": "adapter.control.whitelist",
	"ban.add": "adapter.control.ban", "ban.remove": "adapter.control.ban",
	"server.save": "adapter.control.save", "server.drain": "adapter.control.drain",
	"server.maintenance": "adapter.control.maintenance",
}

func bridgeNodeView0488(n model.ServerBridgeNode) map[string]any {
	healthy := n.Status == "active" && n.ProtocolVersion == 3 && n.RuntimeEpoch > 0 &&
		len(n.RuntimeID) == 64 && n.RuntimeLastSeenAt.After(time.Now().Add(-90*time.Second)) &&
		!n.RuntimeLastSeenAt.After(time.Now().Add(2*time.Minute))
	return map[string]any{"id": n.ID, "projectId": n.ProjectID, "profileId": n.ProfileID,
		"name": n.Name, "kind": n.Kind, "status": n.Status, "protocolVersion": n.ProtocolVersion,
		"runtimeEpoch": n.RuntimeEpoch, "runtimeActive": healthy, "lastHeartbeatAt": n.LastHeartbeatAt,
		"playersOnline": bridgePlayers0488(n), "serverBrand": n.ServerBrand, "minecraftVersion": n.MinecraftVersion}
}
func bridgePlayers0488(n model.ServerBridgeNode) int {
	if n.Telemetry != nil && n.Telemetry.PlayersOnline != nil && *n.Telemetry.PlayersOnline >= 0 {
		return *n.Telemetry.PlayersOnline
	}
	return 0
}
func bridgePayload0488(kind string, raw map[string]string) (map[string]string, error) {
	if _, ok := bridgeJavaControls0488[kind]; !ok {
		return nil, errors.New("serverbridge_command_not_allowed")
	}
	if len(raw) > 16 {
		return nil, errors.New("serverbridge_payload_invalid")
	}
	clean := make(map[string]string, len(raw))
	for k, v := range raw {
		if k == "" || len(k) > 64 || len(v) > 1024 || strings.ContainsAny(k, "\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") || strings.TrimSpace(v) != v {
			return nil, errors.New("serverbridge_payload_invalid")
		}
		clean[k] = v
	}
	allowed := map[string]bool{}
	required := map[string]bool{}
	switch kind {
	case "message.broadcast":
		allowed["message"] = true
		required["message"] = true
	case "player.kick":
		allowed["username"] = true
		allowed["reason"] = true
		required["username"] = true
	case "whitelist.add", "whitelist.remove", "ban.add", "ban.remove":
		allowed["username"] = true
		allowed["reason"] = true
		required["username"] = true
	case "server.maintenance", "server.drain":
		allowed["enabled"] = true
		allowed["reason"] = true
		required["enabled"] = true
	}
	for k := range clean {
		if !allowed[k] {
			return nil, errors.New("serverbridge_payload_unknown_argument")
		}
	}
	for k := range required {
		if clean[k] == "" {
			return nil, errors.New("serverbridge_payload_required_argument")
		}
	}
	if kind == "server.drain" || kind == "server.maintenance" {
		if clean["enabled"] != "true" && clean["enabled"] != "false" {
			return nil, errors.New("serverbridge_payload_enabled_invalid")
		}
	}
	if len(clean["username"]) > 32 {
		return nil, errors.New("serverbridge_username_invalid")
	}
	encoded, _ := json.Marshal(clean)
	if len(encoded) > 4096 {
		return nil, errors.New("serverbridge_payload_too_large")
	}
	return clean, nil
}
func bridgeRuntimeControl0488(node model.ServerBridgeNode, kind string, now time.Time) bool {
	capability, ok := bridgeJavaControls0488[kind]
	if !ok || node.Status != "active" || node.ProtocolVersion != 3 || node.RuntimeEpoch < 1 || len(node.RuntimeID) != 64 {
		return false
	}
	if _, err := hex.DecodeString(node.RuntimeID); err != nil {
		return false
	}
	if node.RuntimeLastSeenAt.Before(now.Add(-90*time.Second)) || node.RuntimeLastSeenAt.After(now.Add(2*time.Minute)) {
		return false
	}
	// Mirror the ServerBridge adapter-family restrictions. A signed claim is
	// necessary but cannot grant a command unsupported by the platform family.
	platform := strings.ToLower(strings.TrimSpace(node.Kind))
	switch platform {
	case "velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia", "fabric", "quilt", "forge", "neoforge", "sponge", "vanilla":
	default:
		return false
	}
	brand := strings.ToLower(node.ServerBrand)
	for _, marker := range []string{"mohist", "arclight", "magma", "catserver", "banner", "cardboard"} {
		if strings.Contains(brand, marker) {
			return false
		}
	}
	proxy := platform == "velocity" || platform == "bungeecord" || platform == "waterfall"
	if (capability == "adapter.control.whitelist" || capability == "adapter.control.ban" || capability == "adapter.control.save") && (proxy || platform == "sponge") {
		return false
	}
	if node.IntegrityStatus != "verified" {
		return false
	}
	for _, v := range node.RuntimeCapabilities {
		if v == capability {
			return true
		}
	}
	return false
}
func bridgeCommandView0488(c model.ServerBridgeControlCommand) map[string]any {
	// Never expose lease credentials, actor, raw arguments or node identity.
	return map[string]any{"id": c.ID, "serverId": c.ServerID, "type": c.Type, "status": c.Status,
		"attempt": c.Attempt, "runtimeEpoch": c.RuntimeEpoch, "createdAt": c.CreatedAt,
		"updatedAt": c.UpdatedAt, "expiresAt": c.ExpiresAt, "completedAt": c.CompletedAt}
}
func (s *Supervisor) bridgeAuthorization0488(ctx context.Context, st *processState, projectID, permission string) (int, error) {
	if projectID == "" {
		return http.StatusBadRequest, errors.New("projectId required")
	}
	for _, p := range []string{"serverbridge:read", permission} {
		ok, err := s.permissionAllowed0207(ctx, st, p, projectID)
		if err != nil {
			return http.StatusServiceUnavailable, errors.New("serverbridge capability policy unavailable")
		}
		if !ok {
			return http.StatusForbidden, fmt.Errorf("serverbridge permission %s denied", p)
		}
	}
	return http.StatusOK, nil
}
func (s *Supervisor) executeBridge0488(ctx context.Context, st *processState, name string, req capabilityRequest) capabilityResult0205 {
	denied := func(status int, e error) capabilityResult0205 { return capabilityResult0205{status: status, err: e} }
	projectID, err := s.scopedProject(st, req.ProjectID)
	if err != nil {
		return denied(http.StatusForbidden, err)
	}
	repo, ok := s.repo.(javaBridgeRepository0488)
	if !ok {
		return denied(http.StatusServiceUnavailable, errors.New("ServerBridge durable storage unavailable"))
	}
	permission := "serverbridge:read"
	kind := strings.ToLower(strings.TrimSpace(req.CommandType))
	if name == "bridge.command.create" {
		var known bool
		permission, known = authorization.GameCommandPermission(kind)
		if !known {
			return denied(http.StatusBadRequest, errors.New("unsupported ServerBridge command"))
		}
		if _, ok = bridgeJavaControls0488[kind]; !ok {
			return denied(http.StatusForbidden, errors.New("ServerBridge command not available to extensions"))
		}
	}
	if status, err := s.bridgeAuthorization0488(ctx, st, projectID, permission); err != nil {
		return denied(status, err)
	}
	if name == "bridge.servers" {
		if req.Offset < 0 || req.Offset > 1000000 || req.Limit < 1 || req.Limit > 50 {
			return denied(http.StatusBadRequest, errors.New("invalid server page"))
		}
		nodes, err := repo.ListServerBridgeNodes(ctx)
		if err != nil {
			return denied(http.StatusServiceUnavailable, errors.New("ServerBridge repository unavailable"))
		}
		items := make([]model.ServerBridgeNode, 0)
		for _, n := range nodes {
			if n.ProjectID == projectID {
				items = append(items, n)
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		start := req.Offset
		if start > len(items) {
			start = len(items)
		}
		end := start + req.Limit
		if end > len(items) {
			end = len(items)
		}
		page := make([]any, 0, end-start)
		for _, n := range items[start:end] {
			page = append(page, bridgeNodeView0488(n))
		}
		out := map[string]any{"items": page}
		if end < len(items) {
			out["nextOffset"] = end
		}
		return capabilityResult0205{status: http.StatusOK, value: out}
	}
	serverID := strings.TrimSpace(req.ServerID)
	if serverID == "" || len(serverID) > 128 {
		return denied(http.StatusBadRequest, errors.New("serverId required"))
	}
	node, err := repo.GetServerBridgeNode(ctx, serverID)
	if err != nil || node.ProjectID != projectID {
		return denied(http.StatusNotFound, errors.New("server not found"))
	}
	switch name {
	case "bridge.server":
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"server": bridgeNodeView0488(node)}}
	case "bridge.access.ticket":
		// Advisory check only: this is NOT an admission decision, and it never
		// consumes the one-time ticket or replaces official Minecraft hasJoined.
		if status, err := s.bridgeAuthorization0488(ctx, st, projectID, "project:read"); err != nil {
			return denied(status, err)
		}
		username := strings.TrimSpace(req.Username)
		if len(username) < 3 || len(username) > 16 {
			return denied(http.StatusBadRequest, errors.New("invalid Minecraft username"))
		}
		for _, c := range username {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return denied(http.StatusBadRequest, errors.New("invalid Minecraft username"))
			}
		}
		ticket, err := repo.GetActiveServerBridgeJoinTicket(ctx, username, serverID, time.Now().UTC())
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return denied(http.StatusServiceUnavailable, errors.New("ServerBridge join-ticket lookup unavailable"))
		}
		pending := err == nil && ticket.ServerID == serverID && ticket.ProjectID == projectID &&
			ticket.IssuedIdentityEpoch == node.IdentityEpoch && strings.EqualFold(ticket.IssuedKeyFingerprint, node.KeyFingerprint) &&
			ticket.ExpiresAt.After(time.Now().UTC()) && ticket.Status == "active"
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"pendingTicket": pending}}
	case "bridge.command.get":
		if req.CommandID == "" || len(req.CommandID) > 128 {
			return denied(http.StatusBadRequest, errors.New("commandId required"))
		}
		command, err := repo.GetServerBridgeControlCommand(ctx, serverID, req.CommandID)
		if err != nil || command.ServerID != serverID {
			return denied(http.StatusNotFound, errors.New("command not found"))
		}
		p, known := authorization.GameCommandPermission(command.Type)
		if !known {
			return denied(http.StatusForbidden, errors.New("command type not permitted"))
		}
		if status, err := s.bridgeAuthorization0488(ctx, st, projectID, p); err != nil {
			return denied(status, err)
		}
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"command": bridgeCommandView0488(command)}}
	case "bridge.command.create":
		now := time.Now().UTC()
		if !bridgeRuntimeControl0488(node, kind, now) {
			return denied(http.StatusConflict, errors.New("ServerBridge runtime not active or adapter capability not verified"))
		}
		payload, err := bridgePayload0488(kind, req.Payload)
		if err != nil {
			return denied(http.StatusBadRequest, err)
		}
		if len(req.IdempotencyKey) < 8 || len(req.IdempotencyKey) > 128 || strings.ContainsAny(req.IdempotencyKey, "\r\n\x00") {
			return denied(http.StatusBadRequest, errors.New("idempotencyKey must be 8..128 characters"))
		}
		ttl := req.ExpiresInSeconds
		if ttl == 0 {
			ttl = 120
		}
		if ttl < 10 || ttl > 600 {
			return denied(http.StatusBadRequest, errors.New("expiresInSeconds must be 10..600"))
		}
		if ctx.Err() != nil {
			return denied(http.StatusGatewayTimeout, ctx.Err())
		}
		// A last policy check before the durable side effect closes the common
		// permission-revocation race; the DB enforces runtime epoch atomically.
		if status, err := s.bridgeAuthorization0488(ctx, st, projectID, permission); err != nil {
			return denied(status, err)
		}
		random := make([]byte, 16)
		if _, err = rand.Read(random); err != nil {
			return denied(http.StatusInternalServerError, errors.New("secure ID generation failed"))
		}
		raw, _ := json.Marshal(payload)
		hash := sha256.Sum256(raw)
		actor := "extension:" + st.key.ExtensionID + ":" + st.key.Scope + ":" + st.key.ScopeID
		canonical := strings.Join([]string{serverID, strconv.FormatInt(node.RuntimeEpoch, 10), strings.ToLower(node.RuntimeID), kind, hex.EncodeToString(hash[:]), actor, req.IdempotencyKey}, "\n")
		digest := sha256.Sum256([]byte(canonical))
		cmd := model.ServerBridgeControlCommand{ID: "ext-" + hex.EncodeToString(random), ServerID: serverID, RuntimeEpoch: node.RuntimeEpoch, RuntimeID: strings.ToLower(node.RuntimeID), Type: kind, Payload: payload, PayloadSHA256: hex.EncodeToString(hash[:]), RequestDigest: hex.EncodeToString(digest[:]), RequestedBy: actor, IdempotencyKey: req.IdempotencyKey, Status: "pending", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second)}
		saved, replay, err := repo.CreateServerBridgeControlCommand(ctx, cmd, now)
		if err != nil {
			if errors.Is(err, repository.ErrConflict) {
				return denied(http.StatusConflict, errors.New("ServerBridge command conflict or runtime replaced"))
			}
			return denied(http.StatusServiceUnavailable, errors.New("ServerBridge command storage unavailable"))
		}
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"command": bridgeCommandView0488(saved), "idempotentReplay": replay}}
	default:
		return denied(http.StatusNotFound, errors.New("unsupported ServerBridge operation"))
	}
}

// The final authorization gate runs after lookup but before a response escapes
// the authenticated broker. Command reads must also recheck the command domain.
func (s *Supervisor) revalidateBridge0488(ctx context.Context, st *processState, name string, req capabilityRequest) error {
	projectID, err := s.scopedProject(st, req.ProjectID)
	if err != nil {
		return err
	}
	permission := "serverbridge:read"
	if name == "bridge.command.create" {
		var ok bool
		permission, ok = authorization.GameCommandPermission(strings.ToLower(strings.TrimSpace(req.CommandType)))
		if !ok {
			return errors.New("unsupported command")
		}
	}
	if name == "bridge.access.ticket" {
		if _, err := s.bridgeAuthorization0488(ctx, st, projectID, "project:read"); err != nil {
			return err
		}
	}
	if name == "bridge.command.get" {
		repo, ok := s.repo.(javaBridgeRepository0488)
		if !ok {
			return errors.New("ServerBridge unavailable")
		}
		command, err := repo.GetServerBridgeControlCommand(ctx, req.ServerID, req.CommandID)
		if err != nil {
			return err
		}
		node, err := repo.GetServerBridgeNode(ctx, req.ServerID)
		if err != nil || node.ProjectID != projectID {
			return errors.New("server scope changed")
		}
		permission, ok = authorization.GameCommandPermission(command.Type)
		if !ok {
			return errors.New("unsupported command")
		}
	}
	_, err = s.bridgeAuthorization0488(ctx, st, projectID, permission)
	return err
}
