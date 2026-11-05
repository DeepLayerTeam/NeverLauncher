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

// Java-расширения используют существующий устойчивый репозиторий ServerBridge v3.
// Намеренно отсутствуют прямой токен узла, необработанная консоль, shell и
// альтернативный транспорт.
type javaBridgeRepository0488 interface {
	ListServerBridgeNodes(context.Context) ([]model.ServerBridgeNode, error)
	GetServerBridgeNode(context.Context, string) (model.ServerBridgeNode, error)
	GetActiveServerBridgeJoinTicket(context.Context, string, string, time.Time) (model.ServerBridgeJoinTicket, error)
	CreateServerBridgeControlCommand(context.Context, model.ServerBridgeControlCommand, time.Time) (model.ServerBridgeControlCommand, bool, error)
	GetServerBridgeControlCommand(context.Context, string, string) (model.ServerBridgeControlCommand, error)
}

// Закрытый список команд с обязательной возможностью адаптера ServerBridge для
// выполнения. Разрушающие shutdown и console НЕ доступны Java-брокеру; они остаются в
// API управления ServerBridge только для администратора.
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
	// Повторяйте ограничения семейства адаптеров ServerBridge. Подписанное
	// утверждение необходимо, но не может разрешить команду, которую семейство
	// платформ не поддерживает.
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
	// Никогда не раскрывайте учётные данные аренды, исполнителя, необработанные
	// аргументы или идентичность узла.
	return map[string]any{"id": c.ID, "serverId": c.ServerID, "type": c.Type, "status": c.Status,
		"attempt": c.Attempt, "runtimeEpoch": c.RuntimeEpoch, "createdAt": c.CreatedAt,
		"updatedAt": c.UpdatedAt, "expiresAt": c.ExpiresAt, "completedAt": c.CompletedAt}
}
func (s *Supervisor) bridgeAuthorization0488(ctx context.Context, st *processState, projectID, permission string) (int, error) {
	if projectID == "" {
		return http.StatusBadRequest, errors.New("Требуется projectId")
	}
	for _, p := range []string{"serverbridge:read", permission} {
		ok, err := s.permissionAllowed0207(ctx, st, p, projectID)
		if err != nil {
			return http.StatusServiceUnavailable, errors.New("Политика разрешений ServerBridge недоступна")
		}
		if !ok {
			return http.StatusForbidden, fmt.Errorf("Разрешение ServerBridge %s отклонено", p)
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
		return denied(http.StatusServiceUnavailable, errors.New("Долговременное хранилище ServerBridge недоступно"))
	}
	permission := "serverbridge:read"
	kind := strings.ToLower(strings.TrimSpace(req.CommandType))
	if name == "bridge.command.create" {
		var known bool
		permission, known = authorization.GameCommandPermission(kind)
		if !known {
			return denied(http.StatusBadRequest, errors.New("Неподдерживаемая команда ServerBridge"))
		}
		if _, ok = bridgeJavaControls0488[kind]; !ok {
			return denied(http.StatusForbidden, errors.New("Команда ServerBridge недоступна расширениям"))
		}
	}
	if status, err := s.bridgeAuthorization0488(ctx, st, projectID, permission); err != nil {
		return denied(status, err)
	}
	if name == "bridge.servers" {
		if req.Offset < 0 || req.Offset > 1000000 || req.Limit < 1 || req.Limit > 50 {
			return denied(http.StatusBadRequest, errors.New("Недопустимая страница серверов"))
		}
		nodes, err := repo.ListServerBridgeNodes(ctx)
		if err != nil {
			return denied(http.StatusServiceUnavailable, errors.New("Репозиторий ServerBridge недоступен"))
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
		return denied(http.StatusBadRequest, errors.New("Требуется serverId"))
	}
	node, err := repo.GetServerBridgeNode(ctx, serverID)
	if err != nil || node.ProjectID != projectID {
		return denied(http.StatusNotFound, errors.New("Сервер не найден"))
	}
	switch name {
	case "bridge.server":
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"server": bridgeNodeView0488(node)}}
	case "bridge.access.ticket":
		// Только рекомендательная проверка: это НЕ решение о допуске. Она никогда не
		// расходует одноразовый билет и не заменяет официальный Minecraft hasJoined.
		if status, err := s.bridgeAuthorization0488(ctx, st, projectID, "project:read"); err != nil {
			return denied(status, err)
		}
		username := strings.TrimSpace(req.Username)
		if len(username) < 3 || len(username) > 16 {
			return denied(http.StatusBadRequest, errors.New("Некорректное значение: имя пользователя Minecraft"))
		}
		for _, c := range username {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return denied(http.StatusBadRequest, errors.New("Некорректное значение: имя пользователя Minecraft"))
			}
		}
		ticket, err := repo.GetActiveServerBridgeJoinTicket(ctx, username, serverID, time.Now().UTC())
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return denied(http.StatusServiceUnavailable, errors.New("Поиск пропуска на сервер через ServerBridge недоступен"))
		}
		pending := err == nil && ticket.ServerID == serverID && ticket.ProjectID == projectID &&
			ticket.IssuedIdentityEpoch == node.IdentityEpoch && strings.EqualFold(ticket.IssuedKeyFingerprint, node.KeyFingerprint) &&
			ticket.ExpiresAt.After(time.Now().UTC()) && ticket.Status == "active"
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"pendingTicket": pending}}
	case "bridge.command.get":
		if req.CommandID == "" || len(req.CommandID) > 128 {
			return denied(http.StatusBadRequest, errors.New("Требуется commandId"))
		}
		command, err := repo.GetServerBridgeControlCommand(ctx, serverID, req.CommandID)
		if err != nil || command.ServerID != serverID {
			return denied(http.StatusNotFound, errors.New("Команда не найдена"))
		}
		p, known := authorization.GameCommandPermission(command.Type)
		if !known {
			return denied(http.StatusForbidden, errors.New("Тип команды не разрешён"))
		}
		if status, err := s.bridgeAuthorization0488(ctx, st, projectID, p); err != nil {
			return denied(status, err)
		}
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"command": bridgeCommandView0488(command)}}
	case "bridge.command.create":
		now := time.Now().UTC()
		if !bridgeRuntimeControl0488(node, kind, now) {
			return denied(http.StatusConflict, errors.New("Среда ServerBridge неактивна или разрешения адаптера не проверены"))
		}
		payload, err := bridgePayload0488(kind, req.Payload)
		if err != nil {
			return denied(http.StatusBadRequest, err)
		}
		if len(req.IdempotencyKey) < 8 || len(req.IdempotencyKey) > 128 || strings.ContainsAny(req.IdempotencyKey, "\r\n\x00") {
			return denied(http.StatusBadRequest, errors.New("idempotencyKey должен содержать от 8 до 128 символов"))
		}
		ttl := req.ExpiresInSeconds
		if ttl == 0 {
			ttl = 120
		}
		if ttl < 10 || ttl > 600 {
			return denied(http.StatusBadRequest, errors.New("expiresInSeconds должен быть от 10 до 600"))
		}
		if ctx.Err() != nil {
			return denied(http.StatusGatewayTimeout, ctx.Err())
		}
		// Последняя проверка политики перед устойчивым побочным эффектом закрывает
		// обычную гонку отзыва разрешения; БД атомарно обеспечивает эпоху Runtime.
		if status, err := s.bridgeAuthorization0488(ctx, st, projectID, permission); err != nil {
			return denied(status, err)
		}
		random := make([]byte, 16)
		if _, err = rand.Read(random); err != nil {
			return denied(http.StatusInternalServerError, errors.New("Ошибка генерации защищённого идентификатора"))
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
				return denied(http.StatusConflict, errors.New("Конфликт команды ServerBridge или замена среды выполнения"))
			}
			return denied(http.StatusServiceUnavailable, errors.New("Хранилище команд ServerBridge недоступно"))
		}
		return capabilityResult0205{status: http.StatusOK, value: map[string]any{"command": bridgeCommandView0488(saved), "idempotentReplay": replay}}
	default:
		return denied(http.StatusNotFound, errors.New("Неподдерживаемая операция ServerBridge"))
	}
}

// Окончательный барьер авторизации срабатывает после чтения, но до выхода ответа из
// аутентифицированного брокера. Чтение команд также требует повторной проверки
// домена команды.
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
			return errors.New("Не поддерживается: команда")
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
			return errors.New("ServerBridge недоступен")
		}
		command, err := repo.GetServerBridgeControlCommand(ctx, req.ServerID, req.CommandID)
		if err != nil {
			return err
		}
		node, err := repo.GetServerBridgeNode(ctx, req.ServerID)
		if err != nil || node.ProjectID != projectID {
			return errors.New("Область сервера изменилась")
		}
		permission, ok = authorization.GameCommandPermission(command.Type)
		if !ok {
			return errors.New("Не поддерживается: команда")
		}
	}
	_, err = s.bridgeAuthorization0488(ctx, st, projectID, permission)
	return err
}
