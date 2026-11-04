package httpapi

// Host operations use RemoteControl's existing on-disk receipt and Host
// Supervisor's real OS-process identity. The Backend persists a separate
// intent before sending a single request and never auto-reissues that request.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/authorization"
	"gitflic.ru/skif4er/launcher/services/api/internal/hostcontrol"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type hostOperationRepo0413 interface {
	CreateHostOperation0413(context.Context, repository.HostOperation0413) (repository.HostOperation0413, bool, error)
	GetHostOperation0413(context.Context, string, string) (repository.HostOperation0413, error)
	GetHostOperationByKey0413(context.Context, string, string) (repository.HostOperation0413, error)
	FinishHostOperation0413(context.Context, repository.HostOperation0413, string) (repository.HostOperation0413, error)
}

var hostKey0413 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

type hostOperationCreate0413 struct {
	Action string `json:"action"`
}

func hostReady0413(action string, op repository.HostOperation0413, node bridgeServerRecord) bool {
	if action == "stop" {
		return true
	}
	now := time.Now().UTC()
	return node.Status == "active" && node.RuntimeEpoch > op.BaselineRuntimeEpoch && node.RuntimeID != "" && node.RuntimeID != op.BaselineRuntimeID && node.LastHeartbeatAt.After(op.CreatedAt) && node.LastHeartbeatAt.After(now.Add(-90*time.Second)) && !node.LastHeartbeatAt.After(now.Add(30*time.Second))
}
func hostOperationWireKey0413(operationID string) string { return "nl-host-" + operationID }
func (s Server) hostOperationPreflight0413(w http.ResponseWriter, r *http.Request) (bridgeServerRecord, repository.HostOperation0413, hostOperationRepo0413, bool) {
	serverID := strings.TrimSpace(r.PathValue("serverId"))
	node, err := s.State.ServerBridge.getNode0142(serverID)
	if err != nil {
		writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
		return bridgeServerRecord{}, repository.HostOperation0413{}, nil, false
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid admin session")
		return bridgeServerRecord{}, repository.HostOperation0413{}, nil, false
	}
	// Host process permissions are GLOBAL; project roles or game-server scopes are not enough.
	if !s.authorizeClaims(r, claims, "project:read", node.ProjectID, "server", serverID).Allowed {
		writeError(w, http.StatusNotFound, "serverbridge_server_not_found")
		return bridgeServerRecord{}, repository.HostOperation0413{}, nil, false
	}
	if !s.authorizeClaims(r, claims, authorization.HostProcess, "", "host", serverID).Allowed {
		writeError(w, http.StatusForbidden, "host_process_permission_required")
		return bridgeServerRecord{}, repository.HostOperation0413{}, nil, false
	}
	rp, ok := s.Repo.(hostOperationRepo0413)
	if !ok || s.State.ServerBridge.backendV2() == nil {
		writeError(w, http.StatusServiceUnavailable, "host_operations_require_postgresql")
		return bridgeServerRecord{}, repository.HostOperation0413{}, nil, false
	}
	return node, repository.HostOperation0413{ServerID: serverID, RequestedBy: claims.Sub}, rp, true
}
func hostOperationOutput0413(op repository.HostOperation0413, node bridgeServerRecord, replay bool) map[string]any {
	return map[string]any{"operation": op, "idempotentReplay": replay, "hostState": op.State, "bridge": map[string]any{"serverId": node.ID, "status": node.Status, "runtimeId": node.RuntimeID, "runtimeEpoch": node.RuntimeEpoch, "lastHeartbeatAt": node.LastHeartbeatAt}, "controlDomain": "host-process"}
}
func decodeHostAction0413(r *http.Request, w http.ResponseWriter) (string, error) {
	var req hostOperationCreate0413
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return "", err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return "", errors.New("extra request body")
	}
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		return "", errors.New("unsupported host action")
	}
	return req.Action, nil
}
func (s Server) serverBridgeHostCreate0413(w http.ResponseWriter, r *http.Request) {
	node, op, rp, ok := s.hostOperationPreflight0413(w, r)
	if !ok {
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !hostKey0413.MatchString(key) {
		writeError(w, http.StatusBadRequest, "host_operation_idempotency_key_required")
		return
	}
	action, err := decodeHostAction0413(r, w)
	if err != nil {
		writeError(w, http.StatusBadRequest, "host_operation_action_invalid")
		return
	}
	digest := sha256.Sum256([]byte(op.ServerID + "\x00" + action + "\x00" + op.RequestedBy + "\x00" + key))
	fingerprint := hex.EncodeToString(digest[:])
	// Idempotent retries never need to reach RemoteControl, even when it or the
	// credential provider is down. Only an exact request digest may replay.
	existing, lookupErr := rp.GetHostOperationByKey0413(r.Context(), op.ServerID, key)
	if lookupErr == nil {
		if existing.RequestDigest != fingerprint || existing.Action != action || existing.RequestedBy != op.RequestedBy {
			writeError(w, http.StatusConflict, "host_operation_idempotency_conflict")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": hostOperationOutput0413(existing, node, true)})
		return
	}
	if !errors.Is(lookupErr, repository.ErrNotFound) {
		writeError(w, http.StatusServiceUnavailable, "host_operation_journal_unavailable")
		return
	}
	target, err := hostcontrol.LoadTarget(s.Config.ServerBridgeHostTargetsFile0413, op.ServerID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_target_unavailable")
		return
	}
	op.Action = action
	op.IdempotencyKey = key
	op.RequestDigest = fingerprint
	op.RemoteNodeID = target.NodeID
	op.BaselineRuntimeID = node.RuntimeID
	op.BaselineRuntimeEpoch = node.RuntimeEpoch
	// Only an operator-provisioned, pinned RemoteControl host may receive a command.
	client, err := hostcontrol.NewClient(target)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_tls_or_token_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 110*time.Second)
	defer cancel()
	// This is a read-only preflight. If it fails no command intent is created.
	before, err := client.Status(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_preflight_failed")
		return
	}
	rawBefore, _ := json.Marshal(before)
	op.HostBefore = rawBefore
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_id_generation_unavailable")
		return
	}
	op.ID = hex.EncodeToString(random)
	stored, reused, err := rp.CreateHostOperation0413(ctx, op)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "host_operation_conflict_or_prior_unresolved")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "host_operation_journal_unavailable")
		return
	}
	if reused {
		writeJSON(w, http.StatusOK, map[string]any{"data": hostOperationOutput0413(stored, node, true)})
		return
	}
	// The journal is committed BEFORE any external effect. On crash or timeout
	// the intent remains indeterminate and another Backend replica cannot retry.
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "serverbridge-host-intent-" + stored.ID, Actor: stored.RequestedBy, Action: "serverbridge:host:intent:" + stored.Action, Target: stored.ServerID + ":" + stored.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	receipt, runErr := client.Execute(ctx, action, hostOperationWireKey0413(stored.ID))
	if runErr != nil {
		stored.Error = "remote command outcome unknown: " + runErr.Error()
	} else {
		stored.RemoteReceipt, _ = json.Marshal(receipt)
		if receipt.State == "indeterminate" {
			stored.Error = "RemoteControl cannot prove host action completion: " + receipt.Error
		} else {
			after, statusErr := client.Status(ctx)
			if statusErr != nil {
				stored.State = "accepted"
				stored.Error = "remote acknowledgement received but host status unavailable: " + statusErr.Error()
			} else {
				stored.HostAfter, _ = json.Marshal(after)
				// A JVM can start before the game plugin reconnects. 'accepted' is not
				// represented as verified success until both host and ServerBridge agree.
				latest, nodeErr := s.State.ServerBridge.getNode0142(op.ServerID)
				if nodeErr == nil {
					node = latest
				}
				if hostcontrol.Verified(action, before, after, receipt) {
					if hostReady0413(action, stored, node) {
						stored.State = "succeeded"
					} else {
						stored.State = "accepted"
					}
				} else {
					stored.State = "accepted"
				}
			}
		}
	}
	// A disconnected HTTP caller must not cancel persistence of an already
	// executed external operation. Complete using a bounded independent context.
	persistCtx, persistCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer persistCancel()
	completed, err := rp.FinishHostOperation0413(persistCtx, stored, "indeterminate")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_outcome_recording_unavailable")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{ID: "serverbridge-host-outcome-" + completed.ID, Actor: completed.RequestedBy, Action: "serverbridge:host:" + completed.State, Target: completed.ServerID + ":" + completed.ID, IP: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC()})
	code := http.StatusAccepted
	if completed.State == "succeeded" {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]any{"data": hostOperationOutput0413(completed, node, false)})
}
func (s Server) serverBridgeHostGet0413(w http.ResponseWriter, r *http.Request) {
	node, info, rp, ok := s.hostOperationPreflight0413(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	operationID := strings.TrimSpace(r.PathValue("operationId"))
	op, err := rp.GetHostOperation0413(ctx, info.ServerID, operationID)
	if errors.Is(err, repository.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host_operation_not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_journal_unavailable")
		return
	}
	// Reconcile only by inspecting the RemoteControl's durable receipt and
	// independently observing the OS/bridge state. This path MUST NOT POST a
	// command. A lost ACK or crashed Backend remains indeterminate unless the
	// agent can prove it executed the exact original operation.
	if r.URL.Query().Get("refresh") == "1" && (op.State == "accepted" || op.State == "indeterminate") {
		target, loadErr := hostcontrol.LoadTarget(s.Config.ServerBridgeHostTargetsFile0413, op.ServerID)
		if loadErr == nil && target.NodeID == op.RemoteNodeID {
			client, clientErr := hostcontrol.NewClient(target)
			if clientErr == nil {
				receipt, receiptErr := client.ReadReceipt04112(ctx, op.Action, hostOperationWireKey0413(op.ID))
				if receiptErr == nil && receipt.State == "succeeded" {
					var before hostcontrol.Status
					if json.Unmarshal(op.HostBefore, &before) == nil && before.NodeID == op.RemoteNodeID {
						after, statusErr := client.Status(ctx)
						if statusErr == nil && hostcontrol.Verified(op.Action, before, after, receipt) {
							latest, nodeErr := s.State.ServerBridge.getNode0142(op.ServerID)
							if nodeErr == nil {
								node = latest
							}
							op.HostAfter, _ = json.Marshal(after)
							op.RemoteReceipt, _ = json.Marshal(receipt)
							originalState := op.State
							op.State = "accepted"
							if hostReady0413(op.Action, op, node) {
								op.State = "succeeded"
							}
							op.Error = ""
							allowed := originalState
							if updated, updateErr := rp.FinishHostOperation0413(ctx, op, allowed); updateErr == nil {
								op = updated
							} else if errors.Is(updateErr, repository.ErrConflict) {
								if current, getErr := rp.GetHostOperation0413(ctx, op.ServerID, op.ID); getErr == nil {
									op = current
								}
							} else {
								writeError(w, http.StatusServiceUnavailable, "host_operation_outcome_recording_unavailable")
								return
							}
						}
					}
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": hostOperationOutput0413(op, node, false)})
}

// Host views are privileged, read-only and use the existing pinned TLS client.
// Never convert an unavailable RemoteControl host into a healthy JVM.
func (s Server) serverBridgeHostStatus04111(w http.ResponseWriter, r *http.Request) {
	node, _, _, ok := s.hostOperationPreflight0413(w, r)
	if !ok {
		return
	}
	target, err := hostcontrol.LoadTarget(s.Config.ServerBridgeHostTargetsFile0413, node.ID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_target_unavailable")
		return
	}
	client, err := hostcontrol.NewClient(target)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_tls_or_token_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	host, err := client.Status(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_status_unavailable")
		return
	}
	// A host's processAlive means only that the Supervisor observed its process.
	// A signed game heartbeat is an independent, separately reported observation.
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"host": host, "observedAt": time.Now().UTC(), "bridge": map[string]any{
			"serverId": node.ID, "status": node.Status, "runtimeId": node.RuntimeID,
			"runtimeEpoch": node.RuntimeEpoch, "lastHeartbeatAt": node.LastHeartbeatAt,
		},
	}})
}

func (s Server) serverBridgeHostList04111(w http.ResponseWriter, r *http.Request) {
	node, _, rp, ok := s.hostOperationPreflight0413(w, r)
	if !ok {
		return
	}
	journal, ok := rp.(interface {
		ListHostOperations04111(context.Context, string, int) ([]repository.HostOperation0413, error)
	})
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "host_operation_journal_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
	defer cancel()
	ops, err := journal.ListHostOperations04111(ctx, node.ID, 25)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "host_operation_journal_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"items": ops}})
}
