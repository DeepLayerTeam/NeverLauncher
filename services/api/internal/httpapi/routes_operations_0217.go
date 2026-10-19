package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/authorization"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const durableRollbackKind0217 = "channel-rollback"

// Only implemented executable operation kinds are registered. An operation is
// authorized against a real resource both at intake AND at worker execution.
type operationSpec0217 struct {
	Kind         string `json:"kind"`
	Action       string `json:"action"`
	ResourceType string `json:"resourceType"`
	Dangerous    bool   `json:"dangerous"`
}

var operationRegistry0217 = map[string]operationSpec0217{
	"package-publish":  {Kind: "package-publish", Action: "release:publish", ResourceType: "package", Dangerous: true},
	"channel-rollback": {Kind: "channel-rollback", Action: "release:publish", ResourceType: "channel", Dangerous: true},
}

type operationRequest0217 struct {
	Kind           string `json:"kind"`
	ProjectID      string `json:"projectId"`
	ResourceID     string `json:"resourceId,omitempty"`
	ProfileID      string `json:"profileId,omitempty"`
	Channel        string `json:"channel,omitempty"`
	ToVersion      string `json:"toVersion,omitempty"`
	IdempotencyKey string `json:"idempotencyKey,omitempty"`
}
type rollbackPayload0217 struct {
	ProjectID            string `json:"projectId"`
	ProfileID            string `json:"profileId"`
	Channel              string `json:"channel"`
	ToVersion            string `json:"toVersion"`
	TargetID             string `json:"targetId"`
	TargetManifestDigest string `json:"targetManifestDigest"`
	TargetArtifactDigest string `json:"targetArtifactDigest"`
}

func readOperationRequest0217(r *http.Request) (operationRequest0217, error) {
	var req operationRequest0217
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return req, errors.New("expected a single JSON object")
	}
	req.Kind = strings.TrimSpace(req.Kind)
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	req.ProfileID = strings.TrimSpace(req.ProfileID)
	req.Channel = strings.TrimSpace(req.Channel)
	req.ToVersion = strings.TrimSpace(req.ToVersion)
	return req, nil
}
func (s Server) registerOperationRoutes0217(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/projects/{projectId}/profiles/{profileId}/channels/{channel}/head", s.requireAuthenticated(s.channelHeadGet0228))
	mux.Handle("GET /api/v1/operations", s.requireAuthenticated(s.operationRegistryGet0217))
	mux.Handle("GET /api/v1/operations/jobs", s.requireAuthenticated(s.operationList02110))
	mux.Handle("POST /api/v1/operations/validate", s.requireAuthenticated(s.operationValidate0217))
	mux.Handle("POST /api/v1/operations/execute", s.requireAuthenticated(s.operationExecute0217))
	mux.Handle("GET /api/v1/operations/{operationId}", s.requireAuthenticated(s.operationStatus0217))
	mux.Handle("GET /api/v1/operations/{operationId}/attempts", s.requireAuthenticated(s.operationAttempts0217))
	mux.Handle("POST /api/v1/operations/{operationId}/cancel", s.requireAuthenticated(s.operationCancel0217))
	mux.Handle("POST /api/v1/operations/{operationId}/retry", s.requireAuthenticated(s.operationRetry0217))
}
func (s Server) operationRegistryGet0217(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": []operationSpec0217{operationRegistry0217["package-publish"], operationRegistry0217["channel-rollback"]}})
}
func (s Server) validateOperation0217(ctx context.Context, r *http.Request, claims authClaims, req operationRequest0217) (operationSpec0217, json.RawMessage, map[string]any, error) {
	spec, ok := operationRegistry0217[req.Kind]
	if !ok {
		return spec, nil, nil, errors.New("unsupported operation kind")
	}
	if req.ProfileID == "" {
		req.ProfileID = "vanilla"
	}
	if req.ProjectID == "" {
		return spec, nil, nil, errors.New("projectId is required")
	}
	resourceID := req.ResourceID
	if req.Kind == durableRollbackKind0217 {
		resourceID = req.Channel
	}
	if resourceID == "" {
		return spec, nil, nil, errors.New("resourceId/channel is required")
	}
	decision := s.authorizeClaims(r, claims, spec.Action, req.ProjectID, spec.ResourceType, resourceID)
	if !decision.Allowed {
		return spec, nil, nil, fmt.Errorf("authorization-denied:%s", decision.ReasonCode)
	}
	if req.Kind == "package-publish" {
		lookup, err := s.lookupPackage(resourceID)
		if err != nil {
			return spec, nil, nil, err
		}
		if lookup.Release.ProjectID != req.ProjectID {
			return spec, nil, nil, repository.ErrNotFound
		}
		if lookup.Release.Status == "published" {
			return spec, nil, nil, repository.ErrImmutable
		}
		if err = s.verifyManifestSignature(lookup.Release.Manifest); err != nil {
			return spec, nil, nil, err
		}
		if err = s.validatePublishEvidenceContext0213(ctx, lookup); err != nil {
			return spec, nil, nil, err
		}
		if err = validateCompatibilityManifest(lookup.Release.Manifest); err != nil {
			return spec, nil, nil, err
		}
		if !checksPassed0212(s.validatePackageFiles(lookup.Release, lookup.Files)) {
			return spec, nil, nil, errors.New("package file integrity check failed")
		}
		digest, err := manifestDigest0212(lookup.Release.Manifest)
		if err != nil {
			return spec, nil, nil, err
		}
		files, err := artifactDigest0212(lookup.Files)
		if err != nil {
			return spec, nil, nil, err
		}
		head, err := s.channelHead0228(ctx, lookup.Release.ProjectID, lookup.Release.ProfileID, lookup.Release.Channel)
		if err != nil {
			return spec, nil, nil, err
		}
		expected := head.Revision
		b, _ := json.Marshal(model.DurablePublishPayload{PackageID: resourceID, ExpectedManifestDigest: digest, ExpectedArtifactDigest: files, ExpectedStatus: lookup.Release.Status, ExpectedHeadRevision: &expected})
		return spec, b, map[string]any{"packageId": resourceID, "version": lookup.Release.Version, "channel": lookup.Release.Channel, "effect": "publish immutable package and advance channel"}, nil
	}
	if req.Channel == "" || req.ToVersion == "" {
		return spec, nil, nil, errors.New("channel and toVersion are required")
	}
	versions, err := s.Repo.ListVersions(req.ProjectID)
	if err != nil {
		return spec, nil, nil, err
	}
	var target *model.ReleaseVersion
	for i := range versions {
		v := &versions[i]
		if v.ProfileID == req.ProfileID && v.Channel == req.Channel && v.Version == req.ToVersion {
			target = v
			break
		}
	}
	if target == nil {
		return spec, nil, nil, repository.ErrNotFound
	}
	if target.Status != "published" {
		return spec, nil, nil, errors.New("rollback target must be a published immutable release")
	}
	if err = s.verifyManifestSignature(target.Manifest); err != nil {
		return spec, nil, nil, fmt.Errorf("rollback target signature invalid: %w", err)
	}
	files, err := s.Repo.ListFiles(req.ProjectID, target.ID)
	if err != nil {
		return spec, nil, nil, err
	}
	if len(files) == 0 {
		return spec, nil, nil, errors.New("rollback target has no canonical files")
	}
	md, err := manifestDigest0212(target.Manifest)
	if err != nil {
		return spec, nil, nil, err
	}
	fd, err := artifactDigest0212(files)
	if err != nil {
		return spec, nil, nil, err
	}
	payload := rollbackPayload0217{ProjectID: req.ProjectID, ProfileID: req.ProfileID, Channel: req.Channel, ToVersion: req.ToVersion, TargetID: target.ID, TargetManifestDigest: md, TargetArtifactDigest: fd}
	raw, _ := json.Marshal(payload)
	return spec, raw, map[string]any{"targetPackageId": target.ID, "targetVersion": target.Version, "projectId": req.ProjectID, "channel": req.Channel, "effect": "create one new signed immutable release from target, validate integrity, then publish subject to project policy"}, nil
}
func (s Server) operationValidate0217(w http.ResponseWriter, r *http.Request) {
	req, err := readOperationRequest0217(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}
	spec, _, effect, err := s.validateOperation0217(r.Context(), r, claims, req)
	if err != nil {
		writeOperationError0217(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"kind": spec.Kind, "permission": spec.Action, "dangerous": spec.Dangerous, "valid": true, "effect": effect}})
}

// Operation errors have stable machine codes and recovery advice shared by Admin/CLI.
func writeOperationError0217(w http.ResponseWriter, err error) {
	code, status, advice := "validation-failed", http.StatusBadRequest, "Correct the invalid fields and validate again"
	switch {
	case errors.Is(err, repository.ErrNotFound):
		status = http.StatusNotFound
		code = "resource-not-found"
		advice = "Check project permissions and resource ID"
	case errors.Is(err, repository.ErrLeaseBusy):
		status = http.StatusConflict
		code = "operation-busy"
		advice = "Wait for the active operation and refresh its status"
	case errors.Is(err, repository.ErrImmutable):
		status = http.StatusConflict
		code = "already-finalized"
		advice = "Open the saved job instead of repeating a completed mutation"
	case errors.Is(err, repository.ErrConflict):
		status = http.StatusConflict
		code = "idempotency-conflict"
		advice = "Reuse a key only for exactly the same operation, or start a new operation with a new key"
	case strings.HasPrefix(err.Error(), "authorization-denied:"):
		status = http.StatusForbidden
		code = "permission-denied"
		advice = "Request project permission or sign in again"
	}
	writeJSON(w, status, map[string]any{"apiVersion": apiContractVersion, "error": map[string]any{"code": code, "reasonCode": code, "message": err.Error(), "action": advice}})
}

func operationKey0217(r *http.Request, req operationRequest0217, actor string, raw []byte) string {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		key = strings.TrimSpace(req.IdempotencyKey)
	}
	if key != "" {
		return key
	}
	sum := sha256.Sum256(append([]byte(req.Kind+"|"+actor+"|"), raw...))
	return "auto:" + hex.EncodeToString(sum[:])
}
func (s Server) enqueueOperation0217(r *http.Request, claims authClaims, req operationRequest0217) (model.DurableJob, bool, error) {
	// Replay is resolved BEFORE revalidation: published releases are immutable,
	// but a successful request must still return its original durable job.
	cp, err := s.durableControlPlane0213()
	if err != nil {
		return model.DurableJob{}, false, err
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		key = strings.TrimSpace(req.IdempotencyKey)
	}
	if len(key) > 240 {
		return model.DurableJob{}, false, errors.New("Idempotency-Key too long")
	}
	if key != "" {
		if journal, ok := s.Repo.(repository.OperationJournal); ok {
			existing, findErr := journal.FindOperationByKey(r.Context(), req.Kind, claims.Sub, key)
			if findErr == nil {
				resource := req.ResourceID
				if req.Kind == durableRollbackKind0217 {
					resource = req.Channel
				}
				if existing.ProjectID != req.ProjectID || existing.ResourceID != resource {
					return model.DurableJob{}, false, repository.ErrConflict
				}
				if req.Kind == durableRollbackKind0217 {
					var payload rollbackPayload0217
					if json.Unmarshal(existing.Payload, &payload) != nil || payload.ToVersion != req.ToVersion || payload.ProfileID != firstNonEmpty(req.ProfileID, "vanilla") {
						return model.DurableJob{}, false, repository.ErrConflict
					}
				}
				if !s.authorizeClaims(r, claims, existing.Action, existing.ProjectID, existing.ResourceType, existing.ResourceID).Allowed {
					return model.DurableJob{}, false, errors.New("authorization-denied:project-access-revoked")
				}
				return existing, false, nil
			}
			if !errors.Is(findErr, repository.ErrNotFound) {
				return model.DurableJob{}, false, findErr
			}
		}
	}
	spec, raw, _, err := s.validateOperation0217(r.Context(), r, claims, req)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	if req.Kind == "package-publish" {
		lookup, e := s.lookupPackage(req.ResourceID)
		if e != nil {
			return model.DurableJob{}, false, e
		}
		if e = s.beforePackagePublish0206(r, lookup.Release); e != nil {
			return model.DurableJob{}, false, e
		}
		if e = s.beforeReleasePublish0206(r, lookup.Release); e != nil {
			return model.DurableJob{}, false, e
		}
	}

	if len(operationKey0217(r, req, claims.Sub, raw)) > 240 {
		return model.DurableJob{}, false, errors.New("Idempotency-Key too long")
	}
	resourceID := req.ResourceID
	if spec.Kind == durableRollbackKind0217 {
		resourceID = req.Channel
	}
	job := model.DurableJob{Kind: spec.Kind, ActorType: "user", ActorID: claims.Sub, Action: spec.Action, ProjectID: req.ProjectID, ResourceType: spec.ResourceType, ResourceID: resourceID, IdempotencyKey: operationKey0217(r, req, claims.Sub, raw), Payload: raw, MaxAttempts: 8}
	return cp.EnqueueDurableJob(r.Context(), job, 30*24*time.Hour)
}

// Public representation intentionally excludes internal lease tokens, worker
// identity, replay keys and frozen payloads. Neither Admin nor CLI need those
// secrets to inspect or recover an operation.
func publicOperation0217(j model.DurableJob) map[string]any {
	return map[string]any{
		"id": j.ID, "correlationId": j.ID, "kind": j.Kind,
		"actorId": j.ActorID, "action": j.Action, "projectId": j.ProjectID,
		"resourceType": j.ResourceType, "resourceId": j.ResourceID,
		"status": j.Status, "attemptCount": j.AttemptCount,
		"maxAttempts": j.MaxAttempts, "availableAt": j.AvailableAt,
		"lastError": j.LastError, "result": j.Result,
		"createdAt": j.CreatedAt, "updatedAt": j.UpdatedAt,
		"completedAt": j.CompletedAt,
	}
}
func (s Server) operationExecute0217(w http.ResponseWriter, r *http.Request) {
	req, err := readOperationRequest0217(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if _, ok := operationRegistry0217[req.Kind]; !ok {
		writeError(w, 400, "unsupported operation kind")
		return
	}
	if !s.freshAuthAllowed117(w, r, "mfa", 5*time.Minute) {
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, err.Error())
		return
	}

	job, _, err := s.enqueueOperation0217(r, claims, req)
	if err != nil {
		writeOperationError0217(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/operations/"+job.ID)
	w.Header().Set("X-Correlation-ID", job.ID)
	s.audit(r, claims.Sub, "operation:enqueue", job.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"apiVersion": apiContractVersion, "data": publicOperation0217(job)})
}
func (s Server) readVisibleOperation0217(w http.ResponseWriter, r *http.Request) (model.DurableJob, bool) {
	cp, err := s.durableControlPlane0213()
	if err != nil {
		writeError(w, 503, err.Error())
		return model.DurableJob{}, false
	}
	job, err := cp.GetDurableJob(r.Context(), r.PathValue("operationId"))
	if err != nil {
		writeError(w, 404, "operation not found")
		return model.DurableJob{}, false
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return model.DurableJob{}, false
	}
	if !s.authorizeClaims(r, claims, "project:read", job.ProjectID, job.ResourceType, job.ResourceID).Allowed && claims.Sub != job.ActorID {
		writeError(w, 404, "operation not found")
		return model.DurableJob{}, false
	}
	// Owner access is still bound to the original project's current authorization.
	if !s.authorizeClaims(r, claims, job.Action, job.ProjectID, job.ResourceType, job.ResourceID).Allowed && claims.Sub == job.ActorID && !s.authorizeClaims(r, claims, "project:read", job.ProjectID, "project", job.ProjectID).Allowed {
		writeError(w, 404, "operation not found")
		return model.DurableJob{}, false
	}
	w.Header().Set("X-Correlation-ID", job.ID)
	return job, true
}
func (s Server) operationStatus0217(w http.ResponseWriter, r *http.Request) {
	job, ok := s.readVisibleOperation0217(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": publicOperation0217(job)})
}

// Public journal deliberately omits internal worker/fencing/lease data.
func publicOperationAttempts02112(attempts []model.DurableJobAttempt) []map[string]any {
	out := make([]map[string]any, 0, len(attempts))
	for _, a := range attempts {
		out = append(out, map[string]any{
			"attempt": a.Attempt, "status": a.Status,
			"startedAt": a.StartedAt, "finishedAt": a.FinishedAt,
			"error": a.Error,
		})
	}
	return out
}

func (s Server) operationAttempts0217(w http.ResponseWriter, r *http.Request) {
	job, ok := s.readVisibleOperation0217(w, r)
	if !ok {
		return
	}
	journal, ok := s.Repo.(repository.OperationJournal)
	if !ok {
		writeError(w, 503, "operation journal unavailable")
		return
	}
	attempts, err := journal.ListOperationAttempts(r.Context(), job.ID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// Never expose worker identities, fencing tokens, or internal attempt IDs to
	// browser/API consumers. They are part of the durable execution boundary.
	publicAttempts := publicOperationAttempts02112(attempts)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"correlationId": job.ID, "attempts": publicAttempts}})
}
func (s Server) authorizeOperationMutation0217(w http.ResponseWriter, r *http.Request, job model.DurableJob) bool {
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return false
	}
	if !s.authorizeClaims(r, claims, job.Action, job.ProjectID, job.ResourceType, job.ResourceID).Allowed {
		writeError(w, 403, "permission revoked or project access denied")
		return false
	}
	return s.freshAuthAllowed117(w, r, "mfa", 5*time.Minute)
}
func (s Server) operationCancel0217(w http.ResponseWriter, r *http.Request) {
	job, ok := s.readVisibleOperation0217(w, r)
	if !ok {
		return
	}
	if !s.authorizeOperationMutation0217(w, r, job) {
		return
	}
	journal, ok := s.Repo.(repository.OperationJournal)
	if !ok {
		writeError(w, 503, "operation journal unavailable")
		return
	}
	claims, _ := s.adminClaims(r)
	updated, err := journal.CancelOperationJob(r.Context(), job.ID, claims.Sub)
	if err != nil {
		writeOperationError0217(w, err)
		return
	}
	s.audit(r, claims.Sub, "operation:cancel", job.ID)
	writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": publicOperation0217(updated)})
}
func (s Server) operationRetry0217(w http.ResponseWriter, r *http.Request) {
	job, ok := s.readVisibleOperation0217(w, r)
	if !ok {
		return
	}
	if !s.authorizeOperationMutation0217(w, r, job) {
		return
	}
	journal, ok := s.Repo.(repository.OperationJournal)
	if !ok {
		writeError(w, 503, "operation journal unavailable")
		return
	}
	claims, _ := s.adminClaims(r)
	updated, err := journal.RetryOperationJob(r.Context(), job.ID)
	if err != nil {
		writeOperationError0217(w, err)
		return
	}
	s.audit(r, claims.Sub, "operation:retry", job.ID)
	writeJSON(w, 202, map[string]any{"apiVersion": apiContractVersion, "data": publicOperation0217(updated)})
}
func (s Server) workerAuthorized0217(ctx context.Context, job model.DurableJob) error {
	cp, err := s.durableControlPlane0213()
	if err != nil {
		return err
	}
	live, err := cp.GetDurableJob(ctx, job.ID)
	if err != nil {
		return err
	}
	if live.Status != model.DurableJobStatusRunning || live.LeaseToken != job.LeaseToken || !live.LeaseExpiresAt.After(time.Now().UTC()) {
		return repository.ErrLeaseLost
	}
	d := s.authorizationService().Authorize(ctx, authorization.Actor{Kind: authorization.ActorUser, ID: job.ActorID}, job.Action, authorization.Scope{Kind: authorization.ScopeProject, ProjectID: job.ProjectID}, authorization.Resource{Kind: job.ResourceType, ID: job.ResourceID, ProjectID: job.ProjectID})
	if !d.Allowed {
		return fmt.Errorf("authorization-revoked:%s", d.ReasonCode)
	}
	return nil
}
