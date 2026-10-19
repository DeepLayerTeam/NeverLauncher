package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/eventbus"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

// rollbackVersion0217 is bound to the persisted operation id, never to wall-clock
// time. All replays/recovered workers converge on the same release and storage key.
func rollbackVersion0217(p rollbackPayload0217, jobID string) string {
	return p.ToVersion + "-rollback-" + strings.TrimPrefix(jobID, "job_")
}
func (s Server) stageRollback0217(ctx context.Context, job model.DurableJob, p rollbackPayload0217) (model.ReleaseVersion, model.IntegrityCheckResult, error) {
	if p.ProjectID != job.ProjectID || p.Channel != job.ResourceID || p.TargetID == "" || p.TargetManifestDigest == "" || p.TargetArtifactDigest == "" {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback payload binding mismatch")
	}
	if err := s.workerAuthorized0217(ctx, job); err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
	}
	// Serialize even different rollback requests for the same channel, while
	// retaining a separate release-specific package mutation lock.
	unlockChannel, err := s.lockPackageMutation(ctx, "rollback-channel:"+p.ProjectID+":"+p.ProfileID+":"+p.Channel)
	if err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
	}
	defer unlockChannel()
	version := rollbackVersion0217(p, job.ID)
	releaseID := p.ProjectID + "-" + p.ProfileID + "-" + version
	unlockPackage, err := s.lockPackageMutation(ctx, "package:"+releaseID)
	if err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
	}
	defer unlockPackage()
	versions, err := s.Repo.ListVersions(p.ProjectID)
	if err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
	}
	var target, created *model.ReleaseVersion
	for i := range versions {
		v := &versions[i]
		if v.ID == p.TargetID {
			target = v
		}
		if v.ID == releaseID {
			created = v
		}
	}
	if target == nil || target.ProfileID != p.ProfileID || target.Channel != p.Channel || target.Version != p.ToVersion || target.Status != "published" {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback target is unavailable or not published")
	}
	md, err := manifestDigest0212(target.Manifest)
	if err != nil || md != p.TargetManifestDigest {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback source manifest drift")
	}
	if err = s.verifyManifestSignature(target.Manifest); err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, fmt.Errorf("rollback source signature: %w", err)
	}
	sourceFiles, err := s.Repo.ListFiles(p.ProjectID, target.ID)
	if err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
	}
	fd, err := artifactDigest0212(sourceFiles)
	if err != nil || fd != p.TargetArtifactDigest || len(sourceFiles) == 0 {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback source files drift")
	}
	if created != nil && created.Status == "published" {
		return *created, model.IntegrityCheckResult{}, nil
	}
	if created == nil {
		newRelease, err := s.Repo.CreateVersion(p.ProjectID, p.ProfileID, p.Channel, version)
		if err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
		created = &newRelease
	}
	if created.ProjectID != p.ProjectID || created.ProfileID != p.ProfileID || created.Channel != p.Channel || created.Version != version {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback release identity conflict")
	}
	files, err := s.Repo.ListFiles(p.ProjectID, created.ID)
	if err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
	}
	byPath := make(map[string]model.FileObject, len(files))
	for _, f := range files {
		byPath[f.Path] = f
	}
	// An interruption during copying is recovered by copying missing files only;
	// a mismatching existing entry is a conflict, never silently overwritten.
	for _, source := range sourceFiles {
		if existing, ok := byPath[source.Path]; ok {
			if existing.Size != source.Size || existing.SHA256 != source.SHA256 {
				return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback copied file changed unexpectedly")
			}
			continue
		}
		if err = s.workerAuthorized0217(ctx, job); err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
		reader, size, openErr := s.Storage.Open(p.ProjectID, target.ID, source.Path)
		if openErr != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, fmt.Errorf("rollback source storage: %w", openErr)
		}
		_, copied, saveErr := s.Storage.Save(p.ProjectID, created.ID, source.Path, reader)
		_ = reader.Close()
		if saveErr != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, saveErr
		}
		if copied != size || copied != source.Size {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback copy size mismatch")
		}
		if err = s.workerAuthorized0217(ctx, job); err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
		clone := source
		clone.ID = ""
		clone.VersionID = created.ID
		clone.URL = s.deliveryURL(p.ProjectID, created.ID, source.Path)
		if _, err = s.Repo.AddFile(clone); err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
	}
	files, err = s.Repo.ListFiles(p.ProjectID, created.ID)
	if err != nil || len(files) != len(sourceFiles) {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, errors.New("rollback incomplete file set")
	}
	if err = s.workerAuthorized0217(ctx, job); err != nil {
		return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
	}
	// Once signed, preserve that exact manifest on every retry; otherwise the
	// publish job would legitimately reject a changed payload digest.
	if created.Status == "draft" || s.verifyManifestSignature(created.Manifest) != nil {
		manifest := target.Manifest
		manifest.Version = version
		manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		manifest.Signature = nil
		manifest.Files = make([]model.ManifestFile, 0, len(files))
		for _, f := range files {
			manifest.Files = append(manifest.Files, model.ManifestFile{Path: f.Path, Size: f.Size, SHA256: f.SHA256, URL: f.URL, Required: f.Required, Executable: f.Executable, TargetOS: append([]string(nil), f.TargetOS...), Mirrors: append([]string(nil), f.Mirrors...)})
		}
		if err = validateCompatibilityManifest(manifest); err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
		signed, err := s.signManifest(manifest)
		if err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
		updated, err := s.Repo.UpdateVersionManifest(p.ProjectID, created.ID, signed)
		if err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
		created = &updated
		updated, err = s.Repo.UpdateVersionStatus(p.ProjectID, created.ID, "staged")
		if err != nil {
			return model.ReleaseVersion{}, model.IntegrityCheckResult{}, err
		}
		created = &updated
	}
	lookup := packageLookup{Release: *created, Files: files}
	// The check writes durable validation evidence and rechecks every file; a
	// recovered job must not assume that an earlier successful check is still fresh.
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/internal/rollback-integrity", nil)
	check, err := s.runPackageIntegrityCheck0212(request, lookup)
	if err != nil || check.Result != "passed" {
		if err == nil {
			err = errors.New("rollback integrity failed")
		}
		return model.ReleaseVersion{}, check, err
	}
	updated, err := s.lookupPackage(created.ID)
	if err != nil {
		return model.ReleaseVersion{}, check, err
	}
	return updated.Release, check, nil
}

// A completed rollback operation means either an immutable release has been
// published, or a runtime-validation-required release has been staged. It must
// never claim publication if the project's runtime policy prevents it.
func (s Server) runRollbackJob0217(ctx context.Context, cp repository.DurableControlPlane, job model.DurableJob, worker string) (map[string]any, error) {
	var p rollbackPayload0217
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "malformed rollback payload")
		return nil, err
	}
	release, check, err := s.stageRollback0217(ctx, job, p)
	if err != nil {
		if strings.HasPrefix(err.Error(), "authorization-revoked:") {
			_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusRevoked, err.Error())
			return nil, err
		}
		// Recoverable storage/DB/lease errors are retried with backoff; the target
		// digest and permissions are checked again before any new side effect.
		_, _ = cp.FailDurableJob(ctx, job.ID, job.LeaseToken, err.Error(), 2*time.Second)
		return nil, err
	}
	if release.Status == "published" {
		return map[string]any{"status": "rolled-back-as-new-validated-immutable-release", "projectId": p.ProjectID, "profileId": p.ProfileID, "channel": p.Channel, "targetVersion": p.ToVersion, "rollbackVersion": release.Version, "packageId": release.ID, "release": release}, nil
	}
	policy, err := s.Repo.GetProjectValidationPolicy(ctx, p.ProjectID)
	if err == nil && policy.RequiredLevel == "runtime" {
		return map[string]any{"status": "rollback-staged-runtime-validation-required", "projectId": p.ProjectID, "profileId": p.ProfileID, "channel": p.Channel, "targetVersion": p.ToVersion, "rollbackVersion": release.Version, "packageId": release.ID, "release": release, "integrity": check, "requiredValidationLevel": "runtime"}, nil
	}
	lookup := packageLookup{Release: release}
	lookup.Files, err = s.Repo.ListFiles(p.ProjectID, release.ID)
	if err != nil {
		_, _ = cp.FailDurableJob(ctx, job.ID, job.LeaseToken, err.Error(), 2*time.Second)
		return nil, err
	}
	if err = s.validatePublishEvidenceContext0213(ctx, lookup); err != nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, err.Error())
		return nil, err
	}
	if err = s.workerAuthorized0217(ctx, job); err != nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusRevoked, err.Error())
		return nil, err
	}
	if s.EventBus != nil {
		if err = s.EventBus.BeforeReleasePublish(ctx, job.ActorID, release); err != nil {
			_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "extension release publish rejected: "+err.Error())
			return nil, err
		}
		event := eventbus.PackagePayload{Action: "publish", Actor: job.ActorID, PackageID: release.ID, ProjectID: p.ProjectID, ProfileID: p.ProfileID, Channel: p.Channel, Version: release.Version, Status: release.Status}
		if err = s.EventBus.BeforePackagePublish(ctx, event); err != nil {
			_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "extension package publish rejected: "+err.Error())
			return nil, err
		}
	}
	md, err := manifestDigest0212(release.Manifest)
	if err != nil {
		return nil, err
	}
	fd, err := artifactDigest0212(lookup.Files)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(model.DurablePublishPayload{PackageID: release.ID, ExpectedManifestDigest: md, ExpectedArtifactDigest: fd, ExpectedStatus: release.Status})
	publishJob, _, err := cp.EnqueueDurableJob(ctx, model.DurableJob{Kind: durablePublishJobKind0213, ActorType: "user", ActorID: job.ActorID, Action: "release:publish", ProjectID: p.ProjectID, ResourceType: "package", ResourceID: release.ID, IdempotencyKey: "rollback-publish:" + job.ID, Payload: raw, MaxAttempts: 8}, 30*24*time.Hour)
	if err != nil {
		_, _ = cp.FailDurableJob(ctx, job.ID, job.LeaseToken, err.Error(), 2*time.Second)
		return nil, err
	}
	if publishJob.Status == model.DurableJobStatusPending {
		leased, leaseErr := cp.LeaseDurableJob(ctx, publishJob.ID, worker+":publish", 90*time.Second)
		if leaseErr == nil {
			_, _ = s.executeDurablePublishJob0213(ctx, cp, leased, worker+":publish")
		}
	}
	publishJob, err = cp.GetDurableJob(ctx, publishJob.ID)
	if err != nil {
		return nil, err
	}
	if publishJob.Status != model.DurableJobStatusSucceeded {
		if publishJob.Status == model.DurableJobStatusFailed || publishJob.Status == model.DurableJobStatusRevoked || publishJob.Status == model.DurableJobStatusDead {
			err = fmt.Errorf("rollback publish job %s: %s", publishJob.Status, publishJob.LastError)
			_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, err.Error())
			return nil, err
		}
		_, _ = cp.FailDurableJob(ctx, job.ID, job.LeaseToken, "waiting for durable publish job", time.Second)
		return nil, repository.ErrLeaseBusy
	}
	release, err = s.lookupRollbackRelease0217(release.ID)
	if err != nil {
		return nil, err
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: job.ActorID, Action: "channel:rollback", Target: job.ID + ":" + release.ID, JobID: job.ID, CorrelationID: job.ID, ReasonCode: "executed", CreatedAt: time.Now().UTC()})
	return map[string]any{"status": "rolled-back-as-new-validated-immutable-release", "projectId": p.ProjectID, "profileId": p.ProfileID, "channel": p.Channel, "targetVersion": p.ToVersion, "rollbackVersion": release.Version, "packageId": release.ID, "release": release, "jobId": publishJob.ID}, nil
}
func (s Server) lookupRollbackRelease0217(id string) (model.ReleaseVersion, error) {
	lookup, err := s.lookupPackage(id)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	return lookup.Release, nil
}
func (s Server) executeRollbackJob0217(ctx context.Context, cp repository.DurableControlPlane, job model.DurableJob, worker string) (model.DurableJob, error) {
	result, err := s.runRollbackJob0217(ctx, cp, job, worker)
	if err != nil {
		return model.DurableJob{}, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return model.DurableJob{}, err
	}
	journal, ok := s.Repo.(repository.OperationJournal)
	if !ok {
		return model.DurableJob{}, errors.New("operation journal unavailable")
	}
	return journal.CompleteOperationJob(ctx, job.ID, job.LeaseToken, raw)
}
func (s Server) rollbackExecute0217(w http.ResponseWriter, r *http.Request) {
	var req packageActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, 400, "invalid rollback request: "+err.Error())
		return
	}
	operation := operationRequest0217{Kind: durableRollbackKind0217, ProjectID: firstNonEmpty(req.ProjectID, queryDefault(r, "projectId", ""), queryDefault(r, "project", "")), ProfileID: firstNonEmpty(req.ProfileID, queryDefault(r, "profileId", "vanilla")), Channel: r.PathValue("channel"), ToVersion: firstNonEmpty(req.ToVersion, queryDefault(r, "toVersion", ""))}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	job, _, err := s.enqueueOperation0217(r, claims, operation)
	if err != nil {
		writeOperationError0217(w, err)
		return
	}
	cp, err := s.durableControlPlane0213()
	if err != nil {
		writeError(w, 503, err.Error())
		return
	}
	w.Header().Set("X-Correlation-ID", job.ID)
	w.Header().Set("Location", "/api/v1/operations/"+job.ID)
	if job.Status == model.DurableJobStatusSucceeded {
		var result any
		if json.Unmarshal(job.Result, &result) != nil {
			writeError(w, 500, "corrupt stored rollback result")
			return
		}
		writeJSON(w, 200, map[string]any{"apiVersion": apiContractVersion, "data": result})
		return
	}
	if job.Status == model.DurableJobStatusFailed || job.Status == model.DurableJobStatusDead || job.Status == model.DurableJobStatusRevoked {
		writeError(w, 409, "rollback job is "+job.Status+": "+job.LastError)
		return
	}
	worker := randomWorkerID0213("rollback-request")
	executionContext := context.WithoutCancel(r.Context())
	leased, err := cp.LeaseDurableJob(executionContext, job.ID, worker, 60*time.Minute)
	if err == nil {
		_, _ = s.executeRollbackJob0217(executionContext, cp, leased, worker)
	}
	latest, getErr := cp.GetDurableJob(executionContext, job.ID)
	if getErr != nil {
		writeError(w, 500, getErr.Error())
		return
	}
	if latest.Status == model.DurableJobStatusSucceeded {
		var result any
		if json.Unmarshal(latest.Result, &result) != nil {
			writeError(w, 500, "corrupt stored rollback result")
			return
		}
		status := 200
		if m, ok := result.(map[string]any); ok && m["status"] == "rollback-staged-runtime-validation-required" {
			status = 202
		}
		writeJSON(w, status, map[string]any{"apiVersion": apiContractVersion, "data": result})
		return
	}
	if latest.Status == model.DurableJobStatusFailed || latest.Status == model.DurableJobStatusDead || latest.Status == model.DurableJobStatusRevoked {
		writeError(w, 409, "rollback job is "+latest.Status+": "+latest.LastError)
		return
	}
	writeJSON(w, 202, map[string]any{"apiVersion": apiContractVersion, "data": map[string]any{"status": "rollback-queued", "job": publicOperation0217(latest), "correlationId": latest.ID}})
}
