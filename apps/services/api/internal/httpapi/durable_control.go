package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/authorization"
	"gitflic.ru/skif4er/launcher/services/api/internal/eventbus"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

const durablePublishJobKind0213 = "package-publish"

var errDurableAuthorizationRevoked0213 = errors.New("Разрешение на публикацию отозвано")

func randomWorkerID0213(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + fmt.Sprintf("-%d", time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func (s Server) durableControlPlane0213() (repository.DurableControlPlane, error) {
	cp, ok := s.Repo.(repository.DurableControlPlane)
	if !ok {
		return nil, errors.New("Репозиторий не поддерживает отказоустойчивый контур управления")
	}
	return cp, nil
}

// StartDurableControlPlane0213 запускает восстановление сохранённых заданий публикации
// и транзакционную доставку outbox. Его можно включать на всех репликах API: PostgreSQL
// SKIP LOCKED и аренды допускают одного активного исполнителя для каждого элемента.
func (s Server) StartDurableControlPlane0213(parent context.Context) (context.CancelFunc, error) {
	return s.StartDurableControlPlaneWithReadiness0455(parent, nil)
}

// StartDurableControlPlaneWithReadiness0455 отслеживает успешные устойчивые опросы, а
// не только работающую goroutine. Функция отмены дожидается операций в процессе
// выполнения.
func (s Server) StartDurableControlPlaneWithReadiness0455(parent context.Context, last *atomic.Int64) (context.CancelFunc, error) {
	cp, err := s.durableControlPlane0213()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	worker := randomWorkerID0213("worker")
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			if err := s.runDurableTick0213(ctx, cp, worker); err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Printf("Ошибка: «durable control-plane tick»: %v", err)
				}
			} else if last != nil {
				last.Store(time.Now().UnixNano())
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			log.Printf("Превышено время ожидания остановки рабочего процесса; сроки аренды истекут по TTL PostgreSQL")
		}
	}, nil
}

func (s Server) runDurableTick0213(ctx context.Context, cp repository.DurableControlPlane, worker string) error {
	jobs, err := cp.LeaseDurableJobs(ctx, durablePublishJobKind0213, worker, 8, 90*time.Second)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if _, err := s.executeDurablePublishJob0213(ctx, cp, job, worker); err != nil {
			log.Printf("Ошибка задания отказоустойчивой публикации %s: %v", job.ID, err)
		}
	}
	rollbacks, err := cp.LeaseDurableJobs(ctx, durableRollbackKind0217, worker, 4, 60*time.Minute)
	if err != nil {
		return err
	}
	for _, job := range rollbacks {
		if _, runErr := s.executeRollbackJob0217(ctx, cp, job, worker); runErr != nil {
			log.Printf("Ошибка задания отказоустойчивого отката %s: %v", job.ID, runErr)
		}
	}
	return s.drainOutbox0213(ctx, cp, worker, 32)
}

func publishPayloadDigest0213(payload model.DurablePublishPayload) (json.RawMessage, string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func (s Server) enqueuePublishJob0213(r *http.Request, lookup packageLookup) (model.DurableJob, bool, error) {
	cp, err := s.durableControlPlane0213()
	if err != nil {
		return model.DurableJob{}, false, err
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	manifestDigest, err := manifestDigest0212(lookup.Release.Manifest)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	artifactDigest, err := artifactDigest0212(lookup.Files)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	head, err := s.channelHead0228(r.Context(), lookup.Release.ProjectID, lookup.Release.ProfileID, lookup.Release.Channel)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	expected := head.Revision
	if rawMatch := strings.TrimSpace(r.Header.Get("If-Match")); rawMatch != "" {
		supplied, parseErr := strconv.ParseInt(strings.Trim(rawMatch, `"`), 10, 64)
		if parseErr != nil || supplied != expected {
			return model.DurableJob{}, false, repository.ErrConflict
		}
	}
	payload := model.DurablePublishPayload{PackageID: lookup.Release.ID, ExpectedManifestDigest: manifestDigest, ExpectedArtifactDigest: artifactDigest, ExpectedStatus: lookup.Release.Status, ExpectedHeadRevision: &expected}
	raw, _, err := publishPayloadDigest0213(payload)
	if err != nil {
		return model.DurableJob{}, false, err
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		idempotencyKey = "auto:" + claims.Sub + ":" + lookup.Release.ID + ":" + manifestDigest
	}
	if len(idempotencyKey) > 240 {
		return model.DurableJob{}, false, errors.New("Заголовок Idempotency-Key слишком длинный")
	}
	job := model.DurableJob{
		Kind:           durablePublishJobKind0213,
		ActorType:      "user",
		ActorID:        claims.Sub,
		Action:         "release:publish",
		ProjectID:      lookup.Release.ProjectID,
		ResourceType:   "package",
		ResourceID:     lookup.Release.ID,
		IdempotencyKey: idempotencyKey,
		Payload:        raw,
		MaxAttempts:    8,
	}
	return cp.EnqueueDurableJob(r.Context(), job, 7*24*time.Hour)
}

func (s Server) publishDurably0213(r *http.Request, lookup packageLookup) (model.ReleaseVersion, model.DurableJob, bool, error) {
	job, _, err := s.enqueuePublishJob0213(r, lookup)
	if err != nil {
		return model.ReleaseVersion{}, model.DurableJob{}, false, err
	}
	if job.Status == model.DurableJobStatusSucceeded {
		current, lookupErr := s.lookupPackage(job.ResourceID)
		if lookupErr != nil {
			return model.ReleaseVersion{}, job, false, lookupErr
		}
		return current.Release, job, false, nil
	}
	if job.Status == model.DurableJobStatusRevoked || job.Status == model.DurableJobStatusFailed || job.Status == model.DurableJobStatusDead {
		return model.ReleaseVersion{}, job, false, fmt.Errorf("Задание отказоустойчивой публикации имеет статус %s: %s", job.Status, job.LastError)
	}
	cp, err := s.durableControlPlane0213()
	if err != nil {
		return model.ReleaseVersion{}, job, false, err
	}
	worker := randomWorkerID0213("request")
	leased, err := cp.LeaseDurableJob(r.Context(), job.ID, worker, 90*time.Second)
	if errors.Is(err, repository.ErrLeaseBusy) {
		return model.ReleaseVersion{}, job, true, nil
	}
	if errors.Is(err, repository.ErrImmutable) {
		latest, getErr := cp.GetDurableJob(r.Context(), job.ID)
		if getErr == nil && latest.Status == model.DurableJobStatusSucceeded {
			current, lookupErr := s.lookupPackage(job.ResourceID)
			if lookupErr == nil {
				return current.Release, latest, false, nil
			}
		}
		return model.ReleaseVersion{}, latest, false, err
	}
	if err != nil {
		return model.ReleaseVersion{}, job, false, err
	}
	release, err := s.executeDurablePublishJob0213(r.Context(), cp, leased, worker)
	latest, _ := cp.GetDurableJob(r.Context(), job.ID)
	if err != nil {
		return model.ReleaseVersion{}, latest, false, err
	}
	_ = s.drainOutbox0213(r.Context(), cp, worker, 8)
	return release, latest, false, nil
}

func (s Server) executeDurablePublishJob0213(ctx context.Context, cp repository.DurableControlPlane, job model.DurableJob, worker string) (model.ReleaseVersion, error) {
	var payload model.DurablePublishPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "Недопустимые данные задания публикации")
		return model.ReleaseVersion{}, err
	}
	// Отказывайте по умолчанию устаревшим заданиям без зафиксированного head;
	// обнаруживайте устаревшие задания заранее, сохраняя CAS репозитория последней
	// границей конкуренции.
	if payload.ExpectedHeadRevision == nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "В задании публикации отсутствует текущая ревизия канала")
		return model.ReleaseVersion{}, repository.ErrConflict
	}
	if payload.PackageID != job.ResourceID || payload.ExpectedManifestDigest == "" || payload.ExpectedArtifactDigest == "" {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "Несовпадение идентификаторов данных задания публикации")
		return model.ReleaseVersion{}, errors.New("Несовпадение: «publish job payload identity»")
	}

	decision := s.authorizationService().Authorize(ctx,
		authorization.Actor{Kind: authorization.ActorUser, ID: job.ActorID},
		job.Action,
		authorization.Scope{Kind: authorization.ScopeProject, ProjectID: job.ProjectID},
		authorization.Resource{Kind: job.ResourceType, ID: job.ResourceID, ProjectID: job.ProjectID},
	)
	if !decision.Allowed {
		reason := "authorization-revoked:" + decision.ReasonCode
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusRevoked, reason)
		return model.ReleaseVersion{}, fmt.Errorf("%w: %s", errDurableAuthorizationRevoked0213, decision.ReasonCode)
	}

	scopeKey := "package:" + job.ResourceID
	lease, err := cp.AcquireDurableScopeLease(ctx, scopeKey, worker+":"+job.ID, 2*time.Minute)
	if err != nil {
		if errors.Is(err, repository.ErrLeaseBusy) {
			_, _ = cp.FailDurableJob(ctx, job.ID, job.LeaseToken, "package mutation lease busy", 750*time.Millisecond)
		}
		return model.ReleaseVersion{}, err
	}
	defer func() { _ = cp.ReleaseDurableScopeLease(context.Background(), scopeKey, lease.LeaseToken) }()

	lookup, err := s.lookupPackage(job.ResourceID)
	if err != nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "Пакет не найден")
		return model.ReleaseVersion{}, err
	}
	manifestDigest, err := manifestDigest0212(lookup.Release.Manifest)
	if err != nil || manifestDigest != payload.ExpectedManifestDigest {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "manifest changed after publish enqueue")
		if err == nil {
			err = repository.ErrConflict
		}
		return model.ReleaseVersion{}, err
	}
	artifactDigest, err := artifactDigest0212(lookup.Files)
	if err != nil || artifactDigest != payload.ExpectedArtifactDigest {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "package files changed after publish enqueue")
		if err == nil {
			err = repository.ErrConflict
		}
		return model.ReleaseVersion{}, err
	}
	head, err := s.channelHead0228(ctx, lookup.Release.ProjectID, lookup.Release.ProfileID, lookup.Release.Channel)
	if err != nil {
		return model.ReleaseVersion{}, err
	}
	if head.Revision != *payload.ExpectedHeadRevision {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "channel head revision changed after publication was queued")
		return model.ReleaseVersion{}, repository.ErrConflict
	}
	if err := s.validatePublishEvidenceContext0213(ctx, lookup); err != nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "Подтверждение публикации больше недействительно: "+err.Error())
		return model.ReleaseVersion{}, err
	}
	if err := s.checkGameReleasePublishGeneration02311(lookup.Release); err != nil {
		return model.ReleaseVersion{}, err
	}
	if err := s.verifyManifestSignature(lookup.Release.Manifest); err != nil {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "Подпись манифеста больше недействительна")
		return model.ReleaseVersion{}, err
	}

	// Авторизация намеренно проверяется повторно прямо перед необратимой
	// фиксацией в БД. Отзыв роли или сервисного токена во время проверки
	// свидетельств и подписей всё равно должен остановить задание.
	decision = s.authorizationService().Authorize(ctx,
		authorization.Actor{Kind: authorization.ActorUser, ID: job.ActorID},
		job.Action,
		authorization.Scope{Kind: authorization.ScopeProject, ProjectID: job.ProjectID},
		authorization.Resource{Kind: job.ResourceType, ID: job.ResourceID, ProjectID: job.ProjectID},
	)
	if !decision.Allowed {
		reason := "authorization-revoked-before-commit:" + decision.ReasonCode
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusRevoked, reason)
		return model.ReleaseVersion{}, fmt.Errorf("%w: %s", errDurableAuthorizationRevoked0213, decision.ReasonCode)
	}

	// После всех проверок авторизации и целостности выдавайте устойчивый
	// одноразовый допуск на пять минут. Устаревшее задание никогда не получает
	// повторно используемый токен.
	stableToken := ""
	if repository.IsStableChannel0341(lookup.Release.Channel) {
		token, coverage, gateErr := s.issueStablePermit03411(ctx, lookup)
		if gateErr != nil {
			reason := "Обязательные целевые среды Runtime отсутствуют, завершились ошибкой или не дали определённого результата: " + fmt.Sprint(coverage.TargetBlockers) + ": " + gateErr.Error()
			s.Repo.AddAuditEvent(model.AuditEvent{Actor: job.ActorID, Action: "release:publish-blocked", Target: lookup.Release.ID, JobID: job.ID, ReasonCode: "stable_runtime_targets_incomplete_03411", CreatedAt: time.Now().UTC()})
			_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, reason)
			return model.ReleaseVersion{}, gateErr
		}
		stableToken = token
	}
	release, err := cp.CommitDurablePublish(ctx, model.DurablePublishCommit{
		StableGateToken03411:   stableToken,
		JobID:                  job.ID,
		JobLeaseToken:          job.LeaseToken,
		ScopeKey:               scopeKey,
		ScopeLeaseToken:        lease.LeaseToken,
		ScopeFencingToken:      lease.FencingToken,
		ExpectedManifestDigest: payload.ExpectedManifestDigest,
		ExpectedArtifactDigest: payload.ExpectedArtifactDigest,
		ExpectedStatus:         payload.ExpectedStatus,
		ExpectedHeadRevision:   payload.ExpectedHeadRevision,
		ActorID:                job.ActorID,
	})
	if errors.Is(err, repository.ErrConflict) {
		_, _ = cp.TerminateDurableJob(ctx, job.ID, job.LeaseToken, model.DurableJobStatusFailed, "publish CAS conflict: channel head or package changed")
	}
	return release, err
}

func (s Server) durableJobGet0213(w http.ResponseWriter, r *http.Request) {
	cp, err := s.durableControlPlane0213()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	job, err := cp.GetDurableJob(r.Context(), r.PathValue("jobId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "job не найден")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "требуется действительный Bearer-токен")
		return
	}
	if claims.Sub != job.ActorID {
		decision := s.authorizationService().Authorize(r.Context(), authorization.Actor{Kind: authorization.ActorUser, ID: claims.Sub}, "project:read", authorization.Scope{Kind: authorization.ScopeProject, ProjectID: job.ProjectID}, authorization.Resource{Kind: job.ResourceType, ID: job.ResourceID, ProjectID: job.ProjectID})
		if !decision.Allowed {
			writeError(w, http.StatusNotFound, "job не найден")
			return
		}
	}
	w.Header().Set("X-Correlation-ID", job.ID)
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": apiContractVersion, "data": job})
}

type publishOutboxPayload0213 struct {
	PackageID string `json:"packageId"`
	ProjectID string `json:"projectId"`
	ProfileID string `json:"profileId"`
	Channel   string `json:"channel"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	ActorID   string `json:"actorId"`
}

func (s Server) drainOutbox0213(ctx context.Context, cp repository.DurableControlPlane, worker string, limit int) error {
	events, err := cp.ClaimOutboxEvents(ctx, worker, limit, 60*time.Second)
	if err != nil {
		return err
	}
	for _, out := range events {
		if err := s.deliverOutboxEvent0213(ctx, out); err != nil {
			backoff := time.Second * time.Duration(1<<minInt0213(out.AttemptCount, 8))
			_ = cp.FailOutboxEvent(ctx, out.ID, out.LeaseToken, err.Error(), backoff)
			continue
		}
		if err := cp.CompleteOutboxEvent(ctx, out.ID, out.LeaseToken); err != nil {
			return err
		}
	}
	return nil
}

func minInt0213(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s Server) deliverOutboxEvent0213(ctx context.Context, out model.DurableOutboxEvent) error {
	if s.EventBus == nil {
		return nil
	}
	var p publishOutboxPayload0213
	if err := json.Unmarshal(out.Payload, &p); err != nil {
		return err
	}
	switch out.EventType {
	case "package.published":
		return s.EventBus.PackageEvent(ctx, out.EventType, eventbus.PackagePayload{Action: "publish", Actor: p.ActorID, PackageID: p.PackageID, ProjectID: p.ProjectID, ProfileID: p.ProfileID, Channel: p.Channel, Version: p.Version, Status: p.Status})
	case "release.published":
		lookup, err := s.lookupPackage(p.PackageID)
		if err != nil {
			return err
		}
		return s.EventBus.ReleasePublished(ctx, p.ActorID, lookup.Release)
	default:
		return fmt.Errorf("Не поддерживается: «durable outbox event» %q", out.EventType)
	}
}
