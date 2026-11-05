package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// BackendLifecycle0289 отправляет односторонний запрос владельцу процесса. HTTP
// никогда не запускает команды, не посылает сигналы произвольным PID и не
// открывает оболочку.
type BackendLifecycle0289 struct {
	InstanceID string
	StartedAt  time.Time
	Enabled    bool
	mu         sync.Mutex
	requested  bool
	shutdown   chan struct{}
}

func NewBackendLifecycle0289(enabled bool) (*BackendLifecycle0289, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &BackendLifecycle0289{InstanceID: hex.EncodeToString(b[:]), StartedAt: time.Now().UTC(), Enabled: enabled, shutdown: make(chan struct{}, 1)}, nil
}
func (l *BackendLifecycle0289) RestartRequested() <-chan struct{} { return l.shutdown }
func (l *BackendLifecycle0289) ScheduleRestart() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.Enabled || l.requested {
		return false
	}
	l.requested = true
	// Задержка не позволяет закрыть HTTP-соединение до отправки ответа 202.
	// Корректное завершение HTTP в main дожидается выполняющихся запросов.
	go func() { time.Sleep(350 * time.Millisecond); l.shutdown <- struct{}{} }()
	return true
}
func (l *BackendLifecycle0289) IsDraining() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.requested
}

// Без перезапуска обновляется только конфигурация без секретов. Секреты
// развёртывания, ключи подписи, адрес прослушивания HTTP и подключение к БД требуют
// контролируемого перезапуска.
func (s Server) backendConfigReload0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.OperationalConfigStore)
	if !ok {
		writeError(w, 503, "Хранилище эксплуатационной конфигурации недоступно")
		return
	}
	revision, err := store.GetOperationalConfig(r.Context())
	if err != nil {
		writeError(w, 503, "Хранилище эксплуатационной конфигурации недоступно")
		return
	}
	if err := revision.Settings.Validate(); err != nil {
		writeError(w, 503, "Некорректная эксплуатационная конфигурация")
		return
	}
	s.audit(r, s.adminActor(r), "backend:config:reload", "revision")
	writeJSON(w, 200, map[string]any{"appliedRevision": revision.Revision, "reloadScope": "dynamic-operational-settings", "restartRequiredForStaticSettings": true})
}

func (s Server) backendInstanceStatus0289(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	l := s.State.BackendLifecycle0289
	if l == nil {
		writeError(w, 503, "Жизненный цикл Backend не инициализирован")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	checks := map[string]string{}
	if checker, ok := s.Repo.(interface{ Health(context.Context) error }); ok {
		if err := checker.Health(ctx); err != nil {
			checks["repository"] = "unavailable"
		} else {
			checks["repository"] = "ok"
		}
	} else {
		checks["repository"] = "not_available"
	}
	if s.Storage != nil {
		if err := s.Storage.Health(ctx); err != nil {
			checks["storage"] = "unavailable"
		} else {
			checks["storage"] = "ok"
		}
	}
	revision := int64(0)
	if store, ok := s.Repo.(repository.OperationalConfigStore); ok {
		if value, err := store.GetOperationalConfig(ctx); err == nil {
			revision = value.Revision
		} else {
			checks["operationalSettings"] = "unavailable"
		}
	}
	recent := backendRecentClients0289(s.State.AuthSessions.listFiltered118("", "", "active", ""), time.Now().UTC(), 5*time.Minute)
	launcherCount := 0
	if store, ok := s.Repo.(repository.BackendMinecraftClientStore0289); ok {
		if clients, err := store.ListRecentMinecraftClients0289(ctx, time.Now().UTC(), 5*time.Minute); err == nil {
			launcherCount = len(clients)
		} else {
			checks["launcherSessions"] = "unavailable"
		}
	}
	writeJSON(w, 200, map[string]any{"instanceId": l.InstanceID, "version": s.Version, "commit": s.SourceCommit,
		"startedAt": l.StartedAt, "uptimeSeconds": int(time.Since(l.StartedAt).Seconds()),
		"supervisedRestartEnabled": l.Enabled, "draining": l.IsDraining(),
		"environment": s.Config.Environment, "storage": s.Storage.Driver(), "repository": s.Config.RepositoryDriver,
		"checks": checks, "operationalConfigRevision": revision, "recentAdminSessions": len(recent), "recentLauncherSessions": launcherCount,
		"sessionMetric": "active auth / launcher sessions observed within 5 minutes (not open sockets)"})
}

type backendClient0289 struct {
	SessionID  string    `json:"sessionId"`
	UserID     string    `json:"userId"`
	Provider   string    `json:"provider"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

func backendRecentClients0289(sessions []authSessionRecord, now time.Time, fresh time.Duration) []backendClient0289 {
	out := make([]backendClient0289, 0)
	for _, it := range sessions {
		if it.Status != "active" || !it.ExpiresAt.After(now) || it.LastSeenAt.After(now.Add(time.Minute)) || now.Sub(it.LastSeenAt) > fresh {
			continue
		}
		out = append(out, backendClient0289{SessionID: it.ID, UserID: it.UserID, Provider: it.Provider, LastSeenAt: it.LastSeenAt, ExpiresAt: it.ExpiresAt})
		if len(out) == 100 {
			break
		}
	}
	return out
}
func (s Server) backendConnectedClients0289(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()
	admins := backendRecentClients0289(s.State.AuthSessions.listFiltered118("", "", "active", ""), now, 5*time.Minute)
	store, ok := s.Repo.(repository.BackendMinecraftClientStore0289)
	if !ok {
		writeError(w, 503, "Хранилище сессий лаунчера недоступно")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	launchers, err := store.ListRecentMinecraftClients0289(ctx, now, 5*time.Minute)
	if err != nil {
		writeError(w, 503, "Сессии лаунчера недоступны")
		return
	}
	writeJSON(w, 200, map[string]any{"adminSessions": admins, "launcherSessions": launchers,
		"adminCount": len(admins), "launcherCount": len(launchers), "sampledAt": now, "freshnessSeconds": 300,
		"source":     "auth_sessions.last_seen_at / minecraft_sessions.last_seen_at",
		"limitation": "recently observed authorization sessions, not guaranteed connected sockets or online Minecraft players", "limitPerType": 100})
}

type backendRestartRequest0289 struct {
	InstanceID   string `json:"instanceId"`
	Confirmation string `json:"confirmation"`
}

func (s Server) backendRestart0289(w http.ResponseWriter, r *http.Request) {
	l := s.State.BackendLifecycle0289
	// Нельзя завершать сервер, если его работу не контролирует явно настроенная служба
	// перезапуска.
	if l == nil || !l.Enabled {
		writeError(w, 503, "Для перезапуска необходимо явно настроить внешний управляющий процесс")
		return
	}
	journal, ok := s.Repo.(repository.BackendRestartJournal)
	if !ok {
		writeError(w, 503, "Для перезапуска необходим надёжный журнал команд PostgreSQL")
		return
	}
	if os.Getenv("LAUNCHER_BACKEND_SUPERVISED_RESTART") != "true" {
		writeError(w, 503, "Внешний контролируемый перезапуск не включён")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Ошибка аутентификации")
		return
	}
	if _, err = repository.BackendRestartKey0289(claims.Sub, key); err != nil {
		writeError(w, 400, "Заголовок Idempotency-Key должен содержать 16–128 символов ASCII: буквы, цифры, дефис, подчёркивание или точку")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	var req backendRestartRequest0289
	if err = dec.Decode(&req); err != nil {
		writeError(w, 400, "Некорректный запрос перезапуска")
		return
	}
	var trailing any
	if err = dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, 400, "Неожиданные данные в конце запроса")
		return
	}
	if req.InstanceID != l.InstanceID || req.Confirmation != "RESTART "+l.InstanceID {
		writeError(w, 409, "Идентичность среды выполнения или явное подтверждение не совпадает")
		return
	}
	rec, claimed, err := journal.ClaimBackendRestart0289(r.Context(), claims.Sub, key, l.InstanceID)
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, 409, "Перезапуск этой среды выполнения уже принят с другим ключом идемпотентности")
		return
	}
	if err != nil {
		writeError(w, 503, "Не удалось сохранить запрос перезапуска в постоянном хранилище")
		return
	}
	if !claimed {
		writeJSON(w, 200, map[string]any{"operation": rec, "rescheduled": false, "note": "duplicate key never repeats the external effect"})
		return
	}
	s.audit(r, claims.Email, "backend:restart:accepted", rec.ID)
	if !l.ScheduleRestart() {
		// Запрос уже сохранён как принятый, но ещё не выполнен. Никогда не сообщайте
		// об успешном завершении.
		writeJSON(w, 202, map[string]any{"operation": rec, "state": "indeterminate", "note": "Перезапуск уже выполняется; проверьте супервизор и идентификатор экземпляра"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 202, map[string]any{"operation": rec, "state": "accepted", "note": "После корректного завершения процесса его должен перезапустить внешний супервизор"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// Это сохраняемые уведомления для конкретных пользователей, которые получают
// авторизованные API-клиенты. Это НЕ рассылки ServerBridge и не команды хосту.
type backendNoticeWrite0289 struct {
	UserID  string `json:"userId"`
	Message string `json:"message"`
}

func (s Server) backendSendNotice0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.BackendNoticeStore0289)
	if !ok {
		writeError(w, 503, "Постоянное хранилище уведомлений серверной части недоступно")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Пользователь не аутентифицирован")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if _, err = repository.BackendRestartKey0289(claims.Sub, key); err != nil {
		writeError(w, 400, "Некорректный Idempotency-Key")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	var req backendNoticeWrite0289
	if err = dec.Decode(&req); err != nil {
		writeError(w, 400, "Некорректный JSON уведомления")
		return
	}
	var extra any
	if err = dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, 400, "Неожиданные поля JSON")
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	req.Message = strings.TrimSpace(req.Message)
	if err = repository.ValidateBackendNotice0289(req.UserID, req.Message); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if user, err := s.Repo.GetUser(req.UserID); err != nil || user.Status != "active" {
		writeError(w, 404, "Получатель не найден или неактивен")
		return
	}
	notice, created, err := store.EnqueueBackendNotice0289(r.Context(), claims.Sub, key, req.UserID, req.Message)
	if errors.Is(err, repository.ErrConflict) {
		writeError(w, 409, "Ключ идемпотентности уже использован для другого уведомления")
		return
	}
	if err != nil {
		writeError(w, 503, "Не удалось сохранить уведомление")
		return
	}
	if created {
		s.audit(r, claims.Email, "backend:notice:queued", notice.ID)
	}
	writeJSON(w, 200, map[string]any{"notice": notice, "queued": created, "delivery": "recipient polls authenticated inbox and acknowledges"})
}
func (s Server) backendInbox0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.BackendNoticeStore0289)
	if !ok {
		writeError(w, 503, "Входящая очередь серверной части недоступна")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Пользователь не аутентифицирован")
		return
	}
	items, err := store.ListBackendNotices0289(r.Context(), claims.Sub)
	if err != nil {
		writeError(w, 503, "Входящая очередь серверной части недоступна")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"items": items, "delivery": "durable-poll", "ackRequired": true})
}
func (s Server) backendNoticeAck0289(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.BackendNoticeStore0289)
	if !ok {
		writeError(w, 503, "Входящая очередь серверной части недоступна")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Пользователь не аутентифицирован")
		return
	}
	id := r.PathValue("noticeId")
	if len(id) != 64 {
		writeError(w, 404, "Уведомление не найдено")
		return
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			writeError(w, 404, "Уведомление не найдено")
			return
		}
	}
	success, err := store.AckBackendNotice0289(r.Context(), claims.Sub, id)
	if err != nil {
		writeError(w, 503, "Не удалось подтвердить получение уведомления")
		return
	}
	if !success {
		writeError(w, 404, "Уведомление не найдено или уже подтверждено")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "acknowledged", "id": id})
}
