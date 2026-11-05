package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type managedWizardRequest02910 struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Config json.RawMessage `json:"config"`
	Reason string          `json:"reason"`
}
type managedActivationRequest02910 struct {
	Revision               int64  `json:"revision"`
	ExpectedActiveRevision int64  `json:"expectedActiveRevision"`
	Reason                 string `json:"reason"`
}

func decodeWizardBody02910(w http.ResponseWriter, r *http.Request, out any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 48<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("Обнаружены лишние данные после: запрос")
	}
	return nil
}
func wizardStore02910(s Server) (repository.ManagedProviderStore02910, bool) {
	v, ok := s.Repo.(repository.ManagedProviderStore02910)
	return v, ok
}
func (s Server) wizardList02910(w http.ResponseWriter, r *http.Request) {
	store, ok := wizardStore02910(s)
	if !ok {
		writeError(w, 503, "Управление провайдерами недоступно")
		return
	}
	heads, err := store.ListManagedProviders02910(r.Context())
	if err != nil {
		writeError(w, 503, "Управление провайдерами недоступно")
		return
	}
	if heads == nil {
		heads = []repository.ManagedProviderHead02910{}
	}
	// Эти ревизии содержат только проверенные конфигурации без секретов со ссылками на
	// окружение.
	writeJSON(w, 200, map[string]any{"items": heads})
}
func wizardRevision02910(req managedWizardRequest02910) repository.ManagedProviderRevision02910 {
	return repository.ManagedProviderRevision02910{ID: strings.ToLower(strings.TrimSpace(req.ID)), Kind: strings.ToLower(strings.TrimSpace(req.Kind)), Config: req.Config, Reason: strings.TrimSpace(req.Reason)}
}
func (s Server) wizardTest02910(w http.ResponseWriter, r *http.Request) {
	var req managedWizardRequest02910
	if err := decodeWizardBody02910(w, r, &req); err != nil {
		writeError(w, 400, "Некорректный запрос")
		return
	}
	v := wizardRevision02910(req)
	if v.Reason == "" {
		v.Reason = "connection diagnostics"
	}
	if err := validateManagedSecrets02910(v); err != nil {
		writeError(w, 400, "Небезопасная или некорректная конфигурация провайдера")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	probe, err := createManagedProvider02910(ctx, v, s.ExtensionHost)
	if err != nil {
		writeJSON(w, 422, map[string]any{"healthy": false, "detail": "live configuration, credential references, mapping or provider health failed"})
		return
	}
	defer closeManaged02910(probe.Connector)
	writeJSON(w, 200, map[string]any{"healthy": true, "metadata": probe.Metadata, "mapping": probe.Mapping, "credentialReferencesVerified": true, "note": "Connectivity proves neither account ownership nor Microsoft Minecraft entitlement"})
}
func (s Server) wizardDraft02910(w http.ResponseWriter, r *http.Request) {
	var req managedWizardRequest02910
	if err := decodeWizardBody02910(w, r, &req); err != nil {
		writeError(w, 400, "Некорректный запрос")
		return
	}
	v := wizardRevision02910(req)
	if err := validateManagedSecrets02910(v); err != nil {
		writeError(w, 400, "Небезопасная или некорректная конфигурация провайдера")
		return
	}
	store, ok := wizardStore02910(s)
	if !ok {
		writeError(w, 503, "Управление провайдерами недоступно")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	v.Actor = claims.Sub
	saved, err := store.SaveManagedProviderDraft02910(r.Context(), v)
	if err != nil {
		writeError(w, 503, "provider draft could not be saved")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth-provider:draft", Target: v.ID + ":" + strconv.FormatInt(saved.Revision, 10), CreatedAt: time.Now().UTC()})
	writeJSON(w, 201, saved)
}
func (s Server) wizardActivate02910(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.PathValue("providerId")))
	var req managedActivationRequest02910
	if err := decodeWizardBody02910(w, r, &req); err != nil || req.Revision < 0 || req.ExpectedActiveRevision < 0 || len(strings.TrimSpace(req.Reason)) < 3 || len(req.Reason) > 500 || strings.ContainsAny(req.Reason, "\r\n\x00") {
		writeError(w, 400, "invalid revision or reason")
		return
	}
	store, ok := wizardStore02910(s)
	if !ok {
		writeError(w, 503, "Управление провайдерами недоступно")
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "Требуется авторизация")
		return
	}
	heads, err := store.ListManagedProviders02910(r.Context())
	if err != nil {
		writeError(w, 503, "Управление провайдерами недоступно")
		return
	}
	var head *repository.ManagedProviderHead02910
	for i := range heads {
		if heads[i].ID == id {
			head = &heads[i]
			break
		}
	}
	if head == nil {
		writeError(w, 404, "unknown provider")
		return
	}
	if head.ActiveRevision != req.ExpectedActiveRevision {
		writeError(w, 409, "active revision changed; reload before applying")
		return
	}
	// Кандидат проверяется НА ЖИВОМ провайдере до переключения устойчивого указателя. Это
	// также проверяет введённые из окружения учётные данные без их раскрытия.
	if req.Revision != 0 {
		var candidate *repository.ManagedProviderRevision02910
		for i := range head.Revisions {
			if head.Revisions[i].Revision == req.Revision {
				candidate = &head.Revisions[i]
				break
			}
		}
		if candidate == nil {
			writeError(w, 404, "unknown revision")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		probe, probeErr := createManagedProvider02910(ctx, *candidate, s.ExtensionHost)
		cancel()
		if probeErr != nil {
			writeError(w, 422, "provider connection or SDK conformance failed; active settings unchanged")
			return
		}
		// Не разрешайте провайдеру из БД переопределять источник, настроенный через env.
		if _, exists := s.Federation.Connector(id); exists && s.Federation.ManagedRevision(id) == 0 {
			_ = closeManaged02910(probe.Connector)
			writeError(w, 409, "provider is managed by bootstrap configuration")
			return
		}
		_ = closeManaged02910(probe.Connector)
	}
	changed, err := store.ActivateManagedProvider02910(r.Context(), id, req.Revision, req.ExpectedActiveRevision, claims.Sub, strings.TrimSpace(req.Reason))
	if errors.Is(err, repository.ErrManagedProviderConflict02910) {
		writeError(w, 409, "active revision changed; reload before applying")
		return
	}
	if errors.Is(err, repository.ErrManagedProviderMissing02910) {
		writeError(w, 404, "unknown provider or revision")
		return
	}
	if err != nil {
		writeError(w, 503, "activation transaction failed")
		return
	}
	// Загружайте сейчас, а не только при следующем запросе авторизации. Если
	// другой узел не может достичь провайдера, его middleware авторизации
	// отказывает.
	syncErr := s.syncManagedProviders02910(r.Context())
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "auth-provider:activate", Target: id + ":" + strconv.FormatInt(req.Revision, 10), CreatedAt: time.Now().UTC()})
	if syncErr != nil {
		writeError(w, 503, "active revision committed but runtime could not synchronize; rollback through Admin")
		return
	}
	writeJSON(w, 200, changed)
}

// Текущее состояние основано на настоящем работающем коннекторе, а не сохранённых
// метаданных. Текст ошибок здоровья никогда не возвращается: драйверы иногда включают
// DSN.
func (s Server) wizardStatus02910(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if err := s.syncManagedProviders02910(ctx); err != nil {
		writeError(w, 503, "managed auth providers cannot be synchronized")
		return
	}
	type health struct {
		ID       string `json:"id"`
		Healthy  bool   `json:"healthy"`
		Revision int64  `json:"revision"`
	}
	records := []health{}
	for _, id := range s.Federation.ManagedIDs() {
		c, ok := s.Federation.Connector(id)
		if !ok {
			continue
		}
		healthCtx, finish := context.WithTimeout(ctx, 3*time.Second)
		err := c.Health(healthCtx)
		finish()
		records = append(records, health{ID: id, Healthy: err == nil, Revision: s.Federation.ManagedRevision(id)})
	}
	writeJSON(w, 200, map[string]any{"items": records})
}
