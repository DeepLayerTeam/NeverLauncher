package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s Server) operationalStore02111(w http.ResponseWriter) (repository.OperationalConfigStore, bool) {
	store, ok := s.Repo.(repository.OperationalConfigStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "хранилище конфигурации недоступно")
		return nil, false
	}
	return store, true
}
func (s Server) operationalSettings02111(r *http.Request) (repository.OperationalConfig, error) {
	store, ok := s.Repo.(repository.OperationalConfigStore)
	if !ok {
		return repository.OperationalConfig{}, errors.New("config store unavailable")
	}
	revision, err := store.GetOperationalConfig(r.Context())
	return revision.Settings, err
}
func (s Server) operationalConfigGet02111(w http.ResponseWriter, r *http.Request) {
	store, ok := s.operationalStore02111(w)
	if !ok {
		return
	}
	revision, err := store.GetOperationalConfig(r.Context())
	if err != nil {
		writeError(w, 500, "не удалось получить настройки: "+err.Error())
		return
	}
	writeJSON(w, 200, revision)
}
func (s Server) operationalConfigHistory02111(w http.ResponseWriter, r *http.Request) {
	store, ok := s.operationalStore02111(w)
	if !ok {
		return
	}
	items, err := store.ListOperationalConfigRevisions(r.Context(), 50)
	if err != nil {
		writeError(w, 500, "не удалось получить историю конфигурации")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

type operationalChange02111 struct {
	ExpectedRevision int64           `json:"expectedRevision"`
	Settings         json.RawMessage `json:"settings"`
	Reason           string          `json:"reason"`
	RestoreRevision  int64           `json:"restoreRevision"`
}

func readOperationalChange02111(r *http.Request) (operationalChange02111, error) {
	var req operationalChange02111
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 16384))
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	if err != nil {
		return req, err
	}
	var trailing any
	if err = dec.Decode(&trailing); err == nil {
		return req, errors.New("лишние JSON-данные")
	} else if !errors.Is(err, io.EOF) {
		return req, err
	}
	if req.ExpectedRevision < 1 {
		return req, errors.New("expectedRevision должен быть положительным")
	}
	if len(strings.TrimSpace(req.Reason)) < 3 || len(req.Reason) > 500 {
		return req, errors.New("причина изменения: от 3 до 500 символов")
	}
	return req, nil
}
func decodeOperationalSettings02111(raw json.RawMessage) (repository.OperationalConfig, error) {
	var v repository.OperationalConfig
	if len(raw) == 0 {
		return v, errors.New("settings обязательны")
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return v, err
	}
	for _, key := range []string{"auditDefaultPageSize", "auditMaxPageSize", "auditLookbackDays", "auditExposeClientDetails", "jobsDefaultPageSize", "jobsMaxPageSize"} {
		if _, ok := keys[key]; !ok {
			return v, fmt.Errorf("%s: поле обязательно", key)
		}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, err
	}
	if err := v.Validate(); err != nil {
		return v, err
	}
	return v, nil
}
func (s Server) operationalConfigValidate02111(w http.ResponseWriter, r *http.Request) {
	req, err := readOperationalChange02111(r)
	if err != nil {
		writeReason02111(w, 400, "invalid_input", err.Error())
		return
	}
	next, err := decodeOperationalSettings02111(req.Settings)
	if err != nil {
		writeReason02111(w, 400, "invalid_field", err.Error())
		return
	}
	store, ok := s.operationalStore02111(w)
	if !ok {
		return
	}
	actual, err := store.GetOperationalConfig(r.Context())
	if err != nil {
		writeError(w, 503, "настройки недоступны")
		return
	}
	if actual.Revision != req.ExpectedRevision {
		writeReason02111(w, 409, "revision_conflict", "конфигурация изменена другой сессией; обновите страницу")
		return
	}
	writeJSON(w, 200, map[string]any{"valid": true, "revision": actual.Revision, "diff": diffOperational02111(actual.Settings, next), "restartRequired": false})
}
func diffOperational02111(before, after repository.OperationalConfig) []map[string]any {
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	var left, right map[string]any
	_ = json.Unmarshal(a, &left)
	_ = json.Unmarshal(b, &right)
	fields := []string{"auditDefaultPageSize", "auditMaxPageSize", "auditLookbackDays", "auditExposeClientDetails", "jobsDefaultPageSize", "jobsMaxPageSize"}
	out := []map[string]any{}
	for _, field := range fields {
		if left[field] != right[field] {
			out = append(out, map[string]any{"field": field, "before": left[field], "after": right[field], "restartRequired": false})
		}
	}
	return out
}
func (s Server) operationalConfigSave02111(w http.ResponseWriter, r *http.Request) {
	req, err := readOperationalChange02111(r)
	if err != nil {
		writeReason02111(w, 400, "invalid_input", err.Error())
		return
	}
	next, err := decodeOperationalSettings02111(req.Settings)
	if err != nil {
		writeReason02111(w, 400, "invalid_field", err.Error())
		return
	}
	s.saveOperational02111(w, r, req, next, nil)
}
func (s Server) operationalConfigRestore02111(w http.ResponseWriter, r *http.Request) {
	req, err := readOperationalChange02111(r)
	if err != nil {
		writeReason02111(w, 400, "invalid_input", err.Error())
		return
	}
	if req.RestoreRevision < 1 {
		writeReason02111(w, 400, "invalid_field", "restoreRevision обязателен")
		return
	}
	s.saveOperational02111(w, r, req, repository.OperationalConfig{}, &req.RestoreRevision)
}
func (s Server) saveOperational02111(w http.ResponseWriter, r *http.Request, req operationalChange02111, next repository.OperationalConfig, restore *int64) {
	store, ok := s.operationalStore02111(w)
	if !ok {
		return
	}
	claims, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "требуется авторизация")
		return
	}
	current, err := store.GetOperationalConfig(r.Context())
	if err != nil {
		writeError(w, 503, "конфигурация недоступна")
		return
	}
	if current.Revision != req.ExpectedRevision {
		writeReason02111(w, 409, "revision_conflict", "ревизия устарела — обновите настройки перед повтором")
		return
	}
	if restore != nil {
		revisions, err := store.ListOperationalConfigRevisions(r.Context(), 100)
		if err != nil {
			writeError(w, 503, "история конфигурации недоступна")
			return
		}
		found := false
		for _, v := range revisions {
			if v.Revision == *restore {
				next = v.Settings
				found = true
				break
			}
		}
		if !found {
			writeReason02111(w, 404, "revision_not_found", "ревизия не найдена в доступной истории")
			return
		}
	}
	diff := diffOperational02111(current.Settings, next)
	if len(diff) == 0 {
		writeReason02111(w, 409, "no_changes", "нет отличий от действующих настроек")
		return
	}
	saved, err := store.SaveOperationalConfig(r.Context(), req.ExpectedRevision, next, claims.Sub, strings.TrimSpace(req.Reason), restore)
	if errors.Is(err, repository.ErrConflict) {
		writeReason02111(w, 409, "revision_conflict", "конфигурация изменена одновременно; обновите ревизию")
		return
	}
	if errors.Is(err, repository.ErrNotFound) {
		writeReason02111(w, 404, "revision_not_found", "ревизия не найдена")
		return
	}
	if err != nil {
		writeError(w, 500, "не удалось применить настройки: "+err.Error())
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: claims.Sub, Action: "config:changed", Target: fmt.Sprintf("revision:%d", saved.Revision), CorrelationID: correlationID02111(r), ReasonCode: "applied", CreatedAt: time.Now().UTC()})
	writeJSON(w, 200, map[string]any{"revision": saved, "diff": diff, "restartRequired": false, "auditQuery": fmt.Sprintf("revision:%d", saved.Revision)})
}
func writeReason02111(w http.ResponseWriter, status int, reason, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": status, "reasonCode": reason, "message": message}})
}

func parseBounded02111(s string, def, max int) (int, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("число должно быть от 1 до %d", max)
	}
	return n, nil
}
func (s Server) auditSearch02111(w http.ResponseWriter, r *http.Request) {
	settings, err := s.operationalSettings02111(r)
	if err != nil {
		writeError(w, 503, "настройки аудита недоступны")
		return
	}
	query := r.URL.Query()
	limit, err := parseBounded02111(query.Get("limit"), settings.AuditDefaultPageSize, settings.AuditMaxPageSize)
	if err != nil {
		writeReason02111(w, 400, "invalid_limit", err.Error())
		return
	}
	offset := 0
	if v := query.Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil || offset < 0 || offset > 100000 {
			writeReason02111(w, 400, "invalid_offset", "offset от 0 до 100000")
			return
		}
	}
	q := repository.AuditQuery{Search: strings.TrimSpace(query.Get("search")), Actor: strings.TrimSpace(query.Get("actor")), Action: strings.TrimSpace(query.Get("action")), Target: strings.TrimSpace(query.Get("target")), CorrelationID: strings.TrimSpace(query.Get("correlationId")), ReasonCode: strings.TrimSpace(query.Get("reasonCode")), JobID: strings.TrimSpace(query.Get("jobId")), Limit: limit, Offset: offset}
	for _, field := range []string{q.Search, q.Actor, q.Action, q.Target, q.CorrelationID, q.ReasonCode, q.JobID} {
		if len(field) > 200 {
			writeReason02111(w, 400, "invalid_filter", "фильтр длиннее 200 символов")
			return
		}
	}
	q.From = time.Now().UTC().AddDate(0, 0, -settings.AuditLookbackDays)
	if val := query.Get("from"); val != "" {
		q.From, err = time.Parse(time.RFC3339, val)
		if err != nil {
			writeReason02111(w, 400, "invalid_date", "from: требуется ISO 8601")
			return
		}
	}
	if val := query.Get("to"); val != "" {
		q.To, err = time.Parse(time.RFC3339, val)
		if err != nil {
			writeReason02111(w, 400, "invalid_date", "to: требуется ISO 8601")
			return
		}
	}
	if !q.To.IsZero() && q.From.After(q.To) {
		writeReason02111(w, 400, "invalid_date", "from должен быть не позже to")
		return
	}
	store, ok := s.Repo.(repository.AuditQueryStore)
	if !ok {
		writeError(w, 503, "поиск аудита недоступен")
		return
	}
	result, err := store.QueryAudit(r.Context(), q)
	if err != nil {
		writeError(w, 500, "поиск аудита завершился ошибкой")
		return
	}
	if !settings.AuditExposeClientDetails {
		for i := range result.Items {
			result.Items[i].IP = ""
			result.Items[i].UserAgent = ""
		}
	}
	writeJSON(w, 200, result)
}
