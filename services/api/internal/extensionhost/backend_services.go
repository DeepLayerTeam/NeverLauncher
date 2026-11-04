package extensionhost

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// Java-службы Backend повторно используют аутентифицированный маршрут возможностей
// расширений. Они не создают прямой доступ к репозиторию, второй токен или обход
// HTTP. Все обращения ограничены одним явным проектом и работают только на чтение.
func (s *Supervisor) executeBackendService0484(ctx context.Context, st *processState, name string, req capabilityRequest) capabilityResult0205 {
	denied := func(status int, text string) capabilityResult0205 {
		return capabilityResult0205{status: status, err: errors.New(text)}
	}
	if ctx.Err() != nil {
		return denied(http.StatusGatewayTimeout, "backend service deadline exceeded")
	}
	permission := "project:read"
	if strings.HasPrefix(name, "channel.") || strings.HasPrefix(name, "release.") {
		permission = "release:read"
	}
	// Списки проектов доступны только при явно выданном глобальном праве
	// project:read; права отдельных проектов не должны позволять перечислять
	// арендаторов.
	projectID := ""
	if name != "project.list" {
		var err error
		projectID, err = s.scopedProject(st, req.ProjectID)
		if err != nil {
			return denied(http.StatusForbidden, "project scope denied")
		}
	} else if st.key.Scope != "global" || strings.TrimSpace(req.ProjectID) != "" {
		return denied(http.StatusForbidden, "global project listing requires a global extension scope")
	}
	permitted, err := s.permissionAllowed0207(ctx, st, permission, projectID)
	if err != nil {
		return denied(http.StatusServiceUnavailable, "capability policy unavailable")
	}
	if !permitted {
		return denied(http.StatusForbidden, "permission "+permission+" not granted")
	}
	if ctx.Err() != nil {
		return denied(http.StatusGatewayTimeout, "backend service deadline exceeded")
	}
	if name != "project.list" {
		if _, e := s.repo.GetProject(projectID); e != nil {
			return denied(http.StatusNotFound, "project not found")
		}
	}
	switch name {
	case "project.list":
		// Глобальные разрешения проверяются выше до перечисления ID проектов.
		projects := s.repo.ListProjects()
		sort.Slice(projects, func(i, j int) bool { return projects[i].ID < projects[j].ID })
		return pagedBackend0484(projects, req)
	case "profile.list", "profile.get":
		profiles, e := s.repo.ListProfiles(projectID)
		if e != nil {
			return denied(http.StatusInternalServerError, "profile repository unavailable")
		}
		// Дополнительная защита от некорректного адаптера репозитория, смешивающего
		// арендаторов.
		scoped := make([]model.Profile, 0, len(profiles))
		for _, p := range profiles {
			if p.ProjectID == projectID {
				scoped = append(scoped, p)
			}
		}
		if name == "profile.get" {
			if req.ProfileID == "" {
				return denied(http.StatusBadRequest, "profileId required")
			}
			for _, p := range scoped {
				if p.ID == req.ProfileID {
					return capabilityResult0205{value: map[string]any{"profile": p}, status: http.StatusOK}
				}
			}
			return denied(http.StatusNotFound, "profile not found")
		}
		sort.Slice(scoped, func(i, j int) bool { return scoped[i].ID < scoped[j].ID })
		return pagedBackend0484(scoped, req)
	case "channel.list", "channel.get":
		channels, e := s.repo.ListChannels(projectID)
		if e != nil {
			return denied(http.StatusInternalServerError, "channel repository unavailable")
		}
		scoped := make([]model.ReleaseChannel, 0, len(channels))
		for _, c := range channels {
			if c.ProjectID == projectID {
				scoped = append(scoped, c)
			}
		}
		if name == "channel.get" {
			if req.Name == "" {
				return denied(http.StatusBadRequest, "channel name required")
			}
			for _, c := range scoped {
				if c.Name == req.Name {
					return capabilityResult0205{value: map[string]any{"channel": c}, status: http.StatusOK}
				}
			}
			return denied(http.StatusNotFound, "channel not found")
		}
		sort.Slice(scoped, func(i, j int) bool { return scoped[i].Name < scoped[j].Name })
		return pagedBackend0484(scoped, req)
	case "release.page":
		releases, e := s.repo.ListVersions(projectID)
		if e != nil {
			return denied(http.StatusInternalServerError, "release repository unavailable")
		}
		// Список не передаёт потенциально крупный подписанный манифест каждого
		// элемента. Полный манифест одной записи запрашивайте через release.get.
		scoped := make([]map[string]any, 0, len(releases))
		for _, v := range releases {
			if v.ProjectID == projectID {
				scoped = append(scoped, map[string]any{
					"id": v.ID, "projectId": v.ProjectID, "profileId": v.ProfileID,
					"channel": v.Channel, "version": v.Version, "status": v.Status,
					"publishedAt": v.PublishedAt,
				})
			}
		}
		sort.Slice(scoped, func(i, j int) bool { return scoped[i]["id"].(string) < scoped[j]["id"].(string) })
		return pagedBackend0484(scoped, req)
	case "release.get":
		if req.Name == "" {
			return denied(http.StatusBadRequest, "release id required")
		}
		releases, e := s.repo.ListVersions(projectID)
		if e != nil {
			return denied(http.StatusInternalServerError, "release repository unavailable")
		}
		for _, v := range releases {
			if v.ProjectID == projectID && v.ID == req.Name {
				return capabilityResult0205{value: map[string]any{"release": v}, status: http.StatusOK}
			}
		}
		return denied(http.StatusNotFound, "release not found")
	case "job.get":
		if req.Name == "" || len(req.Name) > 128 {
			return denied(http.StatusBadRequest, "job id required")
		}
		durable, ok := s.repo.(repository.DurableControlPlane)
		if !ok {
			return denied(http.StatusServiceUnavailable, "durable jobs unavailable")
		}
		job, e := durable.GetDurableJob(ctx, req.Name)
		// Никакого оракула существования других проектов. Никогда не возвращайте
		// полезную нагрузку, результат, токен аренды, идентичность исполнителя, текст
		// ошибки или секреты операции.
		if e != nil || job.ProjectID != projectID {
			return denied(http.StatusNotFound, "job not found")
		}
		view := map[string]any{"id": job.ID, "projectId": job.ProjectID, "kind": job.Kind, "status": job.Status,
			"attemptCount": job.AttemptCount, "maxAttempts": job.MaxAttempts, "createdAt": job.CreatedAt,
			"updatedAt": job.UpdatedAt, "completedAt": job.CompletedAt}
		return capabilityResult0205{value: map[string]any{"job": view}, status: http.StatusOK}
	}
	return denied(http.StatusNotFound, "backend capability not supported")
}

// Детерминированные ограниченные страницы не дают одному расширению запросить
// неограниченный HTTP-ответ. Пустой nextOffset означает последнюю страницу.
func pagedBackend0484[T any](items []T, req capabilityRequest) capabilityResult0205 {
	if req.Offset < 0 || req.Offset > 1_000_000 || req.Limit < 0 || req.Limit > 50 {
		return capabilityResult0205{status: http.StatusBadRequest, err: errors.New("invalid page offset or limit")}
	}
	limit := req.Limit
	if limit == 0 {
		limit = 20
	}
	start := req.Offset
	if start > len(items) {
		start = len(items)
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	page := append([]T{}, items[start:end]...)
	result := map[string]any{"items": page}
	if end < len(items) {
		result["nextOffset"] = end
	}
	return capabilityResult0205{value: result, status: http.StatusOK}
}
