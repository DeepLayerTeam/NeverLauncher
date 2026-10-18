package repository

import (
	"context"
	"sort"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// OperationLister provides a project-isolated, bounded view of durable jobs.
// The API checks the caller's project permission before using this interface.
type OperationLister interface {
	ListProjectOperations(ctx context.Context, projectID, status string, limit, offset int) ([]model.DurableJob, error)
}

func operationPage02110(limit, offset int) (int, int) {
	if limit < 1 {
		limit = 25
	}
	if limit > 101 {
		limit = 101
	}
	if offset < 0 {
		offset = 0
	}
	if offset > 10000 {
		offset = 10000
	}
	return limit, offset
}

func (r *SQLRepository) ListProjectOperations(ctx context.Context, projectID, status string, limit, offset int) ([]model.DurableJob, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	limit, offset = operationPage02110(limit, offset)
	rows, err := r.db.QueryContext(ctx, `SELECT `+durableJobColumns0213+` FROM durable_jobs WHERE project_id=$1 AND ($2='' OR status=$2) ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`, strings.TrimSpace(projectID), strings.TrimSpace(status), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := make([]model.DurableJob, 0, limit)
	for rows.Next() {
		j, scanErr := scanDurableJob0213(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		jobs = append(jobs, j)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return jobs, nil
}

func (r *MemoryRepository) ListProjectOperations(_ context.Context, projectID, status string, limit, offset int) ([]model.DurableJob, error) {
	limit, offset = operationPage02110(limit, offset)
	r.durableMu.Lock()
	defer r.durableMu.Unlock()
	jobs := make([]model.DurableJob, 0)
	for _, j := range r.durableJobs {
		if j.ProjectID == projectID && (status == "" || j.Status == status) {
			jobs = append(jobs, j)
		}
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].ID > jobs[j].ID
		}
		return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
	})
	if offset >= len(jobs) {
		return []model.DurableJob{}, nil
	}
	jobs = jobs[offset:]
	if len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs, nil
}
