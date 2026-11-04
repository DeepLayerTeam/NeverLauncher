package repository

import (
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// ReadProfileSnapshot возвращает стабильную копию ТЕКУЩЕЙ ревизии. Создание релиза фиксирует
// эту копию; будущие изменения профиля не влияют на релиз.
func ReadProfileSnapshot(repo Repository, projectID, profileID string) (model.ProfileSnapshot, error) {
	if reader, ok := repo.(interface {
		CurrentProfileSnapshot(projectID, profileID string) (model.ProfileSnapshot, error)
	}); ok {
		return reader.CurrentProfileSnapshot(projectID, profileID)
	}
	profiles, err := repo.ListProfiles(projectID)
	if err != nil {
		return model.ProfileSnapshot{}, err
	}
	for _, p := range profiles {
		if p.ID == profileID {
			return model.SnapshotProfile(p), nil
		}
	}
	return model.ProfileSnapshot{}, ErrNotFound
}
