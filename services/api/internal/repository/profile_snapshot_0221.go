package repository

import (
	"errors"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// ReadProfileSnapshot returns a stable copy of the *current* revision.
// Release creation freezes this copy, subsequent profile edits cannot affect the release.
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
	return model.ProfileSnapshot{}, errors.New("profile not found")
}
