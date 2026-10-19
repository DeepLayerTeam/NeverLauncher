package httpapi

import (
	"errors"
	"fmt"
	"math"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// The channel generation is an authorization sequence, not the user's
// Minecraft version number and not a local release transaction pointer.
// Caller serializes signatures using the durable game-generation scope lease.
func (s Server) nextGameReleaseGeneration02311(project, profile, channel, exceptID string) (uint64, error) {
	versions, err := s.Repo.ListVersions(project)
	if err != nil {
		return 0, err
	}
	var highest uint64
	for _, v := range versions {
		if v.ID == exceptID || v.ProfileID != profile || v.Channel != channel {
			continue
		}
		if v.Manifest.GameReleaseGeneration > highest {
			highest = v.Manifest.GameReleaseGeneration
		}
	}
	if highest == math.MaxUint64 {
		return 0, errors.New("game release generation exhausted")
	}
	return highest + 1, nil
}

// A package that was signed while current but published after a newer release
// must be signed again; otherwise an old but valid signature could move the
// channel backwards. The durable publish CAS still resolves racing publishers.
func (s Server) checkGameReleasePublishGeneration02311(candidate model.ReleaseVersion) error {
	// Legacy releases may remain readable; once a channel accepts generations
	// even a zero-generation signed release must not become its head again.
	versions, err := s.Repo.ListVersions(candidate.ProjectID)
	if err != nil {
		return err
	}
	for _, v := range versions {
		if v.ID == candidate.ID || v.Status != "published" || v.ProfileID != candidate.ProfileID || v.Channel != candidate.Channel {
			continue
		}
		if candidate.Manifest.GameReleaseGeneration == 0 && v.Manifest.GameReleaseGeneration == 0 {
			continue
		}
		if v.Manifest.GameReleaseGeneration >= candidate.Manifest.GameReleaseGeneration {
			return fmt.Errorf("game anti-rollback: published generation %d is not below candidate %d", v.Manifest.GameReleaseGeneration, candidate.Manifest.GameReleaseGeneration)
		}
	}
	if source := candidate.Manifest.RollbackSource; source != nil {
		matched := false
		for _, v := range versions {
			if v.Status != "published" || v.ProfileID != candidate.ProfileID || v.Channel != candidate.Channel ||
				v.Version != source.Version || v.Manifest.GameReleaseGeneration != source.GameReleaseGeneration {
				continue
			}
			digest, digestErr := manifestDigest0212(v.Manifest)
			if digestErr == nil && digest == source.ManifestSHA256 {
				// A rollback is the old content under a new identity and URL,
				// not an arbitrary release claiming a historical reference.
				if sameGameFileSet02311(v.Manifest.Files, candidate.Manifest.Files) {
					matched = true
				}
				break
			}
		}
		if !matched {
			return errors.New("game rollbackSource is not a published verified historical release")
		}
	}
	return nil
}

func sameGameFileSet02311(previous, current []model.ManifestFile) bool {
	if len(previous) != len(current) {
		return false
	}
	items := make(map[string]model.ManifestFile, len(previous))
	for _, f := range previous {
		if _, exists := items[f.Path]; exists {
			return false
		}
		items[f.Path] = f
	}
	for _, f := range current {
		original, ok := items[f.Path]
		if !ok || original.SHA256 != f.SHA256 || original.Size != f.Size || original.Required != f.Required || original.Executable != f.Executable {
			return false
		}
	}
	return true
}
