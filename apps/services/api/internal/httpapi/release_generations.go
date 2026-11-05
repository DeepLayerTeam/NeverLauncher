package httpapi

import (
	"errors"
	"fmt"
	"math"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
)

// Поколение канала — последовательность авторизации, а не версия Minecraft
// пользователя и не локальный указатель транзакции релиза. Вызывающий сериализует
// подписи устойчивой арендой области поколений игры.
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
		return 0, errors.New("Исчерпаны поколения выпусков игры")
	}
	return highest + 1, nil
}

// Пакет, подписанный как текущий, но опубликованный после более нового релиза,
// нужно подписать повторно; иначе старая, но действительная подпись может откатить
// канал назад. Устойчивый CAS публикации по-прежнему разрешает конкуренцию
// издателей.
func (s Server) checkGameReleasePublishGeneration02311(candidate model.ReleaseVersion) error {
	// Устаревшие релизы могут оставаться читаемыми; после принятия поколений
	// каналом даже подписанный релиз с нулевым поколением не должен вновь стать
	// его head.
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
			return fmt.Errorf("Защита игры от отката: опубликованное поколение %d не меньше кандидатного %d", v.Manifest.GameReleaseGeneration, candidate.Manifest.GameReleaseGeneration)
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
				// Откат — это старое содержимое под новой идентичностью и URL, а не
				// произвольный релиз со ссылкой на историческую запись.
				if sameGameFileSet02311(v.Manifest.Files, candidate.Manifest.Files) {
					matched = true
				}
				break
			}
		}
		if !matched {
			return errors.New("Источник отката игры rollbackSource не является опубликованным проверенным предыдущим релизом")
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
