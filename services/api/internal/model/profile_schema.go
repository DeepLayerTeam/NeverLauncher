package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const ProfileSchemaV2 = "2.0"
const ManifestSchemaV2 = "2.0"

// ProfileSpec — неизменяемые метаданные стартового профиля, покрытые хешем ревизии.
// Пользовательские и изменяемые createdAt/updatedAt намеренно исключены.
type ProfileSpec struct {
	ProjectID        string `json:"projectId"`
	ID               string `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Loader           string `json:"loader"`
	MinecraftVersion string `json:"minecraftVersion,omitempty"`
	LoaderVersion    string `json:"loaderVersion,omitempty"`
	JavaMajor        int    `json:"javaMajor,omitempty"`
	Preset           string `json:"preset"`
	IsDefault        bool   `json:"isDefault"`
}

// ProfileSnapshot копируется в новый релиз v2 при создании и НЕ ДОЛЖЕН
// изменяться после редактирования изменяемого профиля.
type ProfileSnapshot struct {
	SchemaVersion string      `json:"schemaVersion"`
	Revision      int64       `json:"revision"`
	Digest        string      `json:"digest"`
	Spec          ProfileSpec `json:"spec"`
}

func ProfileSpecOf(p Profile) ProfileSpec {
	return ProfileSpec{ProjectID: p.ProjectID, ID: p.ID, Name: p.Name, Description: p.Description, Loader: p.Loader, MinecraftVersion: p.MinecraftVersion, LoaderVersion: p.LoaderVersion, JavaMajor: p.JavaMajor, Preset: p.Preset, IsDefault: p.IsDefault}
}

// ProfileDigest имеет одинаковое двоичное представление в Go и миграции PostgreSQL 0056. Разделители
// NUL исключают неоднозначные комбинации полей; NUL недопустим в тексте PostgreSQL.
func ProfileDigest(s ProfileSpec) string {
	fields := []string{s.ProjectID, s.ID, s.Name, s.Description, s.Loader, s.Preset, fmt.Sprint(s.IsDefault)}
	// Существующие хеши профилей/релизов v2 должны оставаться побайтово
	// стабильными. Только явно настроенные метаданные запуска расширяют домен.
	if s.MinecraftVersion != "" || s.LoaderVersion != "" || s.JavaMajor != 0 {
		fields = append(fields, "launch-0382", s.MinecraftVersion, s.LoaderVersion, fmt.Sprint(s.JavaMajor))
	}
	digest := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(digest[:])
}

func SnapshotProfile(p Profile) ProfileSnapshot {
	spec := ProfileSpecOf(p)
	return ProfileSnapshot{SchemaVersion: ProfileSchemaV2, Revision: p.Revision, Digest: ProfileDigest(spec), Spec: spec}
}

func ValidateProfileSnapshot(s ProfileSnapshot, projectID, profileID string) error {
	if s.SchemaVersion != ProfileSchemaV2 || s.Revision < 1 || s.Spec.ProjectID != projectID || s.Spec.ID != profileID || s.Spec.Name == "" || s.Spec.Loader == "" {
		return errors.New("Недопустимый идентификатор или ревизия снимка профиля v2")
	}
	if s.Digest != ProfileDigest(s.Spec) {
		return errors.New("Хеш снимка профиля v2 не совпадает")
	}
	return nil
}

func ValidateManifestSchema(m Manifest) error {
	if source := m.RollbackSource; source != nil {
		if m.GameReleaseGeneration == 0 || source.GameReleaseGeneration >= m.GameReleaseGeneration ||
			source.Version == "" || len(source.ManifestSHA256) != 64 {
			return errors.New("Недопустимое подписанное значение rollbackSource или gameReleaseGeneration")
		}
		if decoded, err := hex.DecodeString(source.ManifestSHA256); err != nil || len(decoded) != sha256.Size {
			return errors.New("В rollbackSource поле manifestSha256 должно быть SHA-256 в hex")
		}
	}
	switch m.SchemaVersion {
	case "1.0":
		if m.ProfileSnapshot != nil {
			return errors.New("Манифесты v1 не могут содержать снимок профиля v2")
		}
	case ManifestSchemaV2, ManifestSchemaV3:
		if m.ProfileSnapshot == nil {
			return errors.New("Для манифеста v2 требуется снимок профиля")
		}
		if err := ValidateProfileSnapshot(*m.ProfileSnapshot, m.ProjectID, m.ProfileID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Неподдерживаемая схема манифеста %q", m.SchemaVersion)
	}
	if err := ValidateComponentCatalog0241(m); err != nil {
		return err
	}
	if m.SchemaVersion == ManifestSchemaV2 || m.SchemaVersion == ManifestSchemaV3 {
		if err := ValidateRuntimeConstraints0223(m); err != nil {
			return err
		}
		if err := ValidateFileOwnership0224(m); err != nil {
			return err
		}
	}
	return nil
}

func NormalizeProfileV2(p Profile) (Profile, error) {
	if p.SchemaVersion != "" && p.SchemaVersion != ProfileSchemaV2 {
		return Profile{}, fmt.Errorf("Неподдерживаемая схема профиля %q", p.SchemaVersion)
	}
	p.SchemaVersion = ProfileSchemaV2
	if p.Loader == "" {
		p.Loader = "vanilla"
	}
	if p.ProjectID == "" || p.ID == "" || p.Name == "" {
		return Profile{}, errors.New("Для профиля обязательны projectId, id и name")
	}
	if p.MinecraftVersion != "" || p.LoaderVersion != "" || p.JavaMajor != 0 {
		switch p.Loader {
		case "vanilla", "fabric", "quilt", "forge", "neoforge":
		default:
			return Profile{}, errors.New("Неподдерживаемый загрузчик Minecraft")
		}
		if p.MinecraftVersion == "" || p.JavaMajor < 8 || p.JavaMajor > 255 {
			return Profile{}, errors.New("Для настроенного профиля необходимы версия Minecraft и основная версия Java от 8 до 255")
		}
		if len(p.MinecraftVersion) > 64 || len(p.LoaderVersion) > 128 ||
			strings.ContainsAny(p.MinecraftVersion, " /\\\t\n\r") || strings.ContainsAny(p.LoaderVersion, " /\\\t\n\r") {
			return Profile{}, errors.New("Недопустимая версия Minecraft или загрузчика")
		}
		if p.Loader != "vanilla" && p.LoaderVersion == "" {
			return Profile{}, errors.New("Для настроенного модифицированного профиля требуется точная версия загрузчика")
		}
		if p.Loader == "vanilla" && p.LoaderVersion != "" {
			return Profile{}, errors.New("Профиль Vanilla не должен указывать версию загрузчика")
		}
	}
	for _, v := range []string{p.ProjectID, p.ID, p.Name, p.Description, p.Loader, p.Preset, p.MinecraftVersion, p.LoaderVersion} {
		if strings.ContainsRune(v, '\x00') {
			return Profile{}, errors.New("Поля профиля не могут содержать NUL")
		}
	}
	p.Digest = ProfileDigest(ProfileSpecOf(p))
	return p, nil
}

// ValidateReleaseManifestTransition обеспечивает закреплённый при создании черновика
// снимок. Никогда не получайте его из текущего изменяемого профиля при обновлении или
// публикации. Черновик v1 остаётся только v1; обновление требует новой идентичности
// релиза.
func ValidateReleaseManifestTransition(existing, candidate Manifest) error {
	if err := ValidateManifestSchema(existing); err != nil {
		return fmt.Errorf("Сохранённый манифест выпуска недопустим: %w", err)
	}
	if err := ValidateManifestSchema(candidate); err != nil {
		return err
	}
	if existing.SchemaVersion != candidate.SchemaVersion {
		return errors.New("Схема манифеста выпуска неизменяема; создайте новый выпуск")
	}
	if (existing.SchemaVersion == ManifestSchemaV2 || existing.SchemaVersion == ManifestSchemaV3) && *existing.ProfileSnapshot != *candidate.ProfileSnapshot {
		return errors.New("Снимок профиля выпуска неизменяем; создайте новый выпуск")
	}
	if existing.ProjectID != candidate.ProjectID || existing.ProfileID != candidate.ProfileID || existing.Channel != candidate.Channel || existing.Version != candidate.Version {
		return errors.New("Идентификатор манифеста выпуска неизменяем")
	}
	return nil
}
