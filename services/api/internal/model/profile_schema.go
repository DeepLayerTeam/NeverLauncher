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
		return errors.New("invalid v2 profile snapshot identity or revision")
	}
	if s.Digest != ProfileDigest(s.Spec) {
		return errors.New("v2 profile snapshot digest mismatch")
	}
	return nil
}

func ValidateManifestSchema(m Manifest) error {
	if source := m.RollbackSource; source != nil {
		if m.GameReleaseGeneration == 0 || source.GameReleaseGeneration >= m.GameReleaseGeneration ||
			source.Version == "" || len(source.ManifestSHA256) != 64 {
			return errors.New("invalid signed rollbackSource or gameReleaseGeneration")
		}
		if decoded, err := hex.DecodeString(source.ManifestSHA256); err != nil || len(decoded) != sha256.Size {
			return errors.New("rollbackSource manifestSha256 must be SHA-256 hex")
		}
	}
	switch m.SchemaVersion {
	case "1.0":
		if m.ProfileSnapshot != nil {
			return errors.New("v1 manifests cannot contain a v2 profile snapshot")
		}
	case ManifestSchemaV2, ManifestSchemaV3:
		if m.ProfileSnapshot == nil {
			return errors.New("v2 manifest requires a profile snapshot")
		}
		if err := ValidateProfileSnapshot(*m.ProfileSnapshot, m.ProjectID, m.ProfileID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported manifest schema %q", m.SchemaVersion)
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
		return Profile{}, fmt.Errorf("unsupported profile schema %q", p.SchemaVersion)
	}
	p.SchemaVersion = ProfileSchemaV2
	if p.Loader == "" {
		p.Loader = "vanilla"
	}
	if p.ProjectID == "" || p.ID == "" || p.Name == "" {
		return Profile{}, errors.New("profile projectId, id and name required")
	}
	if p.MinecraftVersion != "" || p.LoaderVersion != "" || p.JavaMajor != 0 {
		switch p.Loader {
		case "vanilla", "fabric", "quilt", "forge", "neoforge":
		default:
			return Profile{}, errors.New("unsupported Minecraft loader")
		}
		if p.MinecraftVersion == "" || p.JavaMajor < 8 || p.JavaMajor > 255 {
			return Profile{}, errors.New("configured profile requires Minecraft version and Java major between 8 and 255")
		}
		if len(p.MinecraftVersion) > 64 || len(p.LoaderVersion) > 128 ||
			strings.ContainsAny(p.MinecraftVersion, " /\\\t\n\r") || strings.ContainsAny(p.LoaderVersion, " /\\\t\n\r") {
			return Profile{}, errors.New("invalid Minecraft or loader version")
		}
		if p.Loader != "vanilla" && p.LoaderVersion == "" {
			return Profile{}, errors.New("configured modded profile requires exact loader version")
		}
		if p.Loader == "vanilla" && p.LoaderVersion != "" {
			return Profile{}, errors.New("Vanilla profile cannot declare loader version")
		}
	}
	for _, v := range []string{p.ProjectID, p.ID, p.Name, p.Description, p.Loader, p.Preset, p.MinecraftVersion, p.LoaderVersion} {
		if strings.ContainsRune(v, '\x00') {
			return Profile{}, errors.New("profile fields cannot contain NUL")
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
		return fmt.Errorf("stored release manifest is invalid: %w", err)
	}
	if err := ValidateManifestSchema(candidate); err != nil {
		return err
	}
	if existing.SchemaVersion != candidate.SchemaVersion {
		return errors.New("release manifest schema is immutable; create a new release")
	}
	if (existing.SchemaVersion == ManifestSchemaV2 || existing.SchemaVersion == ManifestSchemaV3) && *existing.ProfileSnapshot != *candidate.ProfileSnapshot {
		return errors.New("release profile snapshot is immutable; create a new release")
	}
	if existing.ProjectID != candidate.ProjectID || existing.ProfileID != candidate.ProfileID || existing.Channel != candidate.Channel || existing.Version != candidate.Version {
		return errors.New("release manifest identity is immutable")
	}
	return nil
}
