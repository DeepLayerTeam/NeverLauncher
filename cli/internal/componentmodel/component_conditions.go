package componentmodel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Условия — подписанные предикаты, а не команды клиента. В схеме 1.0 каждое непустое
// поле должно совпасть; массивы объединяются ИЛИ, поля — И. Отсутствующий доверенный
// контекст никогда не означает неограниченный доступ.
type ComponentConditions0244 struct {
	SchemaVersion         string   `json:"schemaVersion"`
	OS                    []string `json:"os,omitempty"`
	Arch                  []string `json:"arch,omitempty"`
	JavaMajorMin          uint32   `json:"javaMajorMin,omitempty"`
	JavaMajorMax          uint32   `json:"javaMajorMax,omitempty"`
	MinecraftVersions     []string `json:"minecraftVersions,omitempty"`
	MinecraftVersionRange string   `json:"minecraftVersionRange,omitempty"`
	Loaders               []string `json:"loaders,omitempty"`
	LoaderVersionRange    string   `json:"loaderVersionRange,omitempty"`
	Permissions           []string `json:"permissions,omitempty"`
}

type ComponentEnvironment0244 struct {
	OS               string
	Arch             string
	JavaMajor        uint32
	MinecraftVersion string
	Loader           string
	LoaderVersion    string
	// Эта карта ОБЯЗАНА поступать из аутентифицированной серверной авторизации, а не из JSON
	// Desktop или непроверенного локального профиля учётной записи.
	VerifiedPermissions map[string]bool
}

func ComponentCatalogDigest0244(c ComponentCatalog0241) string {
	if c.SchemaVersion != ComponentCatalogSchema0244 && c.SchemaVersion != ComponentCatalogSchema0245 {
		return ComponentCatalogDigest0243(c)
	}
	h := sha256.New()
	h.Write([]byte("launcher.component-catalog.v4\x00"))
	var n [4]byte
	number := func(x int) { binary.BigEndian.PutUint32(n[:], uint32(x)); _, _ = h.Write(n[:]) }
	str := func(v string) { number(len(v)); _, _ = h.Write([]byte(v)) }
	str(ComponentCatalogDigest0243(c))
	number(len(c.Components))
	for _, component := range c.Components {
		v := component.Conditions
		if v == nil {
			h.Write([]byte{0})
			continue
		}
		h.Write([]byte{1})
		str(v.SchemaVersion)
		for _, items := range [][]string{v.OS, v.Arch, v.MinecraftVersions, v.Loaders, v.Permissions} {
			number(len(items))
			for _, value := range items {
				str(value)
			}
		}
		number(int(v.JavaMajorMin))
		number(int(v.JavaMajorMax))
		str(v.MinecraftVersionRange)
		str(v.LoaderVersionRange)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func NewComponentCatalog0244(c ComponentCatalog0241, revision uint64) ComponentCatalog0241 {
	c.SchemaVersion = ComponentCatalogSchema0244
	c.Revision = revision
	if c.Components == nil {
		c.Components = []CatalogComponent0241{}
	}
	for i := range c.Presets {
		if c.Presets[i].Components == nil {
			c.Presets[i].Components = []string{}
		}
	}
	c.Digest = ComponentCatalogDigest0244(c)
	return c
}
func validPermissionName0244(s string) bool {
	if len(s) == 0 || len(s) > 128 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, ch := range []byte(s) {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.' || ch == ':') {
			return false
		}
	}
	return !strings.Contains(s, "..") && !strings.Contains(s, "::")
}

func validDistinct0244(values []string, limit int, valid func(string) bool) error {
	if len(values) > limit {
		return errors.New("Массив условий превышает допустимый предел")
	}
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if !valid(v) || seen[v] {
			return fmt.Errorf("Недопустимое или повторяющееся значение условия %q", v)
		}
		seen[v] = true
	}
	return nil
}
func ValidateCatalogConditions0244(cat ComponentCatalog0241) error {
	if cat.SchemaVersion != ComponentCatalogSchema0244 && cat.SchemaVersion != ComponentCatalogSchema0245 {
		for _, c := range cat.Components {
			if c.Conditions != nil {
				return fmt.Errorf("У компонента %s есть неподписанные условия версии 4", c.ID)
			}
		}
		return nil
	}
	for _, c := range cat.Components {
		v := c.Conditions
		if v == nil {
			continue
		}
		if v.SchemaVersion != "1.0" {
			return fmt.Errorf("Компонент %s: неподдерживаемая схема условий %q", c.ID, v.SchemaVersion)
		}
		if err := validDistinct0244(v.OS, 8, func(s string) bool { return s == "windows" || s == "linux" || s == "macos" }); err != nil {
			return fmt.Errorf("компонент %s: ОС: %w", c.ID, err)
		}
		if err := validDistinct0244(v.Arch, 8, func(s string) bool { return s == "x86_64" || s == "aarch64" }); err != nil {
			return fmt.Errorf("компонент %s: архитектура: %w", c.ID, err)
		}
		if v.JavaMajorMax != 0 && v.JavaMajorMin > v.JavaMajorMax {
			return fmt.Errorf("Компонент %s: границы диапазона основных версий Java указаны в обратном порядке", c.ID)
		}
		if v.JavaMajorMin > 99 || v.JavaMajorMax > 99 {
			return fmt.Errorf("Компонент %s: недопустимая основная версия Java", c.ID)
		}
		if err := validDistinct0244(v.MinecraftVersions, 64, func(s string) bool { return len(s) > 0 && len(s) <= 80 && !strings.ContainsAny(s, " \t\r\n\x00") }); err != nil {
			return fmt.Errorf("компонент %s: Minecraft: %w", c.ID, err)
		}
		if err := validDistinct0244(v.Loaders, 12, func(s string) bool {
			return s == "vanilla" || s == "fabric" || s == "quilt" || s == "forge" || s == "neoforge"
		}); err != nil {
			return fmt.Errorf("компонент %s: загрузчик: %w", c.ID, err)
		}
		if err := validDistinct0244(v.Permissions, 32, func(s string) bool { return validPermissionName0244(s) }); err != nil {
			return fmt.Errorf("компонент %s: разрешения: %w", c.ID, err)
		}
		if v.MinecraftVersionRange != "" {
			if _, err := matchRange0243("1.0.0", v.MinecraftVersionRange); err != nil {
				return fmt.Errorf("Компонент %s, диапазон версий Minecraft: %w", c.ID, err)
			}
		}
		if v.LoaderVersionRange != "" {
			if _, err := matchRange0243("1.0.0", v.LoaderVersionRange); err != nil {
				return fmt.Errorf("Компонент %s, диапазон версий загрузчика: %w", c.ID, err)
			}
		}
	}
	return nil
}
func in0244(list []string, value string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}
	return false
}
func unavailable0244(v *ComponentConditions0244, env ComponentEnvironment0244) string {
	if v == nil {
		return ""
	}
	if len(v.OS) > 0 && !in0244(v.OS, env.OS) {
		return fmt.Sprintf("ОС %q отсутствует в %v", env.OS, v.OS)
	}
	if len(v.Arch) > 0 && !in0244(v.Arch, env.Arch) {
		return fmt.Sprintf("Архитектура %q отсутствует в %v", env.Arch, v.Arch)
	}
	if v.JavaMajorMin > 0 && (env.JavaMajor == 0 || env.JavaMajor < v.JavaMajorMin) {
		return fmt.Sprintf("Основная версия Java %d ниже %d", env.JavaMajor, v.JavaMajorMin)
	}
	if v.JavaMajorMax > 0 && (env.JavaMajor == 0 || env.JavaMajor > v.JavaMajorMax) {
		return fmt.Sprintf("Основная версия Java %d превышает %d", env.JavaMajor, v.JavaMajorMax)
	}
	if len(v.MinecraftVersions) > 0 && !in0244(v.MinecraftVersions, env.MinecraftVersion) {
		return fmt.Sprintf("Версия Minecraft %q отсутствует в %v", env.MinecraftVersion, v.MinecraftVersions)
	}
	if v.MinecraftVersionRange != "" {
		ok, e := matchRange0243(env.MinecraftVersion, v.MinecraftVersionRange)
		if e != nil {
			return "Версия Minecraft не соответствует семантическому версионированию: " + e.Error()
		}
		if !ok {
			return fmt.Sprintf("версия Minecraft %q не входит в диапазон %q", env.MinecraftVersion, v.MinecraftVersionRange)
		}
	}
	if len(v.Loaders) > 0 && !in0244(v.Loaders, strings.ToLower(env.Loader)) {
		return fmt.Sprintf("Загрузчик %q отсутствует в %v", env.Loader, v.Loaders)
	}
	if v.LoaderVersionRange != "" {
		ok, e := matchRange0243(env.LoaderVersion, v.LoaderVersionRange)
		if e != nil {
			return "Версия загрузчика не соответствует семантическому версионированию: " + e.Error()
		}
		if !ok {
			return fmt.Sprintf("загрузчик %q не входит в диапазон %q", env.LoaderVersion, v.LoaderVersionRange)
		}
	}
	for _, permission := range v.Permissions {
		if !env.VerifiedPermissions[permission] {
			return "Отсутствует подтверждённое разрешение: " + permission
		}
	}
	return ""
}

// ResolveCatalogConditional0244 обрабатывает автоматические умолчания отдельно от
// обязательных, явно выбранных и зависимых компонентов. Недоступный компонент по умолчанию
// исключается, а недоступный обязательный выбор вызывает явную ошибку.
func ResolveCatalogConditional0244(cat ComponentCatalog0241, preset string, env ComponentEnvironment0244) ([]string, error) {
	if cat.SchemaVersion != ComponentCatalogSchema0244 && cat.SchemaVersion != ComponentCatalogSchema0245 {
		return nil, fmt.Errorf("Для разрешения условий требуется каталог версии 4")
	}
	if err := ValidateCatalogConditions0244(cat); err != nil {
		return nil, err
	}
	modified := cat
	modified.Components = append([]CatalogComponent0241(nil), cat.Components...)
	explicit := preset != "" || cat.DefaultPreset != ""
	for i, c := range modified.Components {
		reason := unavailable0244(c.Conditions, env)
		if reason != "" {
			if c.Required {
				return nil, resolutionError0243("condition_unsatisfied", c.ID, "", "Обязательный компонент "+c.ID+": "+reason)
			}
			if !explicit {
				modified.Components[i].Default = false
			}
		}
	}
	selected, err := resolveCatalogGraph0243(modified, preset)
	if err != nil {
		return nil, err
	}
	index := make(map[string]CatalogComponent0241, len(cat.Components))
	for _, c := range cat.Components {
		index[c.ID] = c
	}
	for _, id := range selected {
		if why := unavailable0244(index[id].Conditions, env); why != "" {
			return nil, resolutionError0243("condition_unsatisfied", id, "", "Выбранный или зависимый компонент "+id+": "+why)
		}
	}
	return selected, nil
}
