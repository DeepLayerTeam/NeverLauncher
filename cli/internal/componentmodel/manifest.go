package componentmodel

// Этот пакет содержит ту же реализацию каталога, дайджеста и разрешения, что
// внутренняя модель API. Она размещена в отдельном Go-модуле CLI для офлайновой работы
// nl. Держите четыре версионированных исходных файла синхронно с API. Типы манифеста
// ниже сохраняют подписанные метаданные файлов для проверки владения компонентами;
// подпись выпуска проверяется CLI.
import (
	"fmt"
	"path"
	"strings"
)

type Manifest struct {
	SchemaVersion    string                `json:"schemaVersion"`
	Files            []ManifestFile        `json:"files"`
	ComponentCatalog *ComponentCatalog0241 `json:"componentCatalog,omitempty"`
}
type ManifestFile struct {
	Path string `json:"path"
 "fmt"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256"`
	URL        string   `json:"url"`
	Mirrors    []string `json:"mirrors,omitempty"`
	Required   bool     `json:"required"`
	Executable bool     `json:"executable"`
	TargetOS   []string `json:"targetOs,omitempty"`
	Ownership  string   `json:"ownership,omitempty"`
}

func FileOwnership0224(f ManifestFile) string {
	if f.Ownership != "" {
		return f.Ownership
	}
	if f.Required {
		return "required"
	}
	return "optional"
}
func validFilePolicyPath0224(s string, pattern bool) bool {
	if s == "" || strings.ContainsAny(s, "\\\x00\r\n") || strings.HasPrefix(s, "/") || path.Clean(s) != s || s == "." || s == ".." || strings.HasPrefix(s, "../") || strings.Contains(s, ":") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	if pattern {
		return strings.Count(s, "*") == 0 || (strings.HasSuffix(s, "/**") && strings.Count(s, "*") == 2)
	}
	return !strings.ContainsAny(s, "*?[]")
}

// ValidateSignedFiles0249 дополняет проверку владения каталогом для остальных файлов, не
// относящихся к компонентам, но включённых разрешителем в план.
func ValidateSignedFiles0249(files []ManifestFile) error {
	seen := map[string]bool{}
	for _, f := range files {
		if !validFilePolicyPath0224(f.Path, false) {
			return fmt.Errorf("Небезопасный путь подписанного файла %q", f.Path)
		}
		lower := strings.ToLower(f.Path)
		if seen[lower] {
			return fmt.Errorf("Повторяющийся путь подписанного файла %q", f.Path)
		}
		seen[lower] = true
		own := FileOwnership0224(f)
		switch own {
		case "managed", "required", "optional", "user-owned", "generated":
		default:
			return fmt.Errorf("Неподдерживаемый тип владения файлом %q", own)
		}
		if (own == "user-owned" || own == "generated") && f.Required {
			return fmt.Errorf("Требуется файл, принадлежащий пользователю: %q", f.Path)
		}
		if f.Ownership != "" && ((own == "required" && !f.Required) || (own == "optional" && f.Required)) {
			return fmt.Errorf("Противоречивые сведения о владельце файла %q", f.Path)
		}
	}
	return nil
}
