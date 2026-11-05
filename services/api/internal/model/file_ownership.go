package model

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// FileRule — подписанная политика v2. Include разрешает помещать в карантин
// управляемые файлы из ограниченного каталога, если их нет в текущем манифесте.
// Exclude обозначает пользовательский путь; verify проверяет перечисленные файлы, не
// разрешая очистку. После валидации политика остаётся декларативной и исполняется
// нативным Runtime и CLI-обновлятором.
type FileRule struct {
	Pattern   string `json:"pattern"`
	Action    string `json:"action"`
	Ownership string `json:"ownership"`
}

func validOwnership0224(s string) bool {
	switch s {
	case "managed", "required", "optional", "user-owned", "generated":
		return true
	}
	return false
}

func FileOwnership0224(file ManifestFile) string {
	if file.Ownership != "" {
		return file.Ownership
	}
	if file.Required {
		return "required"
	}
	return "optional"
}

func protectedFilePath0224(s string) bool {
	s = strings.ToLower(s)
	if s == "options.txt" || s == "optionsof.txt" || s == "servers.dat" || s == "usercache.json" {
		return true
	}
	for _, prefix := range []string{"saves/", "screenshots/", "resourcepacks/", "shaderpacks/", "config/", "logs/", "crash-reports/", "diagnostics/", ".launcher/", ".launcher-quarantine/"} {
		if strings.HasPrefix(s, prefix) || strings.TrimSuffix(prefix, "/") == s {
			return true
		}
	}
	return false
}

func validFilePolicyPath0224(s string, pattern bool) bool {
	if s == "" || strings.ContainsAny(s, "\\\x00\r\n") || strings.HasPrefix(s, "/") || path.Clean(s) != s || s == "." || s == ".." || strings.HasPrefix(s, "../") || strings.Contains(s, ":") {
		return false
	}
	for _, segment := range strings.Split(s, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	if pattern {
		if strings.Count(s, "*") > 0 && (!strings.HasSuffix(s, "/**") || strings.Count(s, "*") != 2) {
			return false
		}
	} else if strings.ContainsAny(s, "*?[]") {
		return false
	}
	return true
}

func patternMatch0224(pattern, p string) bool {
	if strings.HasSuffix(pattern, "/**") {
		base := strings.TrimSuffix(pattern, "/**")
		return p == base || strings.HasPrefix(p, base+"/")
	}
	return pattern == p
}
func patternsOverlap0224(a, b string) bool {
	return patternMatch0224(a, strings.TrimSuffix(b, "/**")) || patternMatch0224(b, strings.TrimSuffix(a, "/**"))
}

// ValidateFileOwnership0224 вызывается до подписи и публикации v2. Устаревшие
// подписанные манифесты v1 сохраняют свой wire-формат и интерпретацию.
func ValidateFileOwnership0224(m Manifest) error {
	if m.SchemaVersion != ManifestSchemaV2 && m.SchemaVersion != ManifestSchemaV3 {
		return nil
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if !validFilePolicyPath0224(f.Path, false) {
			return fmt.Errorf("Небезопасный путь файла %q", f.Path)
		}
		key := strings.ToLower(f.Path)
		if seen[key] {
			return fmt.Errorf("Повторяющийся путь файла %q", f.Path)
		}
		seen[key] = true
		ownership := FileOwnership0224(f)
		if !validOwnership0224(ownership) {
			return fmt.Errorf("Неподдерживаемый тип владения %q", ownership)
		}
		if (ownership == "user-owned" || ownership == "generated") && f.Required {
			return fmt.Errorf("Пользовательский или генерируемый файл не может быть обязательным: %q", f.Path)
		}
		if f.Ownership != "" && ((ownership == "required" && !f.Required) || (ownership == "optional" && f.Required)) {
			return fmt.Errorf("Противоречивые свойства required/ownership для %q", f.Path)
		}
		if protectedFilePath0224(f.Path) && ownership != "user-owned" && ownership != "generated" {
			return fmt.Errorf("Защищённые пользовательские данные не могут управляться системой: %q", f.Path)
		}
	}
	for i, rule := range m.FileRules {
		if !validFilePolicyPath0224(rule.Pattern, true) || !validOwnership0224(rule.Ownership) {
			return fmt.Errorf("Недопустимое правило файлов %d", i)
		}
		if rule.Action != "include" && rule.Action != "exclude" && rule.Action != "verify" {
			return fmt.Errorf("Неподдерживаемое действие правила файлов %q", rule.Action)
		}
		if rule.Action == "include" && rule.Ownership != "managed" && rule.Ownership != "required" {
			return fmt.Errorf("Правило include должно управлять файлами")
		}
		if rule.Action == "exclude" && rule.Ownership != "user-owned" && rule.Ownership != "generated" {
			return fmt.Errorf("Правило exclude должно защищать пользовательские и генерируемые файлы")
		}
		if rule.Action == "verify" && (rule.Ownership == "user-owned" || rule.Ownership == "generated") {
			return fmt.Errorf("Правило verify не может требовать проверки пользовательских и генерируемых файлов")
		}
		base := strings.TrimSuffix(rule.Pattern, "/**")
		if protectedFilePath0224(base) && rule.Action == "include" {
			return fmt.Errorf("Правило include нацелено на защищённые данные: %q", rule.Pattern)
		}
		for j := 0; j < i; j++ {
			if patternsOverlap0224(m.FileRules[j].Pattern, rule.Pattern) {
				return fmt.Errorf("Пересекающиеся правила файлов %q и %q", m.FileRules[j].Pattern, rule.Pattern)
			}
		}
		for _, f := range m.Files {
			if patternMatch0224(rule.Pattern, f.Path) {
				if rule.Action == "exclude" && FileOwnership0224(f) != "user-owned" && FileOwnership0224(f) != "generated" {
					return fmt.Errorf("Исключённый файл помечен как управляемый: %q", f.Path)
				}
				if rule.Action == "include" && (FileOwnership0224(f) == "user-owned" || FileOwnership0224(f) == "generated") {
					return fmt.Errorf("Правило include нацелено на пользовательский файл: %q", f.Path)
				}
			}
		}
	}
	return nil
}

// ValidatePublishFileOwnership0224 отклоняет неразрешённые управляемые данные на
// окончательной границе публикации. Черновики могут содержать пути до завершения
// загрузки.
func ValidatePublishFileOwnership0224(m Manifest) error {
	if err := ValidateFileOwnership0224(m); err != nil {
		return err
	}
	if m.SchemaVersion != ManifestSchemaV2 && m.SchemaVersion != ManifestSchemaV3 {
		return nil
	}
	for _, f := range m.Files {
		if owner := FileOwnership0224(f); owner == "required" || owner == "managed" || owner == "optional" {
			if f.URL == "" || len(f.SHA256) != 64 || f.Size < 0 {
				return fmt.Errorf("Для публикации управляемого файла требуются URL, размер и SHA-256: %q", f.Path)
			}
			digest, err := hex.DecodeString(f.SHA256)
			if err != nil || len(digest) != 32 {
				return fmt.Errorf("Недопустимый SHA-256 управляемого файла: %q", f.Path)
			}
			parsed, err := url.Parse(f.URL)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("Недопустимый URL загрузки: %q", f.Path)
			}
		}
	}
	return nil
}
