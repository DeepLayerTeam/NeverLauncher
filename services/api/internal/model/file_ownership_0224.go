package model

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// FileRule is a signed v2 policy. Include permits managed files in a constrained
// directory to be quarantined if they are not in the current manifest. Exclude
// makes a path user-owned, and verify checks listed files without authorizing
// cleanup. The policy is declarative only after validation and is enforced by
// the native runtime and the CLI updater.
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
	for _, prefix := range []string{"saves/", "screenshots/", "resourcepacks/", "shaderpacks/", "config/", "logs/", "crash-reports/", "diagnostics/", ".neverlauncher/", ".neverlauncher-quarantine/"} {
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

// ValidateFileOwnership0224 is invoked before signing and publishing v2.
// Legacy v1 signed manifests retain their wire format and interpretation.
func ValidateFileOwnership0224(m Manifest) error {
	if m.SchemaVersion != ManifestSchemaV2 && m.SchemaVersion != ManifestSchemaV3 {
		return nil
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if !validFilePolicyPath0224(f.Path, false) {
			return fmt.Errorf("unsafe file path %q", f.Path)
		}
		key := strings.ToLower(f.Path)
		if seen[key] {
			return fmt.Errorf("duplicate file path %q", f.Path)
		}
		seen[key] = true
		ownership := FileOwnership0224(f)
		if !validOwnership0224(ownership) {
			return fmt.Errorf("unsupported ownership %q", ownership)
		}
		if (ownership == "user-owned" || ownership == "generated") && f.Required {
			return fmt.Errorf("user-owned/generated file cannot be required: %q", f.Path)
		}
		if f.Ownership != "" && ((ownership == "required" && !f.Required) || (ownership == "optional" && f.Required)) {
			return fmt.Errorf("conflicting required/ownership at %q", f.Path)
		}
		if protectedFilePath0224(f.Path) && ownership != "user-owned" && ownership != "generated" {
			return fmt.Errorf("protected user data cannot be managed: %q", f.Path)
		}
	}
	for i, rule := range m.FileRules {
		if !validFilePolicyPath0224(rule.Pattern, true) || !validOwnership0224(rule.Ownership) {
			return fmt.Errorf("invalid file rule %d", i)
		}
		if rule.Action != "include" && rule.Action != "exclude" && rule.Action != "verify" {
			return fmt.Errorf("unsupported file rule action %q", rule.Action)
		}
		if rule.Action == "include" && rule.Ownership != "managed" && rule.Ownership != "required" {
			return fmt.Errorf("include rule must manage files")
		}
		if rule.Action == "exclude" && rule.Ownership != "user-owned" && rule.Ownership != "generated" {
			return fmt.Errorf("exclude rule must protect user-owned/generated files")
		}
		if rule.Action == "verify" && (rule.Ownership == "user-owned" || rule.Ownership == "generated") {
			return fmt.Errorf("verify rule cannot require checks of user-owned/generated files")
		}
		base := strings.TrimSuffix(rule.Pattern, "/**")
		if protectedFilePath0224(base) && rule.Action == "include" {
			return fmt.Errorf("include rule targets protected data: %q", rule.Pattern)
		}
		for j := 0; j < i; j++ {
			if patternsOverlap0224(m.FileRules[j].Pattern, rule.Pattern) {
				return fmt.Errorf("overlapping file rules %q and %q", m.FileRules[j].Pattern, rule.Pattern)
			}
		}
		for _, f := range m.Files {
			if patternMatch0224(rule.Pattern, f.Path) {
				if rule.Action == "exclude" && FileOwnership0224(f) != "user-owned" && FileOwnership0224(f) != "generated" {
					return fmt.Errorf("excluded file is managed: %q", f.Path)
				}
				if rule.Action == "include" && (FileOwnership0224(f) == "user-owned" || FileOwnership0224(f) == "generated") {
					return fmt.Errorf("include targets user-owned file: %q", f.Path)
				}
			}
		}
	}
	return nil
}

// ValidatePublishFileOwnership0224 rejects unresolved managed payloads at the
// final publication boundary. Drafts may have paths before uploads complete.
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
				return fmt.Errorf("managed file requires URL, size, SHA-256 for publish: %q", f.Path)
			}
			digest, err := hex.DecodeString(f.SHA256)
			if err != nil || len(digest) != 32 {
				return fmt.Errorf("invalid managed file SHA-256: %q", f.Path)
			}
			parsed, err := url.Parse(f.URL)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("invalid download URL: %q", f.Path)
			}
		}
	}
	return nil
}
