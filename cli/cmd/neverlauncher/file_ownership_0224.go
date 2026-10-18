package main

import (
	"fmt"
	"path"
	"strings"
)

type FileRule0224 struct {
	Pattern   string `json:"pattern"`
	Action    string `json:"action"`
	Ownership string `json:"ownership"`
}

func manifestOwnership0224(f ManifestFile) string {
	if f.Ownership != "" {
		return f.Ownership
	}
	if f.Required {
		return "required"
	}
	return "optional"
}

func protectedUpdatePath0224(s string) bool {
	s = strings.ToLower(s)
	if s == "options.txt" || s == "optionsof.txt" || s == "servers.dat" || s == "usercache.json" {
		return true
	}
	for _, prefix := range []string{"saves", "screenshots", "resourcepacks", "shaderpacks", "config", "logs", "crash-reports", "diagnostics", ".neverlauncher", ".neverlauncher-quarantine"} {
		if s == prefix || strings.HasPrefix(s, prefix+"/") {
			return true
		}
	}
	return false
}

func managedUpdateFile0224(f ManifestFile) bool {
	if protectedUpdatePath0224(f.Path) {
		return false
	}
	switch manifestOwnership0224(f) {
	case "required", "managed", "optional":
		return true
	}
	return false
}

func filePolicyMatch0224(pattern, p string) bool {
	if strings.HasSuffix(pattern, "/**") {
		base := strings.TrimSuffix(pattern, "/**")
		return p == base || strings.HasPrefix(p, base+"/")
	}
	return p == pattern
}
func validFilePolicyPattern0224(pattern string) bool {
	if pattern == "" || strings.ContainsAny(pattern, "\\\x00\r\n?:[]") || strings.HasPrefix(pattern, "/") || path.Clean(pattern) != pattern || strings.Contains(pattern, "/../") {
		return false
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "." || segment == ".." || segment == "" {
			return false
		}
	}
	if strings.Contains(pattern, "*") && (!strings.HasSuffix(pattern, "/**") || strings.Count(pattern, "*") != 2) {
		return false
	}
	return true
}
func validateManifestFilePolicy0224(m Manifest) error {
	seen := make(map[string]bool)
	for _, f := range m.Files {
		if err := validateUpdaterPath0156(f.Path); err != nil {
			return err
		}
		if strings.ContainsAny(f.Path, "*?[]") {
			return fmt.Errorf("wildcards in file path %q", f.Path)
		}
		key := strings.ToLower(f.Path)
		if seen[key] {
			return fmt.Errorf("duplicate file %q", f.Path)
		}
		seen[key] = true
		switch manifestOwnership0224(f) {
		case "required", "managed", "optional", "user-owned", "generated":
		default:
			return fmt.Errorf("unknown ownership %q", f.Ownership)
		}
		if (f.Ownership == "user-owned" || f.Ownership == "generated") && f.Required {
			return fmt.Errorf("protected file cannot be required %q", f.Path)
		}
		if f.Ownership == "required" && !f.Required || f.Ownership == "optional" && f.Required {
			return fmt.Errorf("required/ownership conflict at %q", f.Path)
		}
		if protectedUpdatePath0224(f.Path) && manifestOwnership0224(f) != "user-owned" && manifestOwnership0224(f) != "generated" {
			return fmt.Errorf("protected file cannot be updated %q", f.Path)
		}
	}
	for i, r := range m.FileRules {
		if !validFilePolicyPattern0224(r.Pattern) {
			return fmt.Errorf("unsafe rule pattern %q", r.Pattern)
		}
		if r.Action != "include" && r.Action != "exclude" && r.Action != "verify" {
			return fmt.Errorf("unknown rule action %q", r.Action)
		}
		if r.Ownership != "managed" && r.Ownership != "required" && r.Ownership != "optional" && r.Ownership != "user-owned" && r.Ownership != "generated" {
			return fmt.Errorf("unknown rule ownership %q", r.Ownership)
		}
		if r.Action == "include" && (r.Ownership != "managed" && r.Ownership != "required" || protectedUpdatePath0224(strings.TrimSuffix(r.Pattern, "/**"))) {
			return fmt.Errorf("invalid include rule %q", r.Pattern)
		}
		if r.Action == "verify" && (r.Ownership == "user-owned" || r.Ownership == "generated") {
			return fmt.Errorf("cannot verify user-owned/generated data %q", r.Pattern)
		}
		if r.Action == "exclude" && r.Ownership != "user-owned" && r.Ownership != "generated" {
			return fmt.Errorf("invalid exclude rule %q", r.Pattern)
		}
		for j := 0; j < i; j++ {
			prev := m.FileRules[j].Pattern
			if filePolicyMatch0224(prev, strings.TrimSuffix(r.Pattern, "/**")) || filePolicyMatch0224(r.Pattern, strings.TrimSuffix(prev, "/**")) {
				return fmt.Errorf("overlapping file rules %q and %q", prev, r.Pattern)
			}
		}
		for _, f := range m.Files {
			if filePolicyMatch0224(r.Pattern, f.Path) && ((r.Action == "exclude" && managedUpdateFile0224(f)) || (r.Action == "include" && !managedUpdateFile0224(f))) {
				return fmt.Errorf("file ownership rule conflicts with %q", f.Path)
			}
		}
	}
	return nil
}

func removableUpdateFile0224(f ManifestFile) bool {
	if !managedUpdateFile0224(f) {
		return false
	}
	return manifestOwnership0224(f) == "managed" || manifestOwnership0224(f) == "required"
}
