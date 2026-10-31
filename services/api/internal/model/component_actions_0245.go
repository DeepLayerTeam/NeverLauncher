package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// An action is owner-authored data in the signed release. The user's preset
// selects the action; a local preference cannot create or edit an action.
// File and ClassPath always point to files owned by this same component.
type ComponentAction0245 struct {
	Type string   `json:"type"`
	Path string   `json:"path,omitempty"`
	Args []string `json:"args,omitempty"`
}

func ComponentCatalogDigest0245(c ComponentCatalog0241) string {
	if c.SchemaVersion != ComponentCatalogSchema0245 {
		return ComponentCatalogDigest0244(c)
	}
	h := sha256.New()
	h.Write([]byte("launcher.component-catalog.v5\x00"))
	var buf [4]byte
	count := func(v int) { binary.BigEndian.PutUint32(buf[:], uint32(v)); h.Write(buf[:]) }
	str := func(v string) { count(len(v)); h.Write([]byte(v)) }
	str(ComponentCatalogDigest0244(c))
	count(len(c.Components))
	for _, component := range c.Components {
		count(len(component.Actions))
		for _, a := range component.Actions {
			str(a.Type)
			str(a.Path)
			count(len(a.Args))
			for _, arg := range a.Args {
				str(arg)
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
func NewComponentCatalog0245(c ComponentCatalog0241, revision uint64) ComponentCatalog0241 {
	c.SchemaVersion = ComponentCatalogSchema0245
	c.Revision = revision
	if c.Components == nil {
		c.Components = []CatalogComponent0241{}
	}
	for i := range c.Presets {
		if c.Presets[i].Components == nil {
			c.Presets[i].Components = []string{}
		}
	}
	c.Digest = ComponentCatalogDigest0245(c)
	return c
}
func safeOptionalArgument0245(t, arg string) bool {
	if len(arg) == 0 || len(arg) > 256 || strings.ContainsAny(arg, "\x00\r\n\t @\\\"'`$;|&<>") {
		return false
	}
	for _, b := range []byte(arg) {
		if b < 33 || b > 126 {
			return false
		}
	}
	if t == "JvmArgs" {
		if arg == "-ea" || arg == "-da" || arg == "-XX:+UseG1GC" {
			return true
		}
		if strings.HasPrefix(arg, "-XX:MaxGCPauseMillis=") {
			raw := strings.TrimPrefix(arg, "-XX:MaxGCPauseMillis=")
			if strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") {
				return false
			}
			n, e := strconv.Atoi(raw)
			return e == nil && n >= 1 && n <= 10000
		}
		if !strings.HasPrefix(arg, "-D") {
			return false
		}
		kv := strings.SplitN(strings.TrimPrefix(arg, "-D"), "=", 2)
		if len(kv) != 2 || kv[1] == "" || len(kv[1]) > 128 {
			return false
		}
		allowed := false
		for _, prefix := range []string{"launcher.optional.", "fabric.", "forge.", "neoforge.", "mixin."} {
			if strings.HasPrefix(kv[0], prefix) {
				allowed = true
			}
		}
		if !allowed || strings.ContainsAny(kv[1], "/:=") {
			return false
		}
		for _, b := range []byte(kv[0] + kv[1]) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
				return false
			}
		}
		return true
	}
	if t == "ClientArgs" {
		for _, prefix := range []string{"--never-optional-", "--fabric-", "--forge-", "--neoforge-", "--mixin-"} {
			if strings.HasPrefix(arg, prefix) {
				rest := strings.TrimPrefix(arg, prefix)
				if len(rest) == 0 {
					return false
				}
				for _, b := range []byte(rest) {
					if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '=' || b == '.') {
						return false
					}
				}
				return true
			}
		}
	}
	return false
}

func ValidateCatalogActions0245(cat ComponentCatalog0241) error {
	if cat.SchemaVersion != ComponentCatalogSchema0245 {
		for _, c := range cat.Components {
			if len(c.Actions) != 0 {
				return fmt.Errorf("component %s actions not signed by catalog schema", c.ID)
			}
		}
		return nil
	}
	if len(cat.Components) > 4096 {
		return fmt.Errorf("too many components")
	}
	for _, c := range cat.Components {
		if len(c.Actions) > 64 {
			return fmt.Errorf("component %s: too many actions", c.ID)
		}
		owned := make(map[string]bool, len(c.Files))
		for _, p := range c.Files {
			owned[p] = true
		}
		seen := make(map[string]bool)
		for _, a := range c.Actions {
			switch a.Type {
			case "File", "ClassPath":
				if len(a.Args) != 0 || !owned[a.Path] || !validFilePolicyPath0224(a.Path, false) {
					return fmt.Errorf("component %s: %s action refers to unsigned/unowned file %q", c.ID, a.Type, a.Path)
				}
				if a.Type == "ClassPath" && !strings.HasSuffix(strings.ToLower(a.Path), ".jar") {
					return fmt.Errorf("component %s: classpath action requires JAR", c.ID)
				}
				key := a.Type + ":" + strings.ToLower(a.Path)
				if seen[key] {
					return fmt.Errorf("component %s: duplicate action %s", c.ID, key)
				}
				seen[key] = true
			case "JvmArgs", "ClientArgs":
				if a.Path != "" || len(a.Args) == 0 || len(a.Args) > 32 {
					return fmt.Errorf("component %s: invalid argument action", c.ID)
				}
				for _, arg := range a.Args {
					if !safeOptionalArgument0245(a.Type, arg) {
						return fmt.Errorf("component %s: unsafe %s argument %q", c.ID, a.Type, arg)
					}
					key := a.Type + ":" + arg
					if seen[key] {
						return fmt.Errorf("component %s: duplicate argument %q", c.ID, arg)
					}
					seen[key] = true
				}
			default:
				return fmt.Errorf("component %s: unsupported action type %q", c.ID, a.Type)
			}
		}
	}
	return nil
}
